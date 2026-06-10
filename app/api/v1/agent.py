"""
Agent 端点 v2：修复任务查询逻辑，清理冗余的 join 写法
"""
import random
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import generate_device_secret, hash_secret
from app.core.deps import require_initial_token, require_agent_auth, require_glpi_token
from app.core.config import get_settings
from app.core.ws_manager import ws_manager
from app.models.models import (
    Client, DeviceRegistration, ClientReport,
    TaskTarget, ActionAudit, InteractionPolicy, Package, Task
)
from app.schemas.schemas import (
    RegisterRequest, RegisterResponse,
    ReportRequest, ReportResponse,
    TaskOut, TaskResultRequest, TaskLogRequest,
    AuditActionRequest, PolicyOut, OkResponse,
)

router = APIRouter(prefix="/api", tags=["agent"])
settings = get_settings()
logger = logging.getLogger(__name__)


# ── POST /api/clients/register ───────────────────────────────────────────────
@router.post("/clients/register", response_model=RegisterResponse)
async def register_client(
    body: RegisterRequest,
    request: Request,
    _: bool = Depends(require_initial_token),
    db: AsyncSession = Depends(get_db),
):
    """设备首次注册，下发唯一 DeviceSecret（双段式认证第一段）"""
    secret      = generate_device_secret()
    secret_hash = hash_secret(secret)
    client_ip   = request.client.host if request.client else None

    # upsert Client
    result = await db.execute(select(Client).where(Client.hash_serial == body.hash_serial))
    client = result.scalar_one_or_none()
    if client:
        client.hostname           = body.hostname
        client.ip                 = body.ip or client_ip
        client.device_secret_hash = secret_hash
        client.last_seen          = datetime.now(timezone.utc)
        if body.bios_serial:
            client.bios_serial    = body.bios_serial
        if body.machine_guid:
            client.machine_guid   = body.machine_guid
    else:
        client = Client(
            hash_serial=body.hash_serial, hostname=body.hostname,
            bios_serial=getattr(body, 'bios_serial', None),
            machine_guid=getattr(body, 'machine_guid', None),
            ip=body.ip or client_ip,
            device_secret_hash=secret_hash,
            last_seen=datetime.now(timezone.utc),
        )
        db.add(client)

    await db.flush()

    # upsert DeviceRegistration
    reg_res = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.hash_serial == body.hash_serial)
    )
    reg = reg_res.scalar_one_or_none()
    if reg:
        reg.device_secret_hash = secret_hash
        reg.last_ip = client_ip
    else:
        db.add(DeviceRegistration(
            hash_serial=body.hash_serial,
            device_secret_hash=secret_hash,
            last_ip=client_ip,
        ))

    await db.commit()
    await db.refresh(client)
    logger.info(f"Registered: {body.hash_serial} ({body.hostname})")
    return RegisterResponse(device_secret=secret, client_id=client.id)


# ── POST /api/clients/report ─────────────────────────────────────────────────
@router.post("/clients/report", response_model=ReportResponse)
async def report_assets(
    body: ReportRequest,
    request: Request,
    client: Client = Depends(require_agent_auth),
    db: AsyncSession = Depends(get_db),
):
    """资产上报：硬件、软件、补丁快照，serial 做 upsert"""
    now = datetime.now(timezone.utc)

    client.hostname  = body.hostname
    client.ip        = body.ip or (request.client.host if request.client else client.ip)
    client.os        = body.os
    client.cpu       = body.cpu
    client.memory_gb = body.memory_gb
    client.bios_serial = getattr(body, 'bios_serial', None)
    client.machine_guid = getattr(body, 'machine_guid', None)
    client.disk_info = [d.model_dump() for d in body.disk_info] if body.disk_info else client.disk_info
    client.last_seen = now

    db.add(ClientReport(
        client_id=client.id,
        current_user=body.current_user,
        software=body.software,
        patches=body.patches,
        collected_at=now,
    ))
    await db.commit()

    # 防惊群：建议 Agent 下次上报的随机延迟（秒）
    jitter = random.randint(0, settings.AGENT_JITTER_MAX)
    return ReportResponse(client_id=client.id, jitter_seconds=jitter)


# ── GET /api/tasks ────────────────────────────────────────────────────────────
# ── GET /api/tasks (v2: N+1 fix — batch JOIN queries) ──────────────────────
@router.get("/tasks", response_model=list[TaskOut])
async def get_tasks(
    client: Client = Depends(require_agent_auth),
    db: AsyncSession = Depends(get_db),
):
    """Fetch pending/deferred tasks for this client with batch queries"""
    from datetime import timedelta
    now = datetime.now(timezone.utc)

    # ── Step 1: stale running tasks → JOIN with Task to get timeout ──
    stale_rows = await db.execute(
        select(TaskTarget, Task.timeout)
        .join(Task, TaskTarget.task_id == Task.id, isouter=True)
        .where(
            TaskTarget.client_id == client.id,
            TaskTarget.status == "running",
        )
    )
    stale_count = 0
    for tt, timeout_val in stale_rows:
        timeout_sec = (timeout_val if timeout_val else 600) * 2
        timeout_sec = max(timeout_sec, 1200)
        if tt.started_at and (now - tt.started_at).total_seconds() > timeout_sec:
            tt.status = "pending"
            stale_count += 1
    if stale_count:
        await db.commit()
        logger.warning(f"Stale tasks reset: {stale_count}")

    # ── Step 2: fetch pending/deferred TaskTargets ──
    tt_result = await db.execute(
        select(TaskTarget).where(
            TaskTarget.client_id == client.id,
            TaskTarget.status.in_(["pending", "deferred"]),
        )
    )
    targets = tt_result.scalars().all()
    if not targets:
        return []

    # Mark running immediately
    for tt in targets:
        tt.status = "running"
        tt.started_at = now
    await db.commit()

    # ── Step 3: batch-fetch all needed Tasks in ONE query ──
    task_ids = [tt.task_id for tt in targets]
    task_map: dict = {}
    if task_ids:
        task_rows = await db.execute(
            select(Task).where(
                Task.id.in_(task_ids),
                Task.status == "active",
            )
        )
        for t in task_rows.scalars().all():
            task_map[t.id] = t

    # ── Step 4: batch-fetch all needed Packages in ONE query ──
    pkg_ids = [
        t.package_id for t in task_map.values()
        if t.package_id is not None]
    pkg_map: dict = {}
    if pkg_ids:
        pkg_rows = await db.execute(
            select(Package).where(Package.id.in_(pkg_ids)))
        for p in pkg_rows.scalars().all():
            pkg_map[p.id] = p

    # ── Step 5: batch-fetch policies in ONE query (global + per-pkg) ──
    pol_map: dict = {}   # package_id → policy (None key = global)
    pol_rows = await db.execute(
        select(InteractionPolicy).where(
            (InteractionPolicy.package_id.in_(pkg_ids))
            | (InteractionPolicy.package_id.is_(None))
        )
    )
    for pol in pol_rows.scalars().all():
        key = pol.package_id  # None for global
        pol_map[key] = pol

    # ── Step 6: build output from in-memory maps (zero DB queries) ──
    tasks_out = []
    for tt in targets:
        task = task_map.get(tt.task_id)
        if not task:
            continue

        if task.task_type == "uninstall":
            tasks_out.append(TaskOut(
                target_id=tt.id,
                task_id=task.id,
                task_name=task.name,
                task_type="uninstall",
                package_hash=None,
                package_size=None,
                uninstall_target=task.uninstall_target,
                interactive=task.interactive,
                need_reboot=task.need_reboot,
                timeout=task.timeout,
                success_codes=task.success_codes or [0],
                defer_count=tt.defer_count,
                max_defer_count=3,
                silent_override=False,
            ))
            continue

        pkg = pkg_map.get(task.package_id)
        if not pkg:
            continue

        # Policy: per-package first, then global
        pol = pol_map.get(task.package_id) or pol_map.get(None)

        tasks_out.append(TaskOut(
            target_id=tt.id,
            task_id=task.id,
            task_name=task.name,
            task_type="install",
            package_filename=pkg.filename,
            package_hash=pkg.file_hash,
            package_size=pkg.file_size,
            silent_args=pkg.silent_args,
            interactive=task.interactive,
            need_reboot=task.need_reboot,
            timeout=task.timeout,
            success_codes=task.success_codes or [0],
            defer_count=tt.defer_count,
            max_defer_count=pol.max_defer_count if pol else 3,
            silent_override=pol.silent_override if pol else False,
            download_url=(
                f"{settings.SERVER_URL}/api/packages/download/{pkg.filename}"),
        ))
    return tasks_out
@router.post("/tasks/{target_id}/result", response_model=OkResponse)
async def report_task_result(
    target_id: int,
    body: TaskResultRequest,
    client: Client = Depends(require_agent_auth),
    db: AsyncSession = Depends(get_db),
):
    """Agent 回报任务执行结果（REST 正式通道）"""
    result = await db.execute(
        select(TaskTarget).where(
            TaskTarget.id == target_id,
            TaskTarget.client_id == client.id,
        )
    )
    tt = result.scalar_one_or_none()
    if not tt:
        raise HTTPException(status_code=404, detail="任务记录不存在")

    if body.deferred:
        tt.status      = "deferred"
        tt.defer_count += 1
    elif body.success:
        tt.status = "success"
    else:
        tt.status      = "failed"
        tt.retry_count += 1

    tt.message       = body.message
    tt.executed_at   = datetime.now(timezone.utc)
    tt.reboot_action = body.reboot_action
    await db.commit()

    # ── 更新父任务状态 ──────────────────────────────────────────────────────
    # 如果所有 TaskTarget 都已完成/失败/取消，则更新 task.status
    from sqlalchemy import func as sqlfunc
    from app.models.models import Task
    stats_res = await db.execute(
        select(TaskTarget.status, sqlfunc.count(TaskTarget.id).label("cnt"))
        .where(TaskTarget.task_id == tt.task_id)
        .group_by(TaskTarget.status)
    )
    stats = {row.status: row.cnt for row in stats_res}
    total = sum(stats.values())
    pending_or_running = stats.get("pending", 0) + stats.get("running", 0) + stats.get("deferred", 0)
    if pending_or_running == 0:
        # 全部结束，判断整体状态
        failed = stats.get("failed", 0)
        success = stats.get("success", 0)
        cancelled = stats.get("cancelled", 0)
        task_res = await db.execute(select(Task).where(Task.id == tt.task_id))
        task = task_res.scalar_one_or_none()
        if task:
            if failed > 0 and success == 0:
                task.status = "failed"      # 全部失败 → 标记 failed
            elif failed > 0:
                task.status = "partial"     # 部分失败 → 新增状态
            else:
                task.status = "completed"   # 全部成功
            await db.commit()

    return OkResponse(message="结果已记录")


# ── POST /api/tasks/{target_id}/log ──────────────────────────────────────────
@router.post("/tasks/{target_id}/log", response_model=OkResponse)
async def upload_task_log(
    target_id: int,
    body: TaskLogRequest,
    client: Client = Depends(require_agent_auth),
    db: AsyncSession = Depends(get_db),
):
    """上传安装日志（最大 512KB）"""
    result = await db.execute(
        select(TaskTarget).where(
            TaskTarget.id == target_id,
            TaskTarget.client_id == client.id,
        )
    )
    tt = result.scalar_one_or_none()
    if not tt:
        raise HTTPException(status_code=404, detail="任务记录不存在")
    tt.install_log = body.log[:524288]
    await db.commit()
    return OkResponse()


# ── GET /api/policy ───────────────────────────────────────────────────────────
@router.get("/policy", response_model=PolicyOut)
async def get_policy(
    _: Client = Depends(require_agent_auth),
    db: AsyncSession = Depends(get_db),
):
    """下发交互策略（全局 + 各包覆盖）"""
    global_res = await db.execute(
        select(InteractionPolicy).where(InteractionPolicy.package_id.is_(None))
    )
    g = global_res.scalar_one_or_none()

    overrides_res = await db.execute(
        select(InteractionPolicy).where(InteractionPolicy.package_id.isnot(None))
    )
    overrides = {
        p.package_id: {
            "max_defer": p.max_defer_count,
            "silent_override": p.silent_override,
        }
        for p in overrides_res.scalars().all()
    }
    return PolicyOut(
        global_max_defer=g.max_defer_count if g else 3,
        global_silent_after=g.silent_after_max if g else True,
        package_overrides=overrides,
    )


# ── POST /api/audit/action ────────────────────────────────────────────────────
@router.post("/audit/action", response_model=OkResponse)
async def report_audit_action(
    body: AuditActionRequest,
    client: Client = Depends(require_agent_auth),
    db: AsyncSession = Depends(get_db),
):
    """上报 SYSTEM 权限执行的进程审计日志"""
    db.add(ActionAudit(
        hash_serial=body.hash_serial,
        client_id=client.id,
        process_path=body.process_path,
        arguments=body.arguments,
        pid=body.pid,
        exit_code=body.exit_code,
        executed_at=body.executed_at,
    ))
    await db.commit()
    return OkResponse()

# ── DELETE /api/clients/{client_id} ───────────────────────────────────────────
@router.delete("/clients/{client_id}", response_model=OkResponse)
async def delete_client(
    client_id: int,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """删除客户端及相关联数据（GLPI 插件调用）"""
    from sqlalchemy import delete as sqldelete
    from sqlalchemy import func as sqlfunc
    from app.models.models import TaskTarget, ActionAudit, ClientReport, Task, DeviceRegistration

    # 1. 查找客户端
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="客户端不存在")

    serial = client.hash_serial

    # 2. 收集属于该客户端的 task_ids（用于后续孤儿清理）
    tt_rows = await db.execute(
        select(TaskTarget.task_id).where(TaskTarget.client_id == client_id)
    )
    task_ids = list(set(row[0] for row in tt_rows))

    # 3. 删除 TaskTarget
    await db.execute(sqldelete(TaskTarget).where(TaskTarget.client_id == client_id))

    # 4. 删除孤儿 Task（没有剩余 TaskTarget 的）
    # Batch delete orphan tasks (NOT IN subquery)

    if task_ids:

        from sqlalchemy import func as sqlfunc2

        non_orphan = await db.execute(

            select(TaskTarget.task_id).where(TaskTarget.task_id.in_(task_ids)).distinct()

        )

        non_orphan_ids = {row[0] for row in non_orphan}

        orphan_ids = [tid for tid in task_ids if tid not in non_orphan_ids]

        if orphan_ids:

            await db.execute(sqldelete(Task).where(Task.id.in_(orphan_ids)))

    logger.info(f"Deleted client #{client_id} ({_hostname}, {_serial})")
    return OkResponse(message=f"已删除 {_hostname} 及关联数据")
