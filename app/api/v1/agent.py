"""
Agent 端点 v2：修复任务查询逻辑，清理冗余的 join 写法
"""
import json
import os
import random
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from app.core.database import get_db
from app.core.security import generate_device_secret, hash_secret
from app.core.deps import require_initial_token, require_agent_auth, require_glpi_token
from app.core.config import get_settings
from app.core.ws_manager import ws_manager
from app.models.models import (
    Client, DeviceRegistration, ClientReport,
    TaskTarget, ActionAudit, InteractionPolicy, Package, Task, Group
)
from app.schemas.schemas import (
    RegisterRequest, RegisterResponse,
    ReportRequest, ReportResponse,
    TaskOut, TaskResultRequest, TaskLogRequest,
    AuditActionRequest, PolicyOut, OkResponse,
    TaskCreate, RegistryOp, CleanupPath, ClientUpdateOut,
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
    """
    设备首次注册，下发唯一 DeviceSecret（双段式认证第一段）
    
    🔒 安全修复 v6.1：
    - 已注册设备重新注册需要验证原 DeviceSecret（防 Token 劫持）
    - 使用 SELECT FOR UPDATE SKIP LOCKED 防止竞态条件
    """
    secret      = generate_device_secret()
    secret_hash = hash_secret(secret)
    client_ip   = request.client.host if request.client else None

    # 🔒 修复竞态条件：使用 FOR UPDATE 锁
    # 先尝试查找现有记录（加锁）
    result = await db.execute(
        select(Client).where(Client.hash_serial == body.hash_serial).with_for_update()
    )
    client = result.scalar_one_or_none()
    
    if client:
        # 🔒 修复安全问题：已注册设备重新注册需要验证原 DeviceSecret
        # 检查请求中是否提供了原 DeviceSecret（无损恢复场景）
        old_secret = body.old_device_secret
        if old_secret:
            # 验证原 DeviceSecret
            from app.core.security import verify_device_secret
            if not verify_device_secret(old_secret, client.device_secret_hash):
                logger.warning(f"Register: invalid old_device_secret for {body.hash_serial}")
                raise HTTPException(
                    status_code=403,
                    detail="设备已注册，提供的原 DeviceSecret 无效。请联系管理员。"
                )
            logger.info(f"Register: re-register with valid old secret: {body.hash_serial}")
        else:
            # 无原 DeviceSecret：拒绝重新注册（需要管理员审批）
            logger.warning(f"Register: rejected re-register without old_secret: {body.hash_serial}")
            raise HTTPException(
                status_code=403,
                detail="设备已注册，请提供原 DeviceSecret 或联系管理员审批重新注册"
            )
        
        # 验证通过：更新 DeviceSecret
        client.hostname           = body.hostname
        client.ip                 = body.ip or client_ip
        client.device_secret_hash = secret_hash
        client.last_seen          = datetime.now(timezone.utc)
        if body.bios_serial:
            client.bios_serial    = body.bios_serial
        if body.machine_guid:
            client.machine_guid   = body.machine_guid
    else:
        # 新设备：创建
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
        select(DeviceRegistration).where(DeviceRegistration.hash_serial == body.hash_serial).with_for_update(skip_locked=True)
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


def _to_jsonable(v):
    """Pydantic 模型 → dict；其它原样返回"""
    if hasattr(v, "model_dump"):
        return v.model_dump()
    return v


def _sanitize_text(obj):
    """递归移除字符串中的控制字符（含 x00），防止 asyncpg 报 UntranslatableCharacterError。"""
    if isinstance(obj, str):
        # 保留可打印字符与基本空白（tab/换行/回车），其余控制字符一律剔除
        return "".join(ch for ch in obj if ord(ch) >= 32 or ch in "\t\n\r")
    if isinstance(obj, dict):
        return {k: _sanitize_text(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_text(v) for v in obj]
    return obj


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
    # 🔒 修复问题3：只在字段存在时才更新（防止清空已有值）
    if body.bios_serial is not None:
        client.bios_serial = body.bios_serial
    if body.machine_guid is not None:
        client.machine_guid = body.machine_guid
    client.disk_info = [d.model_dump() for d in body.disk_info] if body.disk_info else client.disk_info
    client.last_seen = now

    sw = [_to_jsonable(s) for s in body.software] if body.software else None
    pt = [_to_jsonable(p) for p in body.patches] if body.patches else None
    db.add(ClientReport(
        client_id=client.id,
        current_user=_sanitize_text(body.current_user),
        software=_sanitize_text(sw),
        patches=_sanitize_text(pt),
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

    # 🔒 修复问题8：先不标记 running，等过滤完再标记（防止卡在 running）
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

    # ── Step 2: fetch pending/deferred TaskTargets (不先标记 running) ──
    tt_result = await db.execute(
        select(TaskTarget).where(
            TaskTarget.client_id == client.id,
            TaskTarget.status.in_(["pending", "deferred"]),
        )
    )
    targets = tt_result.scalars().all()
    if not targets:
        return []

    # 🔒 修复问题8：先过滤，只对最终下发的 target 标记 running
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

    # 🔒 修复问题8：过滤掉 Task 不存在或非 active 的 target
    valid_targets = []
    for tt in targets:
        task = task_map.get(tt.task_id)
        if task:
            valid_targets.append((tt, task))

    if not valid_targets:
        return []

    # 🔒 修复问题8：现在才标记 running（只对有效 target）
    for tt, _ in valid_targets:
        tt.status = "running"
        tt.started_at = now
    await db.commit()

    # ── Step 4: batch-fetch all needed Packages in ONE query ──
    pkg_ids = [
        t.package_id for _, t in valid_targets
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
    for tt, task in valid_targets:
        common = dict(
            target_id=tt.id,
            task_id=task.id,
            task_name=task.name,
            task_type=task.task_type,
            interactive=task.interactive,
            need_reboot=task.need_reboot,
            timeout=task.timeout,
            success_codes=task.success_codes or [0],
            defer_count=tt.defer_count,
            run_as=task.run_as,
        )

        if task.task_type == "uninstall":
            tasks_out.append(TaskOut(**common, max_defer_count=3, silent_override=False,
                                      uninstall_target=task.uninstall_target))
            continue

        if task.task_type in ("run_command", "registry", "cleanup"):
            # 命令类任务：把 DB 中的 JSON 列表序列化为 JSON 字符串下发给客户端
            reg_ops = json.dumps(task.registry_ops) if task.registry_ops else None
            clean = json.dumps(task.cleanup_paths) if task.cleanup_paths else None
            tasks_out.append(TaskOut(
                **common,
                max_defer_count=3,
                silent_override=False,
                command=task.command,
                interpreter=task.interpreter,
                registry_ops=reg_ops,
                cleanup_paths=clean,
            ))
            continue

        # install（默认分支）
        pkg = pkg_map.get(task.package_id)
        if not pkg:
            continue

        # Policy: per-package first, then global
        pol = pol_map.get(task.package_id) or pol_map.get(None)

        tasks_out.append(TaskOut(
            **common,
            package_filename=pkg.filename,
            package_hash=pkg.file_hash,
            package_size=pkg.file_size,
            silent_args=pkg.silent_args,
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
    """Agent 回报任务执行结果（REST 正式通道）

    状态机（v2 补全）：
      TaskTarget:
        running → success/failed/deferred （终态/推迟）
        success → pending_verify（registry_fix / patch_install 需后校验）
      RemediationTask:
        dispatched → done/failed（软件卸载/升级等直通类型）
        dispatched → pending_verify（registry_fix / patch_install）
        pending_verify → done（后校验通过）
        pending_verify → rollback_required（后校验不达标 → 自动回滚或转人工）
    """
    result = await db.execute(
        select(TaskTarget).where(
            TaskTarget.id == target_id,
            TaskTarget.client_id == client.id,
        )
    )
    tt = result.scalar_one_or_none()
    if not tt:
        raise HTTPException(status_code=404, detail="任务记录不存在")

    # ── 写入 Agent 版本号（用于以后按版本筛查问题）──
    if body.executor_version:
        tt.executor_version = body.executor_version

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

    # ── 漏洞修复联动：若该 target 来自修复任务下发，回写 RemediationTask ──
    if tt.remediation_task_id:
        from app.models.vuln import RemediationTask, RemediationRule, TASK_STATUSES
        rt = (await db.execute(
            select(RemediationTask).where(RemediationTask.id == tt.remediation_task_id)
        )).scalar_one_or_none()
        if rt and not body.deferred:
            rt.result_log = (body.message or "")[:2000]

            if tt.is_verify:
                # ── 声明式验证子任务回报（独立分支，不触发修复状态机）──
                # 由 _post_verify_command 处理：通过→done；未过→计数+自动重下发/转人工
                await _post_verify_command(db, rt, tt, body)
            elif not body.success:
                # 失败 → 终态 failed（需人工介入）
                if rt.status in ("dispatched",):
                    rt.status = "failed"
                logger.info("修复任务 #%s 执行失败 → failed（target #%s）", rt.id, tt.id)
            else:
                # 成功 → 按是否有验证判定条件决定是否进入 pending_verify
                has_verify_spec = bool((rt.action_json or {}).get("verify"))
                # 声明式验证优先；无声明式判定时，registry_fix/patch_install 走 legacy 后校验
                legacy_verify = (not has_verify_spec) and rt.fix_type in ("registry_fix", "patch_install")

                if (has_verify_spec or legacy_verify) and rt.status == "dispatched":
                    # ── 进入 pending_verify（后校验）──
                    rt.status = "pending_verify"
                    tt.status = "pending_verify"
                    logger.info("修复任务 #%s → pending_verify（fix_type=%s，has_verify_spec=%s，target #%s）",
                                rt.id, rt.fix_type, has_verify_spec, tt.id)
                    if has_verify_spec and not legacy_verify:
                        # 声明式验证：on-the-fly 下发验证子任务（run_command + build_verify_command）
                        from app.api.v1.vuln import _dispatch_verify
                        ok = await _dispatch_verify(db, rt, tt)
                        if not ok:
                            # 安全校验拦截 → 转人工
                            rt.status = "needs_manual"
                            logger.warning("修复任务 #%s 验证脚本安全校验拦截 → needs_manual", rt.id)

                elif not has_verify_spec and not legacy_verify and rt.status == "dispatched":
                    # 直通类型（software_uninstall / software_upgrade / shell_exec 无判定等）→ done
                    rt.status = "done"
                    logger.info("修复任务 #%s → done（fix_type=%s，target #%s）",
                                rt.id, rt.fix_type, tt.id)

                # 通用：needs_reboot 检测（Agent 上报 reboot_now/reboot_required，
                # 兼容历史 prompt/force；补丁靠 message 中的 PATCH_REBOOT_REQUIRED=YES 兜底）
                reboot_pending = (body.reboot_action in ("reboot_now", "reboot_required", "prompt", "force")) or \
                                 (body.message and "PATCH_REBOOT_REQUIRED=YES" in body.message)
                if reboot_pending:
                    rt.needs_reboot = True

    await db.commit()

    # ── 后校验（仅对 pending_verify 的 registry_fix / patch_install 执行）──
    await _post_verify(db, tt, body)

    # ── 更新父任务状态 ──────────────────────────────────────────────────────
    from sqlalchemy import func as sqlfunc
    from app.models.models import Task
    stats_res = await db.execute(
        select(TaskTarget.status, sqlfunc.count(TaskTarget.id).label("cnt"))
        .where(TaskTarget.task_id == tt.task_id)
        .group_by(TaskTarget.status)
    )
    stats = {row.status: row.cnt for row in stats_res}
    pending_or_running = stats.get("pending", 0) + stats.get("running", 0) + stats.get("deferred", 0) + stats.get("pending_verify", 0)
    if pending_or_running == 0:
        failed = stats.get("failed", 0)
        success = stats.get("success", 0)
        cancelled = stats.get("cancelled", 0)
        task_res = await db.execute(select(Task).where(Task.id == tt.task_id))
        task = task_res.scalar_one_or_none()
        if task:
            if failed > 0 and success == 0:
                task.status = "failed"
            elif failed > 0:
                task.status = "partial"
            else:
                task.status = "completed"
            await db.commit()

    return OkResponse(message="结果已记录")


async def _post_verify(db: AsyncSession, tt: TaskTarget, body: TaskResultRequest):
    """
    后校验逻辑（report_task_result 的子流程）：
      - registry_fix：比对 verify_snapshot 与 action_json 期望值
      - patch_install：核对 exit_code 和 needs_reboot 标记
    仅在 RemediationTask.status == 'pending_verify' 时执行。
    """
    if not tt.remediation_task_id or tt.status != "pending_verify":
        return

    from app.models.vuln import RemediationTask, RemediationRule
    rt = (await db.execute(
        select(RemediationTask).where(RemediationTask.id == tt.remediation_task_id)
    )).scalar_one_or_none()
    if not rt or rt.status != "pending_verify":
        return

    # 声明式验证（action_json 含 verify，由 is_verify 子任务单独回报）不在此处处理，
    # 避免与 _post_verify_command 重复判定；此处仅服务 legacy registry_fix/patch_install。
    if (rt.action_json or {}).get("verify"):
        return
    if rt.fix_type not in ("registry_fix", "patch_install"):
        return

    verify_ok = True

    if rt.fix_type == "registry_fix":
        # ── 自动补全 rollback_plan（若 Agent 带回了写入前原值）──
        if not rt.rollback_plan and body.verify_snapshot:
            auto_rp = _build_registry_rollback_plan(body.verify_snapshot)
            if auto_rp:
                rt.rollback_plan = auto_rp
                logger.info("修复任务 #%s 自动生成 rollback_plan（注册表原值，%d 条）",
                            rt.id, len(auto_rp.get("action", {}).get("ops", [])))
        verify_ok = _verify_registry_fix(rt, body)
    elif rt.fix_type == "patch_install":
        verify_ok = _verify_patch_install(rt, body)

    if verify_ok:
        rt.status = "done"
        tt.status = "success"
        logger.info("修复任务 #%s 后校验通过 → done", rt.id)
    else:
        # ── 后校验不达标 → rollback_required ──
        rt.status = "rollback_required"
        tt.status = "rollback_required"
        logger.warning("修复任务 #%s 后校验不达标 → rollback_required", rt.id)

        # 有 rollback_plan → 自动下发回滚 Task
        if rt.rollback_plan:
            await _dispatch_rollback(db, rt, tt)
        else:
            logger.warning("修复任务 #%s 无 rollback_plan，停在 rollback_required 等待人工处理", rt.id)

    await db.commit()


async def _post_verify_command(db: AsyncSession, rt: "RemediationTask",
                               tt: TaskTarget, body: TaskResultRequest):
    """声明式验证子任务（is_verify=True）回报处理（report_task_result 的子流程）。

    验证通过 → rt → done（记 verified 日志）；
    验证未通过 → verify_attempts+1：
        - 未达上限 → 重新下发修复任务（_requeue_fix，rt 回到 dispatched，
          修复成功后再进 pending_verify 重新验证），形成「修复→验证→未过→再修复」自动循环；
        - 已达上限 → rt → needs_manual（转人工循环/接管）。
    注意：本函数不自行 commit，由 report_task_result 的外层 await db.commit() 统一提交，
    以便与父验证任务（Task）的状态聚合一起落库。
    """
    if rt.status != "pending_verify":
        # 可能已被并发/其它流程改变，避免重复处理
        return
    if not tt.is_verify:
        return

    max_a = rt.verify_max_attempts or 3

    if body.success:
        rt.status = "done"
        tt.status = "success"
        rt.result_log = ((rt.result_log or "") + f"\n验证通过（声明式，第{(rt.verify_attempts or 0) + 1}次）").strip()
        logger.info("修复任务 #%s 验证通过 → done（verify attempt #%s）",
                    rt.id, (rt.verify_attempts or 0) + 1)
    else:
        rt.verify_attempts = (rt.verify_attempts or 0) + 1
        logger.warning("修复任务 #%s 验证未通过（attempt #%s / max %s）",
                       rt.id, rt.verify_attempts, max_a)
        if rt.verify_attempts < max_a:
            tt.status = "failed"
            rt.result_log = ((rt.result_log or "") +
                             f"\n验证未通过（第{rt.verify_attempts}次），自动重下发修复").strip()
            from app.api.v1.vuln import _requeue_fix
            reason = await _requeue_fix(db, rt, tt)
            if reason:
                rt.status = "needs_manual"
                logger.warning("修复任务 #%s 重下发被门禁拦截：%s → needs_manual", rt.id, reason)
            # 成功则 _requeue_fix 已通过 _do_dispatch 将 rt 置回 dispatched
        else:
            rt.status = "needs_manual"
            tt.status = "failed"
            rt.result_log = ((rt.result_log or "") +
                             f"\n验证连续 {rt.verify_attempts} 次未通过 → 转人工").strip()
            logger.warning("修复任务 #%s 验证连续 %s 次未通过 → needs_manual（转人工循环）",
                           rt.id, rt.verify_attempts)


def _verify_registry_fix(rt: "RemediationTask", body: TaskResultRequest) -> bool:
    """对比 registry_fix 的期望值与 Agent 读回的实际值（支持多 ops + delete + 结构化精确匹配）

    期望值来自 rt.action_json（dispatch 时已用实际生效的 active 规则模板定版，
    见 vuln.py _do_dispatch），避免规则被编辑后校验拿旧值误判回滚。
    """
    vs = body.verify_snapshot
    if not vs:
        logger.info("修复任务 #%s registry_fix 无 verify_snapshot，跳过校验", rt.id)
        return True

    # 期望值来自实际下发的 action（rt.action_json 已在下发时定版）
    aj = rt.action_json or {}
    changes = aj.get("changes") or []
    if not changes:
        # 兼容旧单键格式
        changes = [{
            "hive": "",
            "path": aj.get("registry_path", ""),
            "value": aj.get("value_name", ""),
            "data": aj.get("value_data"),
            "type": aj.get("value_type", "REG_SZ"),
            "action": "set",
        }]

    def _norm(root: str, subkey: str, name: str) -> str:
        return f"{root}\\{subkey}\\{name}".upper().replace("\\", "")

    def _split_registry_path(path: str) -> tuple[str, str]:
        """'HKLM\\SOFTWARE\\X' / 'HKEY_LOCAL_MACHINE\\SOFTWARE\\X' → ('HKLM', 'SOFTWARE\\X')"""
        p = (path or "").strip().strip("\\")
        root, _, sub = p.partition("\\")
        root_map = {
            "HKLM": "HKLM", "HKEY_LOCAL_MACHINE": "HKLM",
            "HKCU": "HKCU", "HKEY_CURRENT_USER": "HKCU",
        }
        return root_map.get(root.upper(), "HKLM"), sub

    # 期望表：norm_key → (action, expected_data_str)
    # 兼容两种存储形态：
    #  - root/subkey 分离（validate_action 归一化后的 LLM 规则 / 下发快照）
    #  - hive+path（旧单键 / 手动规则）
    expected: dict = {}
    for ch in changes:
        root = ch.get("root")
        subkey = ch.get("subkey")
        if not subkey:
            hive = (ch.get("hive") or "HKLM").strip()
            cp = (ch.get("path") or "").strip().strip("\\")
            root, subkey = _split_registry_path(f"{hive}\\{cp}" if cp else hive)
            if not subkey:
                continue
        root = "HKCU" if (root or "HKLM").upper() == "HKCU" else "HKLM"
        name = ch.get("name") or ch.get("value") or ch.get("value_name") or ""
        key = _norm(root, subkey, name)
        act = (ch.get("action") or "set").lower()
        raw = ch.get("value") if ch.get("value") is not None else ch.get("data")
        expected[key] = (act, "" if raw is None else str(raw))

    # 支持多 ops 格式（Agent 新格式：{ ops: [{before, after}, ...] }）
    snaps = vs.get("ops") if isinstance(vs, dict) else None
    snapshots = snaps if isinstance(snaps, list) else ([vs] if isinstance(vs, dict) else [])

    matched_keys: set = set()
    for snap in snapshots:
        after = snap.get("after") if isinstance(snap, dict) else None
        if not after:
            continue
        akey = _norm(after.get("root", ""), after.get("subkey", ""), after.get("name", ""))
        if akey not in expected:
            logger.info("修复任务 #%s registry_fix 校验：snapshot 含未匹配 key=%s，跳过", rt.id, akey)
            continue
        matched_keys.add(akey)
        act, exp_str = expected[akey]
        after_val = after.get("value")
        after_str = "" if after_val is None else str(after_val)
        if act == "delete":
            # 删除成功：实际值应已不存在（None 或空串）
            if after_val not in (None, ""):
                logger.warning("修复任务 #%s 删除校验不达标：期望已删除，实际 %s=%s",
                               rt.id, akey, after_str)
                return False
        else:
            if exp_str != after_str:
                logger.warning("修复任务 #%s 后校验不匹配：期望 %s=%s，实际 %s",
                               rt.id, akey, exp_str, after_str)
                return False

    # 所有「需要写入(set)」的期望值都应在读回快照中出现；
    # 否则视为 Agent 报告成功但实际未按预期写入（保守判失败）。
    # 删除(delete)类不要求出现在快照中（值已消失，Agent 不读回）。
    for key, (act, _) in expected.items():
        if act != "delete" and key not in matched_keys:
            logger.warning("修复任务 #%s 后校验不达标：期望写入 %s 但读回快照缺失", rt.id, key)
            return False

    return True


def _verify_patch_install(rt: "RemediationTask", body: TaskResultRequest) -> bool:
    """核对 patch_install 的 exit_code 和 needs_reboot"""
    # exit_code 非 0 → 失败（已在 report_task_result 处理）
    # 这里仅处理 "装完待重启" 的情况：标记 needs_reboot 但后校验通过
    # （补丁装了就装了，没有回滚概念）
    reboot_pending = (body.reboot_action in ("reboot_now", "reboot_required", "prompt", "force")) or \
                     (body.message and "PATCH_REBOOT_REQUIRED=YES" in body.message)
    if reboot_pending:
        rt.needs_reboot = True
    # patch_install 没有回滚概念 → 总是通过
    return True


# _build_registry_rollback_plan 已提取至 app.core.vuln_engine.build_registry_rollback_plan
from app.core.vuln_engine import build_registry_rollback_plan as _build_registry_rollback_plan


async def _dispatch_rollback(db: AsyncSession, rt: "RemediationTask", tt: TaskTarget):
    """
    根据 rollback_plan 自动下发回滚 Task 到 Agent。
    使用现有 audit 机制记录回滚操作。
    """
    from app.models.models import Task
    from app.models.vuln import RemediationTask as RT

    rp = rt.rollback_plan or {}
    rb_type = rp.get("type", rt.fix_type)
    rb_action = rp.get("action") or rp

    if rb_type == "registry_fix" or rb_type == "registry":
        ops = rb_action.get("ops") or [rb_action] if isinstance(rb_action, dict) else []
        if not isinstance(ops, list):
            ops = [rb_action] if rb_action else []
        rollback_task = Task(
            name=f"回滚 修复任务 #{rt.id}（注册表还原）",
            task_type="registry", target_type="client",
            interactive=False, need_reboot=False, timeout=300,
            success_codes=[0], status="active",
            registry_ops=ops, run_as="system",
        )
    elif rb_type == "software_uninstall":
        # 回滚：重新安装（如果有原始包信息）
        pkg_id = rp.get("package_id")
        if pkg_id:
            rollback_task = Task(
                name=f"回滚 修复任务 #{rt.id}（重新安装）",
                task_type="install", package_id=pkg_id, target_type="client",
                interactive=False, need_reboot=False, timeout=1800,
                success_codes=[0], status="active", run_as="system",
            )
        else:
            logger.warning("修复任务 #%s rollback_plan 缺 package_id，无法自动回滚", rt.id)
            return
    else:
        logger.warning("修复任务 #%s rollback_plan type=%s 不支持自动回滚", rt.id, rb_type)
        return

    db.add(rollback_task)
    await db.flush()
    db.add(TaskTarget(
        task_id=rollback_task.id, client_id=tt.client_id,
        remediation_task_id=rt.id, status="pending",
    ))
    # ── 审计记录 ──
    from app.models.models import ActionAudit
    db.add(ActionAudit(
        hash_serial="system:rollback",
        client_id=tt.client_id,
        process_path=f"rollback:remediation_task:{rt.id}",
        arguments=str(rp)[:500],
        executed_at=datetime.now(timezone.utc),
        reported_at=datetime.now(timezone.utc),
    ))
    logger.info("修复任务 #%s 已自动下发回滚 Task #%s → client #%s",
                rt.id, rollback_task.id, tt.client_id)


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
    # serial / hash_serial 二选一兼容（schema 两者均为 Optional，至少一个必填）
    serial = body.serial or body.hash_serial
    if not serial:
        raise HTTPException(status_code=400, detail="serial 或 hash_serial 字段缺失")
    
    db.add(ActionAudit(
        hash_serial=serial,
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
    """
    删除客户端及相关联数据（GLPI 插件调用）
    
    🔒 修复问题1：原代码有 NameError (_hostname, _serial 未定义)，
       且未删除 Client 和 DeviceRegistration，也无 commit
    """
    from sqlalchemy import delete as sqldelete
    from sqlalchemy import func as sqlfunc
    from app.models.models import TaskTarget, ActionAudit, ClientReport, Task, DeviceRegistration

    # 1. 查找客户端
    result = await db.execute(select(Client).where(Client.id == client_id).with_for_update())
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="客户端不存在")

    hostname = client.hostname
    serial = client.hash_serial

    # 2. 收集属于该客户端的 task_ids（用于后续孤儿清理）
    tt_rows = await db.execute(
        select(TaskTarget.task_id).where(TaskTarget.client_id == client_id)
    )
    task_ids = list(set(row[0] for row in tt_rows))

    # 3. 删除 TaskTarget
    await db.execute(sqldelete(TaskTarget).where(TaskTarget.client_id == client_id))

    # 4. 删除孤儿 Task（没有剩余 TaskTarget 的）
    if task_ids:
        non_orphan = await db.execute(
            select(TaskTarget.task_id).where(TaskTarget.task_id.in_(task_ids)).distinct()
        )
        non_orphan_ids = {row[0] for row in non_orphan}
        orphan_ids = [tid for tid in task_ids if tid not in non_orphan_ids]
        if orphan_ids:
            await db.execute(sqldelete(Task).where(Task.id.in_(orphan_ids)))

    # 5. 🔒 修复问题1：删除 DeviceRegistration（之前漏了）
    await db.execute(sqldelete(DeviceRegistration).where(DeviceRegistration.hash_serial == serial))

    # 6. 🔒 修复问题1：删除 Client 本身（之前漏了）
    await db.delete(client)

    # 7. 🔒 修复问题1：提交事务（之前漏了）
    await db.commit()

    logger.info(f"Deleted client #{client_id} ({hostname}, {serial})")
    return OkResponse(message=f"已删除 {hostname} 及关联数据")


# ════════════════════════════════════════════════════════════════════════════
# 管理员推送任务：POST /api/tasks（GLPI token 保护）
# 支持 install / uninstall / run_command / registry / cleanup 五种类型
# ════════════════════════════════════════════════════════════════════════════
@router.post("/tasks", response_model=OkResponse)
async def create_task(
    body: TaskCreate,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """管理员创建任务并分发到目标客户端（命令类任务无需关联安装包）"""
    valid_types = ("install", "uninstall", "run_command", "registry", "cleanup")
    if body.task_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"不支持的任务类型: {body.task_type}")

    # ── 参数校验 ──
    if body.task_type == "install" and not body.package_id:
        raise HTTPException(status_code=400, detail="install 任务必须指定 package_id")
    if body.task_type == "uninstall" and not body.uninstall_target:
        raise HTTPException(status_code=400, detail="uninstall 任务必须指定 uninstall_target")
    if body.task_type == "run_command" and not body.command:
        raise HTTPException(status_code=400, detail="run_command 任务必须指定 command")
    if body.task_type == "registry" and not body.registry_ops:
        raise HTTPException(status_code=400, detail="registry 任务必须指定 registry_ops")
    if body.task_type == "cleanup" and not body.cleanup_paths:
        raise HTTPException(status_code=400, detail="cleanup 任务必须指定 cleanup_paths")

    # ── 解析目标客户端 id 列表 ──
    client_ids: list[int] = []
    if body.target_type == "all":
        res = await db.execute(select(Client.id))
        client_ids = [r[0] for r in res.all()]
    elif body.target_type == "group":
        res = await db.execute(
            select(Client.id).where(Client.group_id.in_(body.target_ids)))
        client_ids = [r[0] for r in res.all()]
    else:  # client
        client_ids = body.target_ids

    if not client_ids:
        raise HTTPException(status_code=400, detail="未解析到任何目标客户端")

    # ── 创建 Task ──
    task = Task(
        name=body.name,
        task_type=body.task_type,
        uninstall_target=body.uninstall_target if body.task_type == "uninstall" else None,
        package_id=body.package_id if body.task_type == "install" else None,
        target_type=body.target_type,
        interactive=body.interactive,
        need_reboot=body.need_reboot,
        timeout=body.timeout,
        success_codes=body.success_codes or [0],
        status="active",
        # 命令类字段
        command=body.command if body.task_type == "run_command" else None,
        interpreter=body.interpreter if body.task_type == "run_command" else None,
        registry_ops=[op.model_dump() for op in body.registry_ops] if body.registry_ops else None,
        cleanup_paths=[p.model_dump() for p in body.cleanup_paths] if body.cleanup_paths else None,
        run_as=body.run_as,
    )
    db.add(task)
    await db.flush()  # 拿到 task.id

    # ── 创建 TaskTarget ──
    for cid in client_ids:
        db.add(TaskTarget(
            task_id=task.id,
            client_id=cid,
            status="pending",
        ))
    await db.commit()
    logger.info(
        f"Created task #{task.id} type={body.task_type} -> {len(client_ids)} clients")
    return OkResponse(message=f"已创建任务 #{task.id}，分发到 {len(client_ids)} 个客户端")


# ════════════════════════════════════════════════════════════════════════════
# 客户端自更新：GET /api/client/update + GET /api/client/update/download
# ════════════════════════════════════════════════════════════════════════════
def _read_client_update_manifest() -> dict | None:
    """读取 CLIENT_UPDATE_DIR/version.json，返回 dict 或 None"""
    import json as _json
    manifest_path = os.path.join(settings.CLIENT_UPDATE_DIR, "version.json")
    if not os.path.isfile(manifest_path):
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8-sig") as f:
            return _json.load(f)
    except Exception as ex:
        logger.error(f"读取更新清单失败: {ex}")
        return None


@router.get("/client/update", response_model=ClientUpdateOut)
async def client_update_info(
    _: Client = Depends(require_agent_auth),
):
    """返回最新客户端版本信息；若无更新包则返回 available=false"""
    manifest = _read_client_update_manifest()
    if not manifest or not manifest.get("version"):
        return ClientUpdateOut(available=False)

    filename = manifest.get("filename") or "itasset4-update.zip"
    return ClientUpdateOut(
        available=True,
        version=manifest.get("version"),
        url=f"{settings.SERVER_URL}/api/client/update/download",
        hash=manifest.get("hash"),
        size=manifest.get("size"),
        mandatory=bool(manifest.get("mandatory", False)),
        notes=manifest.get("notes"),
    )


@router.get("/client/update/download")
async def client_update_download(
    _: Client = Depends(require_agent_auth),
):
    """下载客户端更新包 zip（仅已注册 Agent 可下载）"""
    manifest = _read_client_update_manifest()
    if not manifest:
        raise HTTPException(status_code=404, detail="更新包不存在")

    filename = manifest.get("filename") or "itasset4-update.zip"
    path = os.path.join(settings.CLIENT_UPDATE_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="更新包文件缺失")

    return FileResponse(
        path,
        filename=filename,
        media_type="application/zip",
    )
