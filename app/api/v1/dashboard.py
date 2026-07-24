"""
管理端点：仪表盘、差异报告、导出（供 GLPI 插件手动导入）、任务管理
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, text, delete as sqlalchemy_delete
from app.core.database import get_db
from app.core.deps import require_glpi_token
from app.core.ws_manager import ws_manager
from app.models.models import Client, ClientReport, Task, TaskTarget, ActionAudit, Package
from app.schemas.schemas import (
    DashboardOut, DiffStatsOut,
    ClientExportItem, ClientExportList, OkResponse,
)

router = APIRouter(prefix="/api", tags=["dashboard"])

logger = logging.getLogger(__name__)


# ── GET /api/dashboard ────────────────────────────────────────────────────────
@router.get("/dashboard", response_model=DashboardOut)
async def get_dashboard(
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    total_clients  = (await db.execute(select(func.count(Client.id)))).scalar() or 0
    pending_tasks  = (await db.execute(select(func.count(TaskTarget.id)).where(TaskTarget.status == "pending"))).scalar() or 0
    failed_tasks   = (await db.execute(select(func.count(TaskTarget.id)).where(TaskTarget.status == "failed"))).scalar() or 0
    
    # 在线 = 仅取 WebSocket 实时连接数（精确），last_seen 24h 窗口过宽会虚高
    # 次选：WS 为 0 时（服务刚重启）降级用 5 分钟内 last_seen 兜底
    ws_online = ws_manager.online_count()
    if ws_online == 0:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        ws_online = (await db.execute(
            select(func.count(Client.id)).where(Client.last_seen >= cutoff)
        )).scalar() or 0
    online_clients = ws_online
    
    online_serials = ws_manager.online_serials()
    if not online_serials and ws_online > 0:
        # fallback: last_seen within 5min
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        rows = await db.execute(
            select(Client.hash_serial).where(Client.last_seen >= cutoff).limit(200))
        online_serials = [r[0] for r in rows]

    return DashboardOut(
        total_clients=total_clients,
        online_clients=online_clients,
        pending_tasks=pending_tasks,
        failed_tasks=failed_tasks,
        online_serials=online_serials,
    )


# ── GET /api/dashboard/diff ───────────────────────────────────────────────────
@router.get("/dashboard/diff", response_model=DiffStatsOut)
async def get_diff_stats(
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """差异统计：客户端有记录但 GLPI 中 serial 对应的 glpi_items_id=0 的数量"""
    # GLPI uses PluginAdmanagerSyncState::getDiffCount() for accurate diff count.
# FastAPI endpoint returns 0 to avoid misleading 100% diff display.
    total = (await db.execute(select(func.count(Client.id)))).scalar() or 0
    last_report = (await db.execute(
        select(func.max(Client.last_seen))
    )).scalar()
    return DiffStatsOut(diff_count=0, total_clients=total, last_report_at=last_report)


# ── GET /api/export/clients ───────────────────────────────────────────────────
@router.get("/export/clients", response_model=ClientExportList)
async def export_clients(
    page:    int = Query(1, ge=1),
    limit:   int = Query(50, ge=1, le=200),
    keyword: str = Query("", description="按 hostname/serial/ip 模糊搜索"),
    _:       bool = Depends(require_glpi_token),
    db:      AsyncSession = Depends(get_db),
):
    """导出终端列表供 GLPI 手动导入，支持 keyword 关键字过滤"""
    offset = (page - 1) * limit

    # 构造过滤条件
    from sqlalchemy import or_, String
    filters = []
    if keyword:
        kw = f"%{keyword}%"
        filters.append(or_(
            Client.hostname.ilike(kw),
            Client.hash_serial.ilike(kw),
            Client.ip.ilike(kw),
        ))

    count_q = select(func.count(Client.id))
    list_q  = select(Client).order_by(Client.id)
    if filters:
        count_q = count_q.where(*filters)
        list_q  = list_q.where(*filters)

    total   = (await db.execute(count_q)).scalar() or 0
    result  = await db.execute(list_q.offset(offset).limit(limit))
    clients = result.scalars().all()

    # v2: batch-fetch latest reports for all clients (1 query, not N)
    cids = [c.id for c in clients]
    latest_map = {}
    if cids:
        subq = (
            select(
                ClientReport.client_id,
                func.max(ClientReport.collected_at).label("max_collected"))
            .where(ClientReport.client_id.in_(cids))
            .group_by(ClientReport.client_id)
            .subquery()
        )
        latest_rows = await db.execute(
            select(ClientReport).join(
                subq,
                and_(
                    ClientReport.client_id == subq.c.client_id,
                    ClientReport.collected_at == subq.c.max_collected)))
        for r in latest_rows.scalars().all():
            latest_map[r.client_id] = r

    items = []
    for c in clients:
        rep = latest_map.get(c.id)
        items.append(ClientExportItem(
            client_id=c.id,
            serial=c.hash_serial,
            hostname=c.hostname,
            ip=c.ip,
            os_name=c.os,
            cpu=c.cpu,
            memory_gb=c.memory_gb,
            manufacturer=None,
            model=None,
            last_seen=c.last_seen,
            current_user=rep.current_user if rep else None,
            bios_serial=c.bios_serial,
            machine_guid=c.machine_guid,
            real_serial=c.bios_serial,
            group_id=c.group_id,
        ))
    return ClientExportList(items=items, total=total, page=page, limit=limit)


# ── GET /api/export/software/{client_id} ─────────────────────────────────────
@router.get("/export/software/{client_id}")
async def export_software(
    client_id: int,
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """导出指定终端最新软件清单"""
    result = await db.execute(
        select(ClientReport)
        .where(ClientReport.client_id == client_id)
        .order_by(ClientReport.collected_at.desc())
        .limit(1)
    )
    rep = result.scalar_one_or_none()
    if not rep:
        raise HTTPException(status_code=404, detail="未找到该终端的采集记录")
    return {"client_id": client_id, "software": rep.software or [], "collected_at": rep.collected_at}


# ── GET /api/audit/actions ───────────────────────────────────────────────────
@router.get("/audit/actions")
async def get_audit_actions(
    serial:     Optional[str] = None,
    date_from:  Optional[datetime] = None,
    date_to:    Optional[datetime] = None,
    limit:      int = Query(100, ge=1, le=500),
    _:          bool = Depends(require_glpi_token),
    db:         AsyncSession = Depends(get_db),
):
    conditions = []
    if serial:
        conditions.append(ActionAudit.hash_serial == serial)
    if date_from:
        conditions.append(ActionAudit.reported_at >= date_from)
    if date_to:
        conditions.append(ActionAudit.reported_at <= date_to)

    q = select(ActionAudit).order_by(ActionAudit.reported_at.desc()).limit(limit)
    if conditions:
        q = q.where(and_(*conditions))
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id, "hash_serial": r.hash_serial, "process_path": r.process_path,
            "arguments": r.arguments, "pid": r.pid, "exit_code": r.exit_code,
            "executed_at": r.executed_at, "reported_at": r.reported_at,
        }
        for r in rows
    ]


# ── POST /api/tasks/admin/create ─────────────────────────────────────────────
@router.post("/tasks/admin/create", response_model=OkResponse)
async def create_task(
    name:        str,
    package_id:  int,
    target_type: str = "client",
    target_id:   Optional[int] = None,
    interactive: bool = True,
    need_reboot: bool = False,
    timeout:     int  = 600,
    _:           bool = Depends(require_glpi_token),
    db:          AsyncSession = Depends(get_db),
):
    """创建部署任务，自动展开目标终端列表"""
    from app.models.models import Group
    pkg = (await db.execute(select(Package).where(Package.id == package_id))).scalar_one_or_none()
    if not pkg:
        raise HTTPException(status_code=404, detail="包不存在")

    task = Task(
        name=name, package_id=package_id,
        target_type=target_type, target_id=target_id,
        interactive=interactive, need_reboot=need_reboot, timeout=timeout,
    )
    db.add(task)
    await db.flush()

    # 展开目标终端
    if target_type == "all":
        clients_res = await db.execute(select(Client))
        client_ids = [c.id for c in clients_res.scalars().all()]
    elif target_type == "group" and target_id:
        clients_res = await db.execute(select(Client).where(Client.group_id == target_id))
        client_ids = [c.id for c in clients_res.scalars().all()]
    else:
        if not target_id:
            raise HTTPException(status_code=400, detail="target_type=client 时 target_id 不能为空")
        client_ids = [target_id]

    for cid in client_ids:
        db.add(TaskTarget(task_id=task.id, client_id=cid))

    await db.commit()

    # WebSocket 推送在线终端立即执行
    online = [s for s in ws_manager.online_serials()]
    if online:
        clients_res = await db.execute(select(Client).where(Client.id.in_(client_ids)))
        serials = {c.id: c.hash_serial for c in clients_res.scalars().all()}
        for cid in client_ids:
            serial = serials.get(cid)
            if serial and ws_manager.is_online(serial):
                await ws_manager.send(serial, {"type": "task_push", "task_name": name})

    return OkResponse(message=f"任务已创建，目标终端 {len(client_ids)} 台")


# ── POST /api/tasks/admin/create-uninstall ───────────────────────────────────
@router.post("/tasks/admin/create-uninstall", response_model=OkResponse)
async def create_uninstall_task(
    software_name: str,
    client_id:     int,
    _:             bool = Depends(require_glpi_token),
    db:            AsyncSession = Depends(get_db),
):
    """创建卸载任务——无需包，客户端直接查注册表执行卸载"""
    client = (await db.execute(select(Client).where(Client.id == client_id))).scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="终端不存在")

    # success_codes: 0=通用成功, 19=Chrome UNINSTALL_SUCCESSFUL,
    #                 3010=需重启但成功(MSI常见)
    task = Task(
        name=f"卸载 {software_name}",
        task_type="uninstall",
        uninstall_target=software_name,
        package_id=None,
        target_type="client",
        target_id=client_id,
        interactive=False,
        need_reboot=False,
        timeout=300,
        success_codes=[0, 19, 3010],
    )
    db.add(task)
    await db.flush()
    db.add(TaskTarget(task_id=task.id, client_id=client_id))
    await db.commit()

    # WebSocket 推送
    if ws_manager.is_online(client.hash_serial):
        await ws_manager.send(client.hash_serial, {"type": "task_push", "task_name": task.name})

    return OkResponse(message=f"卸载任务已创建: {software_name} → {client.hostname}")


# ── PATCH /api/tasks/admin/cancel ────────────────────────────────────────────
@router.patch("/tasks/admin/cancel", response_model=OkResponse)
async def cancel_task(
    task_id: int,
    _:       bool = Depends(require_glpi_token),
    db:      AsyncSession = Depends(get_db),
):
    """取消任务（将所有 pending/deferred/running 的 TaskTarget 设为 cancelled）"""
    result = await db.execute(
        select(TaskTarget).where(
            TaskTarget.task_id == task_id,
            TaskTarget.status.in_(["pending", "deferred", "running"])
        )
    )
    targets = result.scalars().all()
    for tt in targets:
        tt.status = "cancelled"
    task_res = await db.execute(select(Task).where(Task.id == task_id))
    task = task_res.scalar_one_or_none()
    if task:
        task.status = "cancelled"
    await db.commit()
    return OkResponse(message=f"已取消 {len(targets)} 条任务记录")


# ── DELETE /api/tasks/admin/{task_id} ────────────────────────────────────────
@router.delete("/tasks/admin/{task_id}", response_model=OkResponse)
async def delete_task(
    task_id: int,
    _:       bool = Depends(require_glpi_token),
    db:      AsyncSession = Depends(get_db),
):
    """删除任务及其所有 TaskTarget 记录"""
    tt_count = (await db.execute(
        select(func.count(TaskTarget.id)).where(TaskTarget.task_id == task_id)
    )).scalar() or 0
    await db.execute(sqlalchemy_delete(TaskTarget).where(TaskTarget.task_id == task_id))
    await db.execute(sqlalchemy_delete(Task).where(Task.id == task_id))
    await db.commit()
    return OkResponse(message=f"已删除任务及 {tt_count} 条终端记录")


# ── PATCH /api/tasks/admin/reset-failed ──────────────────────────────────────
@router.patch("/tasks/admin/reset-failed", response_model=OkResponse)
async def reset_failed_tasks(
    task_id: int,
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(TaskTarget).where(TaskTarget.task_id == task_id, TaskTarget.status == "failed")
    )
    targets = result.scalars().all()
    for tt in targets:
        tt.status      = "pending"
        tt.retry_count = 0
    await db.commit()
    return OkResponse(message=f"已重置 {len(targets)} 条失败记录")


# ── GET /api/packages/list ────────────────────────────────────────────────────
@router.get("/packages/list")
async def list_packages_admin(
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """列出所有安装包（供 GLPI 插件下拉选择）"""
    result = await db.execute(select(Package).order_by(Package.id.desc()))
    pkgs = result.scalars().all()
    return [
        {
            "id": p.id, "name": p.name, "version": p.version,
            "filename": p.filename, "file_hash": p.file_hash,
            "file_size": p.file_size, "description": p.description,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in pkgs
    ]


# ── GET /api/tasks/admin/list ─────────────────────────────────────────────────
@router.get("/tasks/admin/list")
async def list_tasks_admin(
    status: Optional[str] = None,
    limit:  int = Query(50, ge=1, le=200),
    _:      bool = Depends(require_glpi_token),
    db:     AsyncSession = Depends(get_db),
):
    """列出部署任务（含进度统计）"""
    from sqlalchemy import func as sqlfunc
    from app.models.models import Task, TaskTarget, Package

    # v2: batch queries — 1+1+1=3 queries instead of 1+50+50=101
    result = await db.execute(
        select(Task).order_by(Task.id.desc()).limit(limit))
    tasks = result.scalars().all()
    if not tasks:
        return []

    task_ids = [t.id for t in tasks]
    pkg_ids = {t.package_id for t in tasks if t.package_id}

    # Batch 0: client hostnames for single-client tasks
    single_client_ids = {t.target_id for t in tasks if t.target_type == "client" and t.target_id}
    client_name_map = {}
    if single_client_ids:
        from app.models.models import Client as _Client
        c_rows = await db.execute(
            select(_Client.id, _Client.hostname).where(_Client.id.in_(single_client_ids)))
        client_name_map = {row.id: row.hostname for row in c_rows}

    # Batch 1: all packages
    pkg_map = {}
    if pkg_ids:
        pkg_rows = await db.execute(
            select(Package).where(Package.id.in_(pkg_ids)))
        pkg_map = {p.id: p for p in pkg_rows.scalars().all()}

    # Batch 2: all status aggregations in one query
    stats_rows = await db.execute(
        select(TaskTarget.task_id, TaskTarget.status,
               sqlfunc.count(TaskTarget.id).label("cnt"))
        .where(TaskTarget.task_id.in_(task_ids))
        .group_by(TaskTarget.task_id, TaskTarget.status))
    stats_map = {}
    for row in stats_rows:
        stats_map.setdefault(row.task_id, {})[row.status] = row.cnt

    out = []
    for t in tasks:
        pkg = pkg_map.get(t.package_id)
        stats = stats_map.get(t.id, {})
        total = sum(stats.values())

        out.append({
            "id": t.id, "name": t.name,
            "task_type": t.task_type,
            "uninstall_target": t.uninstall_target,
            "package_name": pkg.name if pkg else (t.uninstall_target or "—"),
            "package_version": pkg.version if pkg else "",
            "target_type": t.target_type,
            "target_name": client_name_map.get(t.target_id, "") if t.target_type == "client" else "",
            "status": t.status,
            "interactive": t.interactive,
            "need_reboot": t.need_reboot,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "progress": {
                "total":   total,
                "pending": stats.get("pending", 0),
                "running": stats.get("running", 0),
                "success": stats.get("success", 0),
                "failed":  stats.get("failed", 0),
                "deferred":stats.get("deferred", 0),
            },
        })
    return out


# ── GET /api/tasks/admin/{task_id}/targets ────────────────────────────────────
@router.get("/tasks/admin/{task_id}/targets")
async def get_task_targets(
    task_id: int,
    _:       bool = Depends(require_glpi_token),
    db:      AsyncSession = Depends(get_db),
):
    """查看单个任务各终端执行明细"""
    from app.models.models import TaskTarget, Client

    result = await db.execute(
        select(TaskTarget, Client)
        .join(Client, TaskTarget.client_id == Client.id)
        .where(TaskTarget.task_id == task_id)
        .order_by(TaskTarget.id)
    )
    rows = result.all()
    return [
        {
            "target_id": tt.id,
            "client_id": c.id,
            "hostname":  c.hostname,
            "hash_serial":    c.hash_serial,
            "status":    tt.status,
            "message":   tt.message,
            "install_log": tt.install_log,
            "reboot_action": tt.reboot_action,
            "retry_count":   tt.retry_count,
            "defer_count":   tt.defer_count,
            "executed_at":   tt.executed_at.isoformat() if tt.executed_at else None,
        }
        for tt, c in rows
    ]


# ── POST /api/maintenance/cleanup-reports ──────────────────────────────────
@router.post("/maintenance/cleanup-reports", response_model=OkResponse)
async def cleanup_old_reports(
    keep_per_client: int = 30,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """Clean old ClientReports, keep only latest keep_per_client per terminal"""
    result = await db.execute(text("""
        DELETE FROM client_reports
        WHERE id NOT IN (
            SELECT id FROM (
                SELECT id,
                    ROW_NUMBER() OVER (
                        PARTITION BY client_id ORDER BY collected_at DESC
                    ) AS rn
                FROM client_reports
            ) ranked
            WHERE ranked.rn <= :keep
        )
    """), {"keep": keep_per_client})
    await db.commit()
    deleted = result.rowcount
    logger.info(f"ClientReport cleanup: deleted {deleted} rows")
    return OkResponse(message=f"Cleanup done: {deleted} old reports removed")
