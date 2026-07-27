"""
漏洞扫描 AI 辅助修复 — API 路由（第一阶段 + 执行通道）

所有端点前缀 /api/vuln，统一 GLPI Bearer Token 鉴权（require_glpi_token）。

设计要点：
  - 上传解析为后台任务：/imports 立即返回 import_id，前端轮询 /imports/{id} 看进度
  - approve/batch-approve 时，可自动执行的修复类型（registry_fix / software_uninstall）
    立即生成 Task+TaskTarget 下发到客户端代理（状态 → dispatched）；
    客户端回报结果时由 agent.py 回写 done/failed（见 report_task_result）
  - patch_install / software_upgrade / manual_review / unsupported 批准后保持 approved，需人工处理
"""
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, File
from sqlalchemy import case, func, select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_glpi_token
from app.core.config import get_settings
from app.core.vuln_engine import (
    REBOOT_BLACKLIST,
    scan_reboot_blacklist,
    can_transition,
    gate_reason as _gate_reason_pure,
    build_patch_install_script,
    IRREVERSIBLE_FIX_TYPES,
)
from app.models.models import Client, Task, TaskTarget, Package
from app.models.vuln import (
    VulnScanImport, VulnFinding, RemediationTask, RemediationRule,
    AutonomyPolicy,
    MATCH_CONFIDENCES, FIX_TYPES, RISK_LEVELS, TASK_STATUSES, RULE_STATUSES,
    AUTO_DISPATCH_FIX_TYPES,
)
from app.schemas.vuln import (
    ImportOut, ImportStatsOut, FindingOut, ResolveMatchRequest,
    TaskListItem, TaskDetailOut, ApproveRequest, BatchApproveRequest,
    RuleIn, RuleUpdate, RuleOut,
)
from app.services import vuln_service as vs
from app.services.package_match import match_package

settings = get_settings()
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vuln", tags=["vuln"])

# 向后兼容别名（原模块内代码保持引用不变）
_REBOOT_BLACKLIST = REBOOT_BLACKLIST
_scan_reboot_blacklist = scan_reboot_blacklist
_can_transition = can_transition
_build_patch_install_script = build_patch_install_script


async def _import_or_404(db: AsyncSession, import_id: int):
    return (await db.execute(
        select(VulnScanImport).where(VulnScanImport.id == import_id)
    )).scalar_one_or_none()


# ── 导入批次 ──────────────────────────────────────────────────────────────────
@router.post("/imports", response_model=ImportOut)
async def upload_import(
    bg: BackgroundTasks,
    file: UploadFile = File(...),
    uploaded_by: str = "",
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """上传 Qualys 格式 xlsx，后台解析，返回 import_id。"""
    if not file.filename or not file.filename.lower().endswith((".xlsx", ".xls")):
        raise HTTPException(400, "仅支持 .xlsx 文件")
    # 大小检查
    content = await file.read()
    max_b = settings.VULN_XLSX_MAX_MB * 1024 * 1024
    if len(content) > max_b:
        raise HTTPException(413, f"文件超过 {settings.VULN_XLSX_MAX_MB}MB 上限")
    if len(content) == 0:
        raise HTTPException(400, "文件为空")

    Path(settings.VULN_UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
    imp = VulnScanImport(
        filename=file.filename,
        uploaded_by=uploaded_by or None,
        status="pending",
    )
    db.add(imp)
    await db.commit()
    await db.refresh(imp)

    # 持久化原始文件到 stored/，供「重新解析」复用（不再用易失的临时文件）
    stored_dir = os.path.join(settings.VULN_UPLOAD_DIR, "stored")
    os.makedirs(stored_dir, exist_ok=True)
    stored_path = os.path.join(stored_dir, f"vuln_import_{imp.id}.xlsx")
    with open(stored_path, "wb") as f:
        f.write(content)

    bg.add_task(vs.parse_import, imp.id, stored_path)
    return ImportOut.model_validate(imp)


@router.post("/imports/{import_id}/reparse", response_model=ImportOut)
async def reparse_import(
    import_id: int,
    bg: BackgroundTasks,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """重新解析已上传批次：使用当前 AI 网关 / 提示配置，清空旧 findings（级联 tasks）后重跑。"""
    imp = await _import_or_404(db, import_id)
    if not imp:
        raise HTTPException(404, "导入批次不存在")
    stored_path = os.path.join(settings.VULN_UPLOAD_DIR, "stored", f"vuln_import_{import_id}.xlsx")
    if not os.path.exists(stored_path):
        raise HTTPException(400, "原始文件已清理，无法重新解析；请重新上传 xlsx")
    # 清空旧漏洞条目（级联删除关联修复任务），重置批次状态
    await db.execute(delete(VulnFinding).where(VulnFinding.import_id == import_id))
    await db.commit()
    imp.status = "pending"
    imp.row_count = 0
    imp.processed_count = 0
    imp.error_message = None
    await db.commit()
    bg.add_task(vs.parse_import, import_id, stored_path)
    return ImportOut.model_validate(imp)


@router.get("/imports", response_model=list[ImportOut])
async def list_imports(
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(
        select(VulnScanImport).order_by(VulnScanImport.id.desc())
    )).scalars().all()
    return [ImportOut.model_validate(r) for r in rows]


@router.get("/imports/{import_id}", response_model=ImportStatsOut)
async def import_stats(
    import_id: int,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    imp = await _import_or_404(db, import_id)
    if not imp:
        raise HTTPException(404, "导入批次不存在")

    # 匹配率统计
    frows = (await db.execute(
        select(VulnFinding.match_confidence, func.count())
        .where(VulnFinding.import_id == import_id)
        .group_by(VulnFinding.match_confidence)
    )).all()
    match_stats = {k: 0 for k in MATCH_CONFIDENCES}
    for conf, cnt in frows:
        match_stats[conf] = cnt

    # 任务风险统计 + 修复类型统计
    trows = (await db.execute(
        select(RemediationTask.risk_level, RemediationTask.fix_type, func.count())
        .join(VulnFinding, RemediationTask.finding_id == VulnFinding.id)
        .where(VulnFinding.import_id == import_id)
        .group_by(RemediationTask.risk_level, RemediationTask.fix_type)
    )).all()
    task_stats = {k: 0 for k in RISK_LEVELS}
    fix_type_stats = {k: 0 for k in FIX_TYPES}
    for risk, fix, cnt in trows:
        if risk in task_stats:
            task_stats[risk] += cnt
        if fix in fix_type_stats:
            fix_type_stats[fix] += cnt

    total = sum(match_stats.values())
    matched = total - match_stats["unmatched"]
    match_rate = round(matched / total, 4) if total else 0.0

    return ImportStatsOut(
        **ImportOut.model_validate(imp).model_dump(),
        match_stats=match_stats,
        task_stats=task_stats,
        fix_type_stats=fix_type_stats,
        match_rate=match_rate,
    )


@router.get("/imports/{import_id}/findings", response_model=list[FindingOut])
async def list_findings(
    import_id: int,
    match: str = "",      # 可选过滤：exact_hostname/exact_ip/fuzzy/unmatched
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    if not await _import_or_404(db, import_id):
        raise HTTPException(404, "导入批次不存在")
    q = (select(VulnFinding, Client.hostname)
         .outerjoin(Client, VulnFinding.asset_id == Client.id)
         .where(VulnFinding.import_id == import_id))
    if match:
        q = q.where(VulnFinding.match_confidence == match)
    rows = (await db.execute(q.order_by(VulnFinding.id))).all()
    out = []
    for f, hostname in rows:
        d = FindingOut.model_validate(f).model_dump()
        d["asset_hostname"] = hostname
        out.append(FindingOut(**d))
    return out


@router.post("/findings/{finding_id}/resolve-match", response_model=FindingOut)
async def resolve_match(
    finding_id: int,
    body: ResolveMatchRequest,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """人工修正资产匹配（asset_id=None 表示确认为无法匹配）。"""
    f = (await db.execute(
        select(VulnFinding).where(VulnFinding.id == finding_id)
    )).scalar_one_or_none()
    if not f:
        raise HTTPException(404, "finding 不存在")

    # 校验 asset 存在
    if body.asset_id is not None:
        cli = (await db.execute(
            select(Client.id).where(Client.id == body.asset_id)
        )).scalar_one_or_none()
        if not cli:
            raise HTTPException(400, "指定的 asset_id 不存在")

    f.asset_id = body.asset_id
    f.match_confidence = "unmatched" if body.asset_id is None else "exact_hostname"

    if body.regenerate_task:
        # 同步更新该 finding 下所有任务的 asset_id（资产修正确认后任务应指向正确资产）
        tasks = (await db.execute(
            select(RemediationTask).where(RemediationTask.finding_id == finding_id)
        )).scalars().all()
        for t in tasks:
            t.asset_id = body.asset_id

    await db.commit()
    await db.refresh(f)
    out = FindingOut.model_validate(f).model_dump()
    if f.asset_id:
        h = (await db.execute(
            select(Client.hostname).where(Client.id == f.asset_id)
        )).scalar_one_or_none()
        out["asset_hostname"] = h
    return FindingOut(**out)


# ── 修复任务 ──────────────────────────────────────────────────────────────────
@router.get("/tasks", response_model=list[TaskListItem])
async def list_tasks(
    status: str = "",        # pending/approved/rejected/needs_manual（默认全部）
    import_id: int = 0,
    risk: str = "",
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    if status and status not in TASK_STATUSES:
        raise HTTPException(400, "非法的 status 过滤")
    q = (select(RemediationTask, VulnFinding, Client.hostname)
         .join(VulnFinding, RemediationTask.finding_id == VulnFinding.id)
         .outerjoin(Client, RemediationTask.asset_id == Client.id))
    if status:
        q = q.where(RemediationTask.status == status)
    if risk:
        q = q.where(RemediationTask.risk_level == risk)
    if import_id:
        q = q.where(VulnFinding.import_id == import_id)
    q = q.order_by(
        # 高风险优先，便于管理员先处理
        case({"high": 0, "medium": 1, "low": 2},
             value=RemediationTask.risk_level, else_=3),
        RemediationTask.id,
    )
    rows = (await db.execute(q)).all()
    out = []
    for t, f, hostname in rows:
        d = TaskListItem.model_validate(t).model_dump()
        d["finding_id"] = f.id
        d["import_id"] = f.import_id
        d["ip"] = f.ip
        d["dns_name"] = f.dns_name
        d["qid"] = f.qid
        d["title"] = f.title
        d["match_confidence"] = f.match_confidence
        d["asset_hostname"] = hostname
        d["action_summary"] = vs.action_summary(t.fix_type, t.action_json)
        out.append(TaskListItem(**d))
    return out


@router.get("/tasks/{task_id}", response_model=TaskDetailOut)
async def task_detail(
    task_id: int,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(
        select(RemediationTask, VulnFinding, Client.hostname)
        .join(VulnFinding, RemediationTask.finding_id == VulnFinding.id)
        .outerjoin(Client, RemediationTask.asset_id == Client.id)
        .where(RemediationTask.id == task_id)
    )).one_or_none()
    if not row:
        raise HTTPException(404, "任务不存在")
    t, f, hostname = row
    d = TaskDetailOut.model_validate(t).model_dump()
    d["finding_id"] = f.id
    d["import_id"] = f.import_id
    d["ip"] = f.ip
    d["dns_name"] = f.dns_name
    d["qid"] = f.qid
    d["title"] = f.title
    d["match_confidence"] = f.match_confidence
    d["asset_hostname"] = hostname
    d["results_raw"] = f.results_raw
    d["solution_raw"] = f.solution_raw
    d["action_summary"] = vs.action_summary(t.fix_type, t.action_json)
    d["matched_package_id"] = t.matched_package_id
    d["needs_reboot"] = t.needs_reboot
    if t.fix_type == "software_upgrade" and t.matched_package_id:
        pkg = (await db.execute(
            select(Package).where(Package.id == t.matched_package_id)
        )).scalar_one_or_none()
        d["matched_package_name"] = pkg.name if pkg else None
    return TaskDetailOut(**d)


# ── 执行通道：approved → 下发客户端代理 ─────────────────────────────────────
# 注册表值类型映射（LLM/规则输出 → 客户端 RegistryOp.type）
_VTYPE_MAP = {
    "REG_SZ": "string", "REG_EXPAND_SZ": "expand",
    "REG_DWORD": "dword", "REG_QWORD": "qword",
    "REG_BINARY": "binary", "REG_MULTI_SZ": "string",
}


def _split_registry_path(path: str) -> tuple[str, str]:
    """'HKLM\\SOFTWARE\\X' / 'HKEY_LOCAL_MACHINE\\SOFTWARE\\X' → ('HKLM', 'SOFTWARE\\X')"""
    p = (path or "").strip().strip("\\")
    root, _, sub = p.partition("\\")
    root_map = {
        "HKLM": "HKLM", "HKEY_LOCAL_MACHINE": "HKLM",
        "HKCU": "HKCU", "HKEY_CURRENT_USER": "HKCU",
    }
    return root_map.get(root.upper(), "HKLM"), sub


async def _find_rule(db: AsyncSession, finding: VulnFinding) -> RemediationRule | None:
    """按 finding 的 QID 查当前规则（以规则「当前」状态为准，而非解析时快照）"""
    return (await db.execute(
        select(RemediationRule).where(RemediationRule.qid == finding.qid)
    )).scalar_one_or_none()


def _gate_reason(task: RemediationTask, rule: RemediationRule | None,
                 for_auto: bool) -> str | None:
    """
    下发门禁（三道闸 + 回滚方案硬闸门）。返回 None 表示允许下发，否则返回阻止原因：
      闸1·规则转正：规则必须存在且为 active（人工已确认）。
      闸2·高风险：for_auto=True 时 high 风险不下发，需显式「确认下发」。
      闸3·回滚方案：不可逆操作（software_uninstall / service_config）
           必须有 rollback_plan，否则禁止自动下发。
    注意：patch_install 不在不可逆列表中（补丁没有回滚概念，装了就装了）。
    """
    return _gate_reason_pure(
        fix_type=task.fix_type,
        asset_id=task.asset_id,
        risk_level=task.risk_level,
        for_auto=for_auto,
        rule_status=rule.status if rule else None,
        rule_rollback_plan=rule.rollback_plan if rule else None,
        task_rollback_plan=task.rollback_plan if hasattr(task, 'rollback_plan') else None,
        matched_package_id=getattr(task, 'matched_package_id', None),
    )


async def _dispatch_to_agent(db: AsyncSession, task: RemediationTask,
                             finding: VulnFinding, action: dict) -> str | None:
    """
    将可自动执行的修复任务生成 Task+TaskTarget 下发到客户端代理。
    action 以当前 active 规则的 action_template 为准（人工在规则库编辑后生效），
    而非任务解析时的 action_json 快照。
    返回 None 表示已成功生成下发任务；否则返回未下发原因。
    """
    a = action or {}

    if task.fix_type == "registry_fix":
        changes = a.get("changes") or []
        if not changes:
            # 兼容旧单键格式（registry_path/value_name/value_data/value_type）
            path = a.get("registry_path") or ""
            if not path:
                return "action 缺少 registry_path / changes"
            root, subkey = _split_registry_path(path)
            if not subkey:
                return "registry_path 缺少子键"
            vtype = _VTYPE_MAP.get((a.get("value_type") or "REG_SZ").upper(), "string")
            ops = [{
                "action": "set", "root": root, "subkey": subkey,
                "name": a.get("value_name") or "",
                "value": "" if a.get("value_data") is None else str(a.get("value_data")),
                "type": vtype,
            }]
        else:
            ops = []
            for ch in changes:
                cp = (ch.get("path") or "").strip().strip("\\")
                hive = (ch.get("hive") or "HKLM").strip()
                root, subkey = _split_registry_path(f"{hive}\\{cp}" if cp else hive)
                if not subkey:
                    return f"changes 中某项的 path 缺少子键：{ch.get('path')}"
                vtype = _VTYPE_MAP.get((ch.get("type") or "REG_SZ").upper(), "string")
                raw = ch.get("data")
                val = "" if raw is None else (raw if isinstance(raw, int) else str(raw))
                act = (ch.get("action") or "set").lower()
                ops.append({
                    "action": act, "root": root, "subkey": subkey,
                    "name": ch.get("value") or ch.get("value_name") or "",
                    "value": "" if act == "delete" else val,
                    "type": vtype,
                })
        requires_reboot = bool(a.get("requires_reboot", False))
        agent_task = Task(
            name=f"漏洞修复 QID {finding.qid}（注册表）",
            task_type="registry", target_type="client",
            interactive=False, need_reboot=requires_reboot, timeout=300,
            success_codes=[0], status="active",
            registry_ops=ops, run_as="system",
        )
    elif task.fix_type == "software_uninstall":
        sw = a.get("software") or ""
        if not sw:
            return "action 缺少 software"
        agent_task = Task(
            name=f"漏洞修复 QID {finding.qid}（卸载 {sw}）",
            task_type="uninstall", uninstall_target=sw, target_type="client",
            interactive=False, need_reboot=False, timeout=1800,
            success_codes=[0], status="active", run_as="system",
        )
    elif task.fix_type == "software_upgrade":
        # 前置条件（门禁已校验 matched_package_id 非空）：复用现有 install 类型下发
        pkg_id = task.matched_package_id
        pkg = (await db.execute(
            select(Package).where(Package.id == pkg_id)
        )).scalar_one_or_none() if pkg_id else None
        if not pkg:
            return "关联的安装包不存在或已被删除，请重新匹配"
        sw = a.get("software") or ""
        agent_task = Task(
            name=f"漏洞修复 QID {finding.qid}（升级 {sw} → {pkg.version}）",
            task_type="install", package_id=pkg.id, target_type="client",
            interactive=False, need_reboot=False, timeout=1800,
            success_codes=[0, 3010], status="active", run_as="system",
        )
    elif task.fix_type == "patch_install":
        # 复用 run_command 通道：触发本机 Windows Update 安装，显式禁止自动重启
        kb_ids = a.get("kb_ids") or []
        script = _build_patch_install_script(kb_ids)
        # ── P0 安全：服务端扫描脚本内容，命中重启/关机关键词则拒绝下发 ──
        hit = _scan_reboot_blacklist(script)
        if hit:
            logger.error("修复任务 #%s 脚本内容命中禁止的重启/关机关键词: %s", task.id, hit)
            return f"SECURITY_BLOCKED: 脚本内容包含禁止的重启/关机操作（命中: {hit}）"
        agent_task = Task(
            name=f"漏洞修复 QID {finding.qid}（Windows Update 补丁安装）",
            task_type="run_command", command=script, interpreter="powershell",
            target_type="client",
            interactive=False, need_reboot=False, timeout=1800,
            success_codes=[0], status="active", run_as="system",
        )
    else:
        return f"fix_type={task.fix_type} 不支持自动下发"

    db.add(agent_task)
    await db.flush()   # 拿 agent_task.id
    db.add(TaskTarget(
        task_id=agent_task.id, client_id=task.asset_id,
        remediation_task_id=task.id, status="pending",
    ))
    logger.info("修复任务 #%s 已下发：%s → client #%s（agent task #%s）",
                task.id, task.fix_type, task.asset_id, agent_task.id)
    return None


async def _do_dispatch(db: AsyncSession, task: RemediationTask,
                       finding: VulnFinding, for_auto: bool) -> str | None:
    """
    门禁 + 下发。成功返回 None（task.status 已置 dispatched），失败返回原因（task 保持 approved）。

    前置检查：kill_switch（全局熔断）开启时，自动下发（for_auto=True）一律阻断，
    但不影响显式 dispatch_task（for_auto=False）。
    """
    # ── 全局熔断检查 ──
    if for_auto:
        from app.models.vuln import AutonomyPolicy
        pol = (await db.execute(
            select(AutonomyPolicy).where(AutonomyPolicy.id == 1)
        )).scalar_one_or_none()
        if pol and pol.kill_switch:
            return "全局熔断已开启（kill_switch=true），所有自动下发已暂停。需管理员在管理面手动关闭熔断后重试。"

    rule = await _find_rule(db, finding)
    reason = _gate_reason(task, rule, for_auto)
    if reason:
        return reason

    # 以当前 active 规则的模板为准（人工编辑后生效），description 沿用任务快照
    action = dict(rule.action_template or {})
    action.setdefault("description", (task.action_json or {}).get("description", ""))
    # ── 下发即定版：把实际生效的规则模板写入任务快照，
    #    供 _verify_registry_fix 比对实际下发值（避免规则被编辑后误判回滚）──
    task.action_json = dict(action)
    # ── 下发前快照：rollback_plan 从规则带入任务 ──
    if rule.rollback_plan:
        task.rollback_plan = dict(rule.rollback_plan)
    # ── 规则版本号 ──
    if rule.current_version_id:
        task.rule_version_id = rule.current_version_id

    reason = await _dispatch_to_agent(db, task, finding, action)
    if reason:
        return reason
    task.status = "dispatched"
    return None


async def _set_task_status(db, task_id: int, nxt: str, operator: str) -> RemediationTask:
    t = (await db.execute(
        select(RemediationTask).where(RemediationTask.id == task_id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "任务不存在")
    if not _can_transition(t.status, nxt):
        raise HTTPException(409, f"任务当前状态为 {t.status}，无法切换到 {nxt}")
    t.status = nxt
    t.approved_by = operator
    t.approved_at = datetime.now(timezone.utc)
    return t


@router.post("/tasks/{task_id}/approve", response_model=TaskDetailOut)
async def approve_task(
    task_id: int,
    body: ApproveRequest,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """
    批准任务。执行通道带两道闸：
      - 规则未转正（draft/无规则）→ 停在 approved，需先去 QID 规则库转正再「确认下发」
      - high 风险 → 停在 approved，需显式「确认下发」（POST /tasks/{id}/dispatch）
    两道闸都过（low/medium + active 规则）才随批准自动下发（→ dispatched）。
    """
    t = await _set_task_status(db, task_id, "approved", body.operator)
    block_reason = None
    if t.fix_type in AUTO_DISPATCH_FIX_TYPES:
        finding = (await db.execute(
            select(VulnFinding).where(VulnFinding.id == t.finding_id)
        )).scalar_one_or_none()
        if finding:
            block_reason = await _do_dispatch(db, t, finding, for_auto=True)
            if block_reason:
                logger.info("修复任务 #%s 批准但未自动下发：%s", t.id, block_reason)
    await db.commit()
    await db.refresh(t)
    out = await task_detail(task_id, db=db)
    out.dispatch_block_reason = block_reason
    return out


@router.post("/tasks/{task_id}/dispatch", response_model=TaskDetailOut)
async def dispatch_task(
    task_id: int,
    body: ApproveRequest,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """
    显式「确认下发」：approved → dispatched。
    适用于：批准时被闸住的任务（high 风险 或 规则当时未转正、现已转正）。
    规则闸仍然生效（必须 active）；high 风险在此视为已获得人工二次确认。
    """
    t = (await db.execute(
        select(RemediationTask).where(RemediationTask.id == task_id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "任务不存在")
    if t.status != "approved":
        raise HTTPException(409, f"任务当前状态为 {t.status}，仅「已批准」状态可确认下发")
    if t.fix_type not in AUTO_DISPATCH_FIX_TYPES:
        raise HTTPException(400, f"fix_type={t.fix_type} 不支持下发执行")

    finding = (await db.execute(
        select(VulnFinding).where(VulnFinding.id == t.finding_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "关联 finding 不存在")

    reason = await _do_dispatch(db, t, finding, for_auto=False)
    if reason:
        raise HTTPException(400, f"无法下发：{reason}")
    await db.commit()
    await db.refresh(t)
    logger.info("修复任务 #%s 经显式确认下发（operator=%s）", t.id, body.operator)
    return await task_detail(task_id, db=db)


@router.post("/tasks/{task_id}/rematch-package", response_model=TaskDetailOut)
async def rematch_package(
    task_id: int,
    body: ApproveRequest,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """
    重新匹配软件安装包（software_upgrade 专用）。
    软件部署库可能晚于任务生成才补充上传，故提供手动重跑匹配；
    匹配成功 → 写入 matched_package_id，下次批准/确认下发即可走 install 通道。
    """
    t = (await db.execute(
        select(RemediationTask).where(RemediationTask.id == task_id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "任务不存在")
    if t.fix_type != "software_upgrade":
        raise HTTPException(400, "仅 software_upgrade 类型支持重新匹配安装包")
    aj = t.action_json or {}
    sw = aj.get("software") or aj.get("download_hint") or ""
    tv = aj.get("target_version") or ""
    pkg = await match_package(db, sw, tv)
    t.matched_package_id = pkg.id if pkg else None
    await db.commit()
    await db.refresh(t)
    out = await task_detail(task_id, db=db)
    out.dispatch_block_reason = None if pkg else "仍未匹配到安装包，请先在软件部署库上传/关联对应安装包"
    return out


@router.post("/tasks/{task_id}/reject", response_model=TaskDetailOut)
async def reject_task(
    task_id: int,
    body: ApproveRequest,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    t = await _set_task_status(db, task_id, "rejected", body.operator)
    await db.commit()
    await db.refresh(t)
    return await task_detail(task_id, db=db)


@router.post("/tasks/{task_id}/mark-manual", response_model=TaskDetailOut)
async def mark_manual_task(
    task_id: int,
    body: ApproveRequest,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """标记已手动处理（管理员已线下处理，无需下发）。"""
    t = await _set_task_status(db, task_id, "needs_manual", body.operator)
    await db.commit()
    await db.refresh(t)
    return await task_detail(task_id, db=db)


@router.post("/tasks/batch-approve", response_model=dict)
async def batch_approve(
    body: BatchApproveRequest,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """
    批量批准：pending → approved；仅「low/medium 风险 + active 规则」的可执行类型
    随批准自动下发（→ dispatched）。high 风险与规则未转正的一律停在 approved 并
    列入 held（含原因），需逐条「确认下发」。
    """
    rows = (await db.execute(
        select(RemediationTask).where(RemediationTask.id.in_(body.task_ids))
    )).scalars().all()
    found = {r.id for r in rows}
    missing = [i for i in body.task_ids if i not in found]
    ok, skipped, dispatched, held = [], [], [], []
    now = datetime.now(timezone.utc)
    for t in rows:
        if not _can_transition(t.status, "approved"):
            skipped.append({"id": t.id, "status": t.status})
            continue
        t.status = "approved"
        t.approved_by = body.operator
        t.approved_at = now
        ok.append(t.id)
        # 执行通道：两道闸都过才随批准自动下发
        if t.fix_type in AUTO_DISPATCH_FIX_TYPES:
            finding = (await db.execute(
                select(VulnFinding).where(VulnFinding.id == t.finding_id)
            )).scalar_one_or_none()
            if finding:
                reason = await _do_dispatch(db, t, finding, for_auto=True)
                if reason is None:
                    dispatched.append(t.id)
                else:
                    held.append({"id": t.id, "reason": reason})
                    logger.info("修复任务 #%s 批准但未自动下发：%s", t.id, reason)
    await db.commit()
    msg = f"已批准 {len(ok)} 个任务（{len(dispatched)} 个已自动下发"
    if held:
        msg += f"，{len(held)} 个需人工确认后下发"
    msg += "）"
    return {"approved": ok, "dispatched": dispatched, "held": held,
            "skipped": skipped, "missing": missing, "message": msg}


# ── 规则库 ────────────────────────────────────────────────────────────────────
@router.get("/rules", response_model=list[RuleOut])
async def list_rules(
    status: str = "",
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    q = select(RemediationRule)
    if status:
        q = q.where(RemediationRule.status == status)
    rows = (await db.execute(q.order_by(RemediationRule.qid))).scalars().all()
    return [RuleOut.model_validate(r) for r in rows]


@router.post("/rules", response_model=RuleOut)
async def create_rule(
    body: RuleIn,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    if body.fix_type not in FIX_TYPES:
        raise HTTPException(400, "非法的 fix_type")
    if body.default_risk_level not in RISK_LEVELS:
        raise HTTPException(400, "非法的 default_risk_level")
    if body.status not in RULE_STATUSES:
        raise HTTPException(400, "非法的 status")
    exists = (await db.execute(
        select(RemediationRule.id).where(RemediationRule.qid == body.qid)
    )).scalar_one_or_none()
    if exists:
        raise HTTPException(409, f"QID {body.qid} 的规则已存在")
    # ── 新规则：直接创建，同时写入 rule_versions（version=1）──
    rule = RemediationRule(
        qid=body.qid, fix_type=body.fix_type,
        action_template=body.action_template,
        rollback_plan=body.rollback_plan,
        default_risk_level=body.default_risk_level,
        status=body.status, source="manual", notes=body.notes,
    )
    db.add(rule)
    await db.flush()

    from app.models.vuln import RuleVersion
    ver = RuleVersion(
        rule_id=rule.id, version=1,
        action_template=body.action_template,
        rollback_plan=body.rollback_plan,
        fix_type=body.fix_type,
        default_risk_level=body.default_risk_level,
        status=body.status, source="manual", notes=body.notes,
        approved_by="manual:creator" if body.status == "active" else None,
        deprecated=False,
    )
    db.add(ver)
    await db.flush()
    rule.current_version_id = ver.id
    await db.commit()
    await db.refresh(rule)
    return RuleOut.model_validate(rule)


@router.put("/rules/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: int,
    body: RuleUpdate,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    rule = (await db.execute(
        select(RemediationRule).where(RemediationRule.id == rule_id)
    )).scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "规则不存在")
    data = body.model_dump(exclude_unset=True)
    if "fix_type" in data and data["fix_type"] not in FIX_TYPES:
        raise HTTPException(400, "非法的 fix_type")
    if "default_risk_level" in data and data["default_risk_level"] not in RISK_LEVELS:
        raise HTTPException(400, "非法的 default_risk_level")
    if "status" in data and data["status"] not in RULE_STATUSES:
        raise HTTPException(400, "非法的 status")

    # ── 规则版本化：改规则时新开一条 version 记录，不覆盖原有内容 ──
    from app.models.vuln import RuleVersion
    # 1) 旧版本标 deprecated
    if rule.current_version_id:
        old_ver = (await db.execute(
            select(RuleVersion).where(RuleVersion.id == rule.current_version_id)
        )).scalar_one_or_none()
        if old_ver:
            old_ver.deprecated = True

    # 2) 计算新版本号
    max_ver = (await db.execute(
        select(func.coalesce(func.max(RuleVersion.version), 0))
        .where(RuleVersion.rule_id == rule_id)
    )).scalar_one() or 0
    new_version = max_ver + 1

    # 3) 先应用字段变更到主表
    for k, v in data.items():
        setattr(rule, k, v)

    # 4) 创建新 version 记录
    new_ver = RuleVersion(
        rule_id=rule.id, version=new_version,
        action_template=rule.action_template,
        rollback_plan=getattr(rule, 'rollback_plan', None),
        fix_type=rule.fix_type,
        default_risk_level=rule.default_risk_level,
        status=rule.status, source=rule.source, notes=rule.notes,
        deprecated=False,
    )
    db.add(new_ver)
    await db.flush()
    rule.current_version_id = new_ver.id
    await db.commit()
    await db.refresh(rule)
    return RuleOut.model_validate(rule)


@router.delete("/rules/{rule_id}", response_model=dict)
async def delete_rule(
    rule_id: int,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    rule = (await db.execute(
        select(RemediationRule).where(RemediationRule.id == rule_id)
    )).scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "规则不存在")
    await db.delete(rule)
    await db.commit()
    return {"ok": True, "message": f"规则 {rule.qid} 已删除"}


# ── 全局熔断开关（Kill Switch）────────────────────────────────────────────────
@router.get("/kill-switch", response_model=dict)
async def get_kill_switch(
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """查询当前熔断状态"""
    pol = (await db.execute(
        select(AutonomyPolicy).where(AutonomyPolicy.id == 1)
    )).scalar_one_or_none()
    if not pol:
        # 惰性初始化
        pol = AutonomyPolicy(kill_switch=False)
        db.add(pol)
        await db.commit()
        await db.refresh(pol)
    return {
        "kill_switch": pol.kill_switch,
        "updated_by": pol.updated_by,
        "updated_at": pol.updated_at.isoformat() if pol.updated_at else None,
    }


@router.post("/kill-switch/toggle", response_model=dict)
async def toggle_kill_switch(
    body: ApproveRequest,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """
    切换全局熔断开关。
    开启后：所有自动下发（for_auto=True）一律阻断，已下发的任务不受影响；
    人工显式确认下发（POST /tasks/{id}/dispatch）不受限制。
    """
    pol = (await db.execute(
        select(AutonomyPolicy).where(AutonomyPolicy.id == 1)
    )).scalar_one_or_none()
    if not pol:
        pol = AutonomyPolicy(kill_switch=False)
        db.add(pol)
        await db.flush()

    new_state = not pol.kill_switch
    pol.kill_switch = new_state
    pol.updated_by = body.operator
    pol.updated_at = datetime.now(timezone.utc)

    # ── 审计记录 ──
    from app.models.models import ActionAudit
    db.add(ActionAudit(
        hash_serial="system:kill_switch",
        process_path=f"kill_switch:{'ON' if new_state else 'OFF'}",
        arguments=f"operator={body.operator}",
        executed_at=datetime.now(timezone.utc),
        reported_at=datetime.now(timezone.utc),
    ))

    await db.commit()
    await db.refresh(pol)
    state_label = "已开启（自动下发暂停）" if new_state else "已关闭（自动下发恢复）"
    logger.warning("全局熔断开关 %s，操作者: %s", state_label, body.operator)
    return {
        "ok": True,
        "kill_switch": pol.kill_switch,
        "message": f"全局熔断 {state_label}",
    }
