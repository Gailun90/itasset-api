"""
自动金丝雀后台调度器

职责（唯一安全网，人工不再审批新规则能否生效的前提）：
  - 定期检查处于 in_progress 的金丝雀规则；
  - 观察窗口到点后，统计首批样本中的 rollback_required 占比；
  - 占比 <= rollback_threshold（默认 0）→ 自动放量（规则置 verified，排队任务自动全量下发）；
  - 占比 > threshold → 自动暂停规则（status=paused），排队任务转 needs_manual 等人工。

不依赖人工触发；与全局 kill_switch 互不冲突（熔断停的是下发，金丝雀停的是单条规则）。
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.vuln_engine import (
    evaluate_canary_outcome,
    resolve_autonomy_params,
    CANARY_STATUS_IN_PROGRESS,
    CANARY_STATUS_VERIFIED,
    CANARY_OUTCOME_RELEASE,
    CANARY_OUTCOME_PAUSE,
)
from app.models.vuln import RemediationRule, RemediationTask, AutonomyRule, VulnFinding

logger = logging.getLogger(__name__)

CHECK_INTERVAL_SECONDS = 60


async def _load_autonomy_rules(db) -> dict:
    """加载金丝雀分级参数表为 {(fix_type, risk_level): {...}} 字典。"""
    rows = (await db.execute(select(AutonomyRule))).scalars().all()
    out = {}
    for r in rows:
        out[(r.fix_type, r.risk_level)] = {
            "canary_batch_size": r.canary_batch_size,
            "canary_window_minutes": r.canary_window_minutes,
            "rollback_threshold": r.rollback_threshold,
        }
    return out


async def _group_first_batch(db, rule) -> dict:
    """把首批样本（canary_batch=True）按 dispatch_group_key 分组。"""
    batch = (await db.execute(
        select(RemediationTask).where(
            RemediationTask.rule_id == rule.id,
            RemediationTask.canary_batch.is_(True),
        )
    )).scalars().all()
    groups: dict = {}
    for t in batch:
        key = t.dispatch_group_key or ""
        groups.setdefault(key, []).append(t)
    return groups


async def _queued_for_group(db, rule, group_key) -> list:
    """某分组下排队等待放量的任务（canary_waiting）。"""
    return (await db.execute(
        select(RemediationTask).where(
            RemediationTask.rule_id == rule.id,
            RemediationTask.dispatch_group_key == group_key,
            RemediationTask.status == "canary_waiting",
        )
    )).scalars().all()


async def _release_group(db, rule, group_key):
    """某分组观察达标 → 放量：该组排队任务自动全量下发。"""
    # 延迟导入避免循环依赖（vuln.py 不导入本模块）
    from app.api.v1.vuln import _do_dispatch
    queued = await _queued_for_group(db, rule, group_key)
    released = 0
    for t in queued:
        # 重新走下发：此时规则已 verified，canary 分支跳过 → 全量下发
        t.status = "approved"
        finding = (await db.execute(
            select(VulnFinding).where(VulnFinding.id == t.finding_id)
        )).scalar_one_or_none()
        if not finding:
            continue
        reason = await _do_dispatch(db, t, finding, for_auto=True)
        if reason is None:
            released += 1
        else:
            logger.warning("金丝雀放量时任务 #%s 下发失败：%s", t.id, reason)
    logger.info("规则 #%s（QID %s）组 %s 金丝雀观察达标，自动放量 %s 个排队任务",
                rule.id, rule.qid, group_key, released)


async def _pause_group(db, rule, group_key):
    """某分组观察不达标 → 该组排队任务转 needs_manual 等人工。"""
    queued = await _queued_for_group(db, rule, group_key)
    for t in queued:
        t.status = "needs_manual"
    logger.warning("规则 #%s（QID %s）组 %s 金丝雀观察不达标，%s 个排队任务转人工",
                   rule.id, rule.qid, group_key, len(queued))


async def run_canary_scheduler():
    """后台定时循环：每 CHECK_INTERVAL_SECONDS 检查 in_progress 规则的观察窗口。

    最终形态·二精细化：首批样本按 dispatch_group_key（OU/role/维护窗口）分组，
    每组独立评估观察结果（同组同批）。任一分组不达标 → 暂停整条规则；
    通过的分组在规则临时置 verified 后自动放量，之后规则若曾失败则置 paused 等人工。
    """
    logger.info("自动金丝雀调度器启动")
    while True:
        try:
            await asyncio.sleep(CHECK_INTERVAL_SECONDS)
            async with AsyncSessionLocal() as db:
                autonomy = await _load_autonomy_rules(db)
                rules = (await db.execute(
                    select(RemediationRule).where(
                        RemediationRule.canary_status == CANARY_STATUS_IN_PROGRESS)
                )).scalars().all()
                for rule in rules:
                    if rule.canary_started_at is None:
                        continue
                    params = resolve_autonomy_params(
                        rule.fix_type, rule.default_risk_level, autonomy)
                    window = timedelta(minutes=params["canary_window_minutes"])
                    if datetime.now(timezone.utc) - rule.canary_started_at < window:
                        continue  # 窗口未到

                    groups = await _group_first_batch(db, rule)
                    if not groups:
                        continue

                    any_failed = False
                    release_groups = []
                    for gkey, batch in groups.items():
                        dispatched = len(batch)
                        rollback = sum(1 for t in batch if t.status == "rollback_required")
                        outcome = evaluate_canary_outcome(
                            dispatched, rollback, params["rollback_threshold"])
                        if outcome == CANARY_OUTCOME_RELEASE:
                            release_groups.append(gkey)
                        else:
                            any_failed = True
                            await _pause_group(db, rule, gkey)

                    # ── 放行通过的分组（临时置 verified 让 _do_dispatch 跳过金丝雀分支）──
                    if release_groups:
                        rule.canary_status = CANARY_STATUS_VERIFIED
                        for gkey in release_groups:
                            await _release_group(db, rule, gkey)

                    # ── 规则整体结论 ──
                    if any_failed:
                        rule.status = "paused"
                        logger.warning(
                            "规则 #%s（QID %s）有分组金丝雀观察不达标，已暂停整条规则",
                            rule.id, rule.qid)
                    else:
                        # 全部分组通过：规则恢复 active 全量下发
                        rule.status = "active"
                        logger.info(
                            "规则 #%s（QID %s）全部分组金丝雀观察达标，置 verified",
                            rule.id, rule.qid)
                    await db.commit()
        except asyncio.CancelledError:
            logger.info("自动金丝雀调度器被取消，退出")
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("自动金丝雀调度器单轮异常：%s", e)
            # 不退出循环，下一轮继续
