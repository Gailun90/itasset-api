# -*- coding: utf-8 -*-
"""Agent 对话引擎 — 定时/上线触发任务 + 后台调度器（从 agent_chat.py 拆分）。

仅依赖 app 包与惰性 `app.api.v1.vuln._do_dispatch`，不反向依赖 agent_chat.py。
"""
import asyncio
import json
import hashlib
import logging
import os
import time
import shutil
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from sqlalchemy import select, func, update, delete as sqldelete, text, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, Base
from app.core.config import get_settings
from app.core.ws_manager import ws_manager
from app.models.models import Client, Task, TaskTarget, Package, Group, ClientReport
from app.models.vuln import (
    VulnFinding, RemediationTask, RemediationRule,
    TASK_STATUSES, FIX_TYPES, RISK_LEVELS,
)
from app.services.settings_service import get_ai_settings

settings = get_settings()
logger = logging.getLogger(__name__)

PRIORITY_ORDER = {
    "registry_fix": 1,
    "cleanup": 2,
    "software_uninstall": 3,
    "patch_install": 4,
    "software_upgrade": 5,
    "shell_exec": 6,
    "manual_review": 99,
    "unsupported": 100,
}


async def _consume_online_triggers(client_id: int, serial: str, db: AsyncSession) -> int:
    """
    消费 schedule_task(trigger_type="online") 写入的 agent.trigger.online.* 触发规则。

    此前这个函数完整存在过，但在后续的并行改动里被整段删掉了，导致 AI 告诉用户
    "终端上线时将自动触发"，实际上这个 SystemSetting 记录从写入那一刻起就没有任何
    代码会去读它——包括 2026-08-01 那次让 AI 安排的"终端上线清理恶意 BAT 文件"任务
    （agent.trigger.online.2d525d77，覆盖 6 台终端），两天过去了，这几台机器只要
    上线过就应该被清理，但因为这个函数不存在，一次都没有真正执行过。

    终端连接时调用：匹配 client_ids 命中该终端的规则，创建 Task 并下发，
    一次性触发后从触发规则的 client_ids 里移除自身；全部命中完后删除整条记录。
    """
    from app.models.models import SystemSetting
    result = await db.execute(
        select(SystemSetting).where(SystemSetting.key.like("agent.trigger.online.%"))
    )
    triggers = result.scalars().all()
    if not triggers:
        return 0

    fired = 0
    for trigger in triggers:
        try:
            data = json.loads(trigger.value) if trigger.value else None
            if not data:
                await db.execute(sqldelete(SystemSetting).where(SystemSetting.key == trigger.key))
                continue
            target_ids = data.get("client_ids") or []
            if client_id not in target_ids:
                continue

            task = Task(
                name=data.get("name", "在线触发任务"),
                task_type=data.get("task_type", "run_command"),
                command=data.get("command"),
                interpreter=data.get("interpreter", "powershell"),
                target_type="client",
                interactive=False,
                need_reboot=False,
                timeout=600,
                success_codes=[0],
                status="active",
                run_as="system",
            )
            db.add(task)
            await db.flush()
            db.add(TaskTarget(task_id=task.id, client_id=client_id, status="pending"))

            remaining = [cid for cid in target_ids if cid != client_id]
            if remaining:
                data["client_ids"] = remaining
                trigger.value = json.dumps(data)
            else:
                await db.execute(sqldelete(SystemSetting).where(SystemSetting.key == trigger.key))

            fired += 1
            logger.info(f"Online trigger fired: {data.get('name')} → client {serial}")
        except Exception as e:
            logger.error(f"Online trigger consume error (trigger {trigger.key}): {e}", exc_info=True)
            await db.rollback()
            continue

    if fired:
        await db.commit()
    return fired


async def check_and_dispatch_on_connect(serial: str, client_id: int, db: AsyncSession):
    """
    Phase 2: 终端上线触发 — Agent WS 连接时检查该终端是否有 pending vuln tasks → 自动 dispatch
    由 websocket.py 在 Agent 连接时调用。
    """
    # 先消费该终端命中的"上线触发"自定义任务（schedule_task online）——
    # 这一步此前在并行改动里被整段删掉了，现在补回来
    await _consume_online_triggers(client_id, serial, db)

    # 查找该终端的 approved 修复任务
    result = await db.execute(
        select(RemediationTask)
        .where(
            and_(
                RemediationTask.asset_id == client_id,
                RemediationTask.status.in_(["approved"]),
            )
        )
        .order_by(RemediationTask.risk_level.desc())
    )
    tasks = result.scalars().all()

    if not tasks:
        return {"dispatched": 0, "message": "无待下发任务"}

    # 按优先级排序
    tasks_sorted = sorted(tasks, key=lambda t: PRIORITY_ORDER.get(t.fix_type, 99))

    dispatched = 0
    for rt in tasks_sorted[:5]:  # 每次最多下发 5 个
        try:
            # 查找关联的 finding
            finding_result = await db.execute(
                select(VulnFinding).where(VulnFinding.id == rt.finding_id)
            )
            finding = finding_result.scalar_one_or_none()
            if not finding:
                continue

            from app.api.v1.vuln import _do_dispatch
            reason = await _do_dispatch(db, rt, finding, for_auto=True)
            if not reason:
                dispatched += 1
                logger.info(f"Auto-dispatched remediation task #{rt.id} on client {serial} connect")
            else:
                logger.info(f"Auto-dispatch task #{rt.id} blocked: {reason}")
        except Exception as e:
            logger.error(f"Auto-dispatch task #{rt.id} failed: {e}")

    await db.commit()
    return {"dispatched": dispatched, "total_pending": len(tasks)}


async def run_agent_scheduler():
    """
    Phase 2: 定时扫描 — 每 10 分钟扫描在线终端 + pending tasks → 按优先级排序 → 逐步 dispatch
    在 main.py lifespan 中启动。

    修复：此前是"先 sleep 600 秒再检查"，也就是说服务每重启一次，这个 10 分钟倒计时
    就重新清零一次。今天为了让各种改动生效重启了很多次 itasset-api，导致这个循环
    很可能一次都没真正跑到检查这一步。改成"先检查、再 sleep"，服务重启后至少能
    立刻做一次扫描，不用等一个完整的 10 分钟窗口。
    """
    first_run = True
    while True:
        try:
            if first_run:
                first_run = False
            else:
                await asyncio.sleep(600)  # 10 分钟
            logger.info("Agent scheduler: running periodic scan...")

            from app.core.database import AsyncSessionLocal
            async with AsyncSessionLocal() as db:
                # 查找所有 approved 状态的修复任务
                result = await db.execute(
                    select(RemediationTask).where(
                        RemediationTask.status == "approved"
                    )
                )
                all_tasks = result.scalars().all()

                # 按优先级排序
                tasks_sorted = sorted(
                    all_tasks,
                    key=lambda t: (
                        PRIORITY_ORDER.get(t.fix_type, 99),
                        # high 风险优先
                        {"high": 0, "medium": 1, "low": 2}.get(t.risk_level, 1),
                    ),
                )

                dispatched = 0
                for rt in tasks_sorted:
                    # 检查终端是否在线
                    client_result = await db.execute(
                        select(Client).where(Client.id == rt.asset_id)
                    )
                    client = client_result.scalar_one_or_none()
                    if not client:
                        continue

                    if not ws_manager.is_online(client.hash_serial):
                        continue  # 离线，跳过

                    try:
                        # 查找关联的 finding
                        finding_result = await db.execute(
                            select(VulnFinding).where(VulnFinding.id == rt.finding_id)
                        )
                        finding = finding_result.scalar_one_or_none()
                        if not finding:
                            continue

                        from app.api.v1.vuln import _do_dispatch
                        reason = await _do_dispatch(db, rt, finding, for_auto=True)
                        if not reason:
                            dispatched += 1
                            logger.info(f"Scheduled dispatch: task #{rt.id} → client {client.hostname}")
                        else:
                            logger.info(f"Scheduled dispatch task #{rt.id} blocked: {reason}")
                    except Exception as e:
                        logger.error(f"Scheduled dispatch task #{rt.id} failed: {e}")

                if dispatched:
                    logger.info(f"Agent scheduler: dispatched {dispatched} tasks")

                # 检查定时触发任务
                await _check_scheduled_triggers(db)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Agent scheduler error: {e}", exc_info=True)


async def _check_scheduled_triggers(db: AsyncSession):
    """检查定时触发任务是否到期"""
    from app.models.models import SystemSetting
    result = await db.execute(
        select(SystemSetting).where(
            SystemSetting.key.like("agent.trigger.scheduled.%")
        )
    )
    triggers = result.scalars().all()

    now = datetime.now(timezone.utc)
    for trigger in triggers:
        try:
            data = json.loads(trigger.value)
            scheduled_at = datetime.fromisoformat(data["scheduled_at"].replace("Z", "+00:00"))
            if scheduled_at > now:
                continue

            # 到期，执行任务
            client_ids = data.get("client_ids", [])
            task = Task(
                name=data["name"],
                task_type=data["task_type"],
                command=data.get("command"),
                interpreter=data.get("interpreter", "powershell"),
                target_type="client",
                interactive=False,
                need_reboot=False,
                timeout=600,
                success_codes=[0],
                status="active",
                run_as="system",
            )
            db.add(task)
            await db.flush()
            for cid in client_ids:
                db.add(TaskTarget(task_id=task.id, client_id=cid, status="pending"))

            # 修复：SystemSetting 的主键是 key，不是 id（模型里根本没有 id 这个属性）。
            # 此前这里写的是 SystemSetting.id == trigger.id，一执行就抛
            # AttributeError（Python 级别的错误，SQL 都发不出去），被下面的
            # except 兜住但从未 db.rollback()，导致前面刚创建好、已经 flush
            # 但还没 commit 的 Task/TaskTarget，随着这个函数所在的
            # `async with AsyncSessionLocal() as db:` 正常退出而被隐式回滚——
            # 也就是说，每一次定时触发任务到期，都会在"看起来已经创建成功"之后，
            # 静默地整个消失，数据库里什么都不会留下。这是"AI 设置的定时任务
            # 总是失效"的直接原因之一。
            await db.execute(
                sqldelete(SystemSetting).where(SystemSetting.key == trigger.key)
            )
            await db.commit()
            logger.info(f"Scheduled trigger fired: {data['name']}")

        except Exception as e:
            logger.error(f"Scheduled trigger error: {e}", exc_info=True)
            await db.rollback()


async def _get_agent_triggers(db: AsyncSession) -> list[dict]:
    """
    列出所有还没触发完的 AI 定时/上线任务（schedule_task 工具写入的
    agent.trigger.scheduled.* / agent.trigger.online.* 记录）。
    被 GET /api/agent/triggers 和 AI 工具 list_scheduled_tasks 共用，
    避免逻辑重复导致两边行为不一致。
    """
    from app.models.models import SystemSetting, Client

    result = await db.execute(
        select(SystemSetting).where(SystemSetting.key.like("agent.trigger.%"))
    )
    rows = result.scalars().all()

    all_client_ids: set[int] = set()
    parsed_rows = []
    for r in rows:
        try:
            data = json.loads(r.value) if r.value else {}
        except json.JSONDecodeError:
            data = {}
        cids = data.get("client_ids") or []
        all_client_ids.update(cids)
        parsed_rows.append((r, data, cids))

    hostnames: dict[int, str] = {}
    if all_client_ids:
        cres = await db.execute(
            select(Client.id, Client.hostname).where(Client.id.in_(all_client_ids))
        )
        hostnames = {cid: hn for cid, hn in cres.all()}

    triggers = []
    for r, data, cids in parsed_rows:
        trigger_type = "scheduled" if r.key.startswith("agent.trigger.scheduled.") else "online"
        triggers.append({
            "key": r.key,
            "trigger_type": trigger_type,
            "name": data.get("name", "(未命名)"),
            "task_type": data.get("task_type"),
            "command": data.get("command"),
            "interpreter": data.get("interpreter"),
            "priority": data.get("priority"),
            "scheduled_at": data.get("scheduled_at"),
            "created_at": data.get("created_at"),
            "target_clients": [
                {"id": cid, "hostname": hostnames.get(cid, f"#{cid}（终端已删除）")}
                for cid in cids
            ],
            "remaining_count": len(cids),
        })

    triggers.sort(key=lambda t: t.get("created_at") or "", reverse=True)
    return triggers


async def tool_schedule_task(
    db: AsyncSession,
    name: str,
    task_type: str,
    trigger_type: str,
    client_ids: list[int] = None,
    command: str = None,
    scheduled_at: str = None,
    priority: str = "normal",
    interpreter: str = "powershell",
) -> dict:
    """创建定时或触发式任务

    修复：此前无论 immediate/online/scheduled 三种触发方式，创建 Task 时都没有
    设置 interpreter 字段，客户端会用默认解释器（cmd）去跑命令——如果命令是
    PowerShell 语法（比如 Remove-Item），cmd 会直接报"不是内部或外部命令"，
    执行必然失败。跟 tool_shell_exec 保持一致，默认用 powershell。
    """
    if task_type == "run_command" and not command:
        return {"error": "run_command 任务需要 command 参数"}

    if trigger_type == "immediate":
        # 立即创建并下发
        task = Task(
            name=name,
            task_type=task_type,
            command=command,
            interpreter=interpreter,
            target_type="client",
            interactive=False,
            need_reboot=False,
            timeout=600,
            success_codes=[0],
            status="active",
            run_as="system",
        )
        db.add(task)
        await db.flush()
        for cid in (client_ids or []):
            db.add(TaskTarget(task_id=task.id, client_id=cid, status="pending"))
        await db.commit()
        return {
            "task_id": task.id,
            "status": "created_and_dispatched",
            "trigger": "immediate",
        }

    elif trigger_type == "online":
        # 终端上线触发：存入待触发队列
        # 使用 SystemSetting 存储触发规则
        from app.models.models import SystemSetting
        trigger_data = {
            "name": name,
            "task_type": task_type,
            "command": command,
            "interpreter": interpreter,
            "client_ids": client_ids or [],
            "priority": priority,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        key = f"agent.trigger.online.{secrets.token_hex(4)}"
        db.add(SystemSetting(
            key=key,
            value=json.dumps(trigger_data),
            updated_by="agent",
        ))
        await db.commit()
        return {
            "trigger_key": key,
            "status": "scheduled_online_trigger",
            "detail": "终端上线时将自动触发",
        }

    elif trigger_type == "scheduled":
        if not scheduled_at:
            return {"error": "scheduled 触发需要 scheduled_at 参数"}
        # 存储定时任务
        from app.models.models import SystemSetting
        trigger_data = {
            "name": name,
            "task_type": task_type,
            "command": command,
            "interpreter": interpreter,
            "client_ids": client_ids or [],
            "priority": priority,
            "scheduled_at": scheduled_at,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        key = f"agent.trigger.scheduled.{secrets.token_hex(4)}"
        db.add(SystemSetting(
            key=key,
            value=json.dumps(trigger_data),
            updated_by="agent",
        ))
        await db.commit()
        return {
            "trigger_key": key,
            "status": "scheduled",
            "scheduled_at": scheduled_at,
        }

    return {"error": f"未知触发类型: {trigger_type}"}


async def tool_list_scheduled_tasks(db: AsyncSession, **_) -> dict:
    """
    查询所有还没触发完的定时/上线任务，包括每个任务当前关联的目标终端列表。
    用来回答"我之前安排的 XXX 任务关联了哪些终端"这类问题，
    也是修改/取消前必须先查一遍、确认改的是哪一条的前置步骤。
    """
    triggers = await _get_agent_triggers(db)
    return {"count": len(triggers), "triggers": triggers}


async def tool_update_scheduled_task(
    db: AsyncSession,
    trigger_key: str,
    name: str = None,
    command: str = None,
    interpreter: str = None,
    priority: str = None,
    client_ids: list[int] = None,
    scheduled_at: str = None,
) -> dict:
    """修改一个还没触发的定时/上线任务（只更新传入的字段，其它保持不变）"""
    from app.models.models import SystemSetting

    if not trigger_key.startswith("agent.trigger."):
        return {"error": "非法的 trigger_key"}

    result = await db.execute(select(SystemSetting).where(SystemSetting.key == trigger_key))
    row = result.scalar_one_or_none()
    if not row:
        return {"error": f"未找到该任务（可能已经触发或被取消）: {trigger_key}"}

    try:
        data = json.loads(row.value) if row.value else {}
    except json.JSONDecodeError:
        data = {}

    updates = {
        "name": name, "command": command, "interpreter": interpreter,
        "priority": priority, "client_ids": client_ids, "scheduled_at": scheduled_at,
    }
    changed = {}
    for k, v in updates.items():
        if v is not None:
            data[k] = v
            changed[k] = v

    row.value = json.dumps(data, ensure_ascii=False)
    row.updated_by = "agent"
    await db.commit()
    return {"ok": True, "trigger_key": trigger_key, "changed": changed, "message": f"已更新：{data.get('name')}"}


async def tool_cancel_scheduled_task(db: AsyncSession, trigger_key: str) -> dict:
    """取消一个还没触发的定时/上线任务"""
    from app.models.models import SystemSetting

    if not trigger_key.startswith("agent.trigger."):
        return {"error": "非法的 trigger_key"}

    result = await db.execute(sqldelete(SystemSetting).where(SystemSetting.key == trigger_key))
    await db.commit()
    if result.rowcount == 0:
        return {"error": f"未找到该任务（可能已经触发或被取消）: {trigger_key}"}
    return {"ok": True, "message": f"已取消：{trigger_key}"}
