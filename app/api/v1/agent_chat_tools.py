# -*- coding: utf-8 -*-
"""Agent 对话引擎 — TOOL_DEFINITIONS 与 12 个执行工具（从 agent_chat.py 拆分）。

定时/触发类工具在 agent_chat_tasks.py；record_feedback 留在 agent_chat.py
（与反馈持久化 helpers 同模块，便于测试打桩）。
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

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_pending_tasks",
            "description": "查看待处理漏洞修复任务列表。可按风险等级、修复类型、状态过滤。",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["pending", "approved", "dispatched", "done", "failed", "all"],
                        "description": "任务状态过滤，默认 pending",
                        "default": "pending",
                    },
                    "risk_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "all"],
                        "description": "风险等级过滤",
                        "default": "all",
                    },
                    "fix_type": {
                        "type": "string",
                        "enum": ["registry_fix", "software_upgrade", "software_uninstall", "patch_install", "manual_review", "unsupported", "shell_exec", "all"],
                        "description": "修复类型过滤",
                        "default": "all",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回数量上限。0 或不传表示不限制（返回全部匹配任务）；传正整数则最多返回该数量。",
                        "default": 0,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shell_exec",
            "description": "对指定终端执行远程 Shell 命令。需要终端在线。命令通过 WebSocket 下发到 C# Agent 执行。",
            "parameters": {
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "integer",
                        "description": "终端 ID（Client.id）",
                    },
                    "command": {
                        "type": "string",
                        "description": "要执行的 Shell 命令（bat/powershell）",
                    },
                    "interpreter": {
                        "type": "string",
                        "enum": ["bat", "cmd", "powershell"],
                        "description": "命令解释器，默认 powershell",
                        "default": "powershell",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "超时秒数，默认 60",
                        "default": 60,
                    },
                },
                "required": ["client_id", "command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dispatch_task",
            "description": "将已批准的漏洞修复任务下发到终端执行。任务状态从 approved 变为 dispatched。",
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "integer",
                        "description": "修复任务 ID（RemediationTask.id）",
                    },
                    "client_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "目标终端 ID 列表（可选，默认下发到任务关联的所有终端）",
                    },
                },
                "required": ["task_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_client_status",
            "description": "查看终端在线状态。可搜索终端名称，返回在线/离线状态和最近上线时间。",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "搜索关键词（主机名/IP），为空返回全部",
                        "default": "",
                    },
                    "online_only": {
                        "type": "boolean",
                        "description": "仅返回在线终端",
                        "default": False,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回数量上限。0 或不传表示不限制（返回全部匹配终端）；传正整数则最多返回该数量。",
                        "default": 0,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_rule",
            "description": "创建或修改 QID 修复规则。如果指定 QID 的规则不存在则新建，已存在则更新。可设置修复类型、动作模板、风险等级、状态等。",
            "parameters": {
                "type": "object",
                "properties": {
                    "qid": {
                        "type": "string",
                        "description": "QID 编号",
                    },
                    "fix_type": {
                        "type": "string",
                        "enum": ["registry_fix", "software_upgrade", "software_uninstall", "patch_install", "manual_review", "unsupported", "shell_exec"],
                        "description": "修复类型",
                    },
                    "action_template": {
                        "type": "object",
                        "description": "修复动作模板（JSON），如 {\"changes\":[{\"root\":\"HKLM\",\"subkey\":\"SOFTWARE\\\\X\",\"name\":\"Y\",\"value\":\"Z\",\"type\":\"REG_SZ\",\"action\":\"set\"}]}",
                    },
                    "default_risk_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "默认风险等级",
                    },
                    "status": {
                        "type": "string",
                        "enum": ["active", "draft", "disabled", "paused"],
                        "description": "规则状态",
                    },
                    "notes": {
                        "type": "string",
                        "description": "备注",
                    },
                },
                "required": ["qid", "fix_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "manage_package",
            "description": "管理软件安装包：list=查看列表，associate=关联到修复任务，delete=删除安装包，update=修改包信息（名称/版本/静默参数/描述）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "associate", "delete", "update"],
                        "description": "操作类型",
                    },
                    "package_id": {
                        "type": "integer",
                        "description": "安装包 ID（associate/delete/update 时必填）",
                    },
                    "task_id": {
                        "type": "integer",
                        "description": "修复任务 ID（associate 时必填）",
                    },
                    "search": {
                        "type": "string",
                        "description": "搜索关键词（list 时可用）",
                        "default": "",
                    },
                    "name": {
                        "type": "string",
                        "description": "包名称（update 时可修改）",
                    },
                    "version": {
                        "type": "string",
                        "description": "包版本（update 时可修改）",
                    },
                    "silent_args": {
                        "type": "string",
                        "description": "静默安装参数（update 时可修改）",
                    },
                    "description": {
                        "type": "string",
                        "description": "包描述（update 时可修改）",
                    },
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "deploy_software",
            "description": "软件部署操作：向终端推送安装/卸载/命令/注册表/清理任务。支持指定单个终端、分组或全部终端。",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["install", "uninstall", "run_command", "registry", "cleanup"],
                        "description": "部署类型：install=安装软件，uninstall=卸载软件，run_command=执行命令，registry=注册表操作，cleanup=清理文件",
                    },
                    "name": {
                        "type": "string",
                        "description": "任务名称",
                    },
                    "package_id": {
                        "type": "integer",
                        "description": "安装包 ID（install 时必填）",
                    },
                    "uninstall_target": {
                        "type": "string",
                        "description": "要卸载的软件名称（uninstall 时必填）",
                    },
                    "command": {
                        "type": "string",
                        "description": "命令内容（run_command 时必填）",
                    },
                    "interpreter": {
                        "type": "string",
                        "enum": ["bat", "cmd", "powershell"],
                        "description": "命令解释器（run_command 时使用）",
                        "default": "powershell",
                    },
                    "client_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "目标终端 ID 列表",
                    },
                    "group_id": {
                        "type": "integer",
                        "description": "目标分组 ID（指定时部署到该分组所有终端）",
                    },
                    "target_all": {
                        "type": "boolean",
                        "description": "是否部署到所有终端",
                        "default": False,
                    },
                    "interactive": {
                        "type": "boolean",
                        "description": "是否允许用户交互（推迟等）",
                        "default": False,
                    },
                    "need_reboot": {
                        "type": "boolean",
                        "description": "是否需要重启",
                        "default": False,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "超时秒数",
                        "default": 600,
                    },
                },
                "required": ["action", "name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "schedule_task",
            "description": "创建定时或触发式任务。支持按终端上线触发或定时执行。",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "任务名称",
                    },
                    "task_type": {
                        "type": "string",
                        "enum": ["run_command", "registry", "cleanup", "install", "uninstall"],
                        "description": "任务类型",
                    },
                    "trigger_type": {
                        "type": "string",
                        "enum": ["online", "scheduled", "immediate"],
                        "description": "触发类型：online=终端上线时触发，scheduled=定时执行，immediate=立即执行",
                    },
                    "client_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "目标终端 ID 列表",
                    },
                    "command": {
                        "type": "string",
                        "description": "命令内容（run_command 时必填）",
                    },
                    "interpreter": {
                        "type": "string",
                        "enum": ["powershell", "cmd", "bat"],
                        "description": "命令解释器。PowerShell 语法（如 Remove-Item、Get-Process 等）必须选 powershell，"
                                        "否则终端会用 cmd 执行，报\"不是内部或外部命令\"直接失败。",
                        "default": "powershell",
                    },
                    "scheduled_at": {
                        "type": "string",
                        "description": "定时执行时间（ISO 8601 格式，scheduled 时必填）",
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["low", "normal", "high", "urgent"],
                        "description": "优先级",
                        "default": "normal",
                    },
                },
                "required": ["name", "task_type", "trigger_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_scheduled_tasks",
            "description": "查询所有还没触发完的定时/上线任务，包括每个任务当前关联的目标终端列表、命令、"
                            "解释器、优先级等完整信息。想回答'之前那个任务关联了哪些终端'，或者要修改/取消"
                            "某个任务之前，都必须先调用这个查一遍确认是哪一条，不要凭空猜 trigger_key。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_scheduled_task",
            "description": "修改一个还没触发的定时/上线任务。只会更新你传入的字段，没传的字段保持原样。"
                            "trigger_key 必须是 list_scheduled_tasks 返回的真实值。",
            "parameters": {
                "type": "object",
                "properties": {
                    "trigger_key": {"type": "string", "description": "要修改的任务 key（从 list_scheduled_tasks 获取）"},
                    "name": {"type": "string", "description": "任务名称"},
                    "command": {"type": "string", "description": "命令内容"},
                    "interpreter": {"type": "string", "enum": ["powershell", "cmd", "bat"], "description": "命令解释器"},
                    "priority": {"type": "string", "enum": ["low", "normal", "high", "urgent"]},
                    "client_ids": {"type": "array", "items": {"type": "integer"}, "description": "目标终端 ID 列表（会整体替换，不是追加）"},
                    "scheduled_at": {"type": "string", "description": "定时执行时间（ISO 8601，仅 scheduled 类型有意义）"},
                },
                "required": ["trigger_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cancel_scheduled_task",
            "description": "取消一个还没触发的定时/上线任务。trigger_key 必须是 list_scheduled_tasks 返回的真实值。",
            "parameters": {
                "type": "object",
                "properties": {
                    "trigger_key": {"type": "string", "description": "要取消的任务 key"},
                },
                "required": ["trigger_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": "只读数据库查询，覆盖没有专门工具的临时性信息需求（比如统计、多表关联查询）。"
                            "只能执行单条 SELECT 语句，数据库连接本身在只读事务里运行，任何写操作都会被数据库"
                            "引擎直接拒绝，不是靠你自觉。优先使用其它专门的工具（如 list_tasks/list_rules 等），"
                            "只有确实没有对应工具时才用这个。表名/字段名不确定时，可以先查 information_schema。",
            "parameters": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "单条 SELECT 语句，不要带分号"},
                },
                "required": ["sql"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_priority",
            "description": "调整任务优先级。影响调度器执行顺序。",
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "integer",
                        "description": "任务 ID",
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["low", "normal", "high", "urgent"],
                        "description": "新优先级",
                    },
                },
                "required": ["task_id", "priority"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "manage_task",
            "description": "对漏洞修复任务执行状态变更：approve（批准）、reject（拒绝）、cancel（取消/关闭）、delete（删除）。cancel 会将任务状态改为 rejected 并标记为已取消；delete 会彻底删除任务记录。",
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "integer",
                        "description": "修复任务 ID（RemediationTask.id）",
                    },
                    "action": {
                        "type": "string",
                        "enum": ["approve", "reject", "cancel", "delete"],
                        "description": "操作类型",
                    },
                    "reason": {
                        "type": "string",
                        "description": "操作原因（可选）",
                    },
                },
                "required": ["task_id", "action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_task",
            "description": "修改修复任务的动作内容。可更新 action_json（修复动作）、risk_level（风险等级）、fix_type（修复类型）。适用于需要调整修复方案的场景。",
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "integer",
                        "description": "修复任务 ID",
                    },
                    "action_json": {
                        "type": "object",
                        "description": "新的修复动作 JSON（如 {\"changes\":[{\"root\":\"HKLM\",\"subkey\":\"SOFTWARE\\\\X\",\"name\":\"Y\",\"value\":\"Z\",\"type\":\"REG_SZ\",\"action\":\"set\"}]}）",
                    },
                    "risk_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "新的风险等级",
                    },
                    "fix_type": {
                        "type": "string",
                        "enum": ["registry_fix", "software_upgrade", "software_uninstall", "patch_install", "manual_review", "unsupported", "shell_exec"],
                        "description": "新的修复类型",
                    },
                },
                "required": ["task_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_client_software",
            "description": "获取指定终端已安装的软件列表（直接从系统数据库读取，无需远程命令）。返回软件名称、版本、发布者、安装日期等信息。",
            "parameters": {
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "integer",
                        "description": "终端 ID",
                    },
                    "search": {
                        "type": "string",
                        "description": "搜索关键词（按软件名称/发布者过滤）",
                        "default": "",
                    },
                },
                "required": ["client_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_feedback",
            "description": "保存一条操作员的反馈/偏好/约束，供后续所有对话回合（跨会话）参考。"
                           "当你从用户处了解到一条应长期遵守的偏好、纠正或限制时使用，"
                           "例如“以后不要在终端执行 rm -rf”“默认只针对已引用终端操作”“审批弹窗不要内联样式”。"
                           "该工具仅做持久化记录，不执行任何生产变更，无需审批。",
            "parameters": {
                "type": "object",
                "properties": {
                    "feedback": {
                        "type": "string",
                        "description": "要记住的反馈内容（简洁陈述一条可执行的约束或偏好）",
                    },
                    "operator": {
                        "type": "string",
                        "description": "反馈来源操作员标识（可选，默认 unknown）",
                        "default": "unknown",
                    },
                },
                "required": ["feedback"],
            },
        },
    },
]


# ════════════════════════════════════════════════════════════════════════════
# 工具函数实现
# ════════════════════════════════════════════════════════════════════════════


async def tool_list_pending_tasks(
    db: AsyncSession,
    status: str = "pending",
    risk_level: str = "all",
    fix_type: str = "all",
    limit: int = 0,
) -> dict:
    """查看待处理漏洞修复任务"""
    q = (
        select(
            RemediationTask.id,
            RemediationTask.fix_type,
            RemediationTask.risk_level,
            RemediationTask.status,
            RemediationTask.action_json,
            VulnFinding.qid,
            VulnFinding.title,
            VulnFinding.ip,
            VulnFinding.dns_name,
            Client.hostname,
        )
        .join(VulnFinding, RemediationTask.finding_id == VulnFinding.id)
        .outerjoin(Client, RemediationTask.asset_id == Client.id)
    )
    if status != "all":
        q = q.where(RemediationTask.status == status)
    if risk_level != "all":
        q = q.where(RemediationTask.risk_level == risk_level)
    if fix_type != "all":
        q = q.where(RemediationTask.fix_type == fix_type)
    q = q.order_by(
        # high 优先, 然后按 id 排序
        RemediationTask.risk_level == "high",
        RemediationTask.id.desc(),
    )
    # limit <= 0 表示不限制（返回全部匹配任务）；仅当显式传入正整数时才截断
    if limit and limit > 0:
        q = q.limit(limit)

    rows = (await db.execute(q)).all()
    tasks = []
    for r in rows:
        aj = r[4] or {}
        summary = ""
        if r[1] == "registry_fix":
            changes = aj.get("changes", [])
            summary = f"修改注册表 {len(changes)} 项" if changes else "注册表修复"
        elif r[1] == "software_uninstall":
            summary = f"卸载 {aj.get('software', '未知软件')}"
        elif r[1] == "software_upgrade":
            summary = f"升级 {aj.get('software', '未知软件')}"
        elif r[1] == "patch_install":
            summary = "安装补丁"
        elif r[1] == "shell_exec":
            summary = f"执行命令: {aj.get('command', '')[:60]}"
        else:
            summary = str(aj)[:80]

        tasks.append({
            "id": r[0],
            "fix_type": r[1],
            "risk_level": r[2],
            "status": r[3],
            "qid": r[5],
            "title": (r[6] or "")[:100],
            "ip": r[7],
            "dns_name": r[8],
            "hostname": r[9],
            "action_summary": summary,
        })

    return {"tasks": tasks, "count": len(tasks)}


async def tool_shell_exec(
    db: AsyncSession,
    client_id: int,
    command: str,
    interpreter: str = "powershell",
    timeout: int = 60,
) -> dict:
    """对指定终端执行远程 Shell 命令（通过 Task+task_push 标准流程）"""
    # 查终端
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        return {"error": f"终端 ID {client_id} 不存在"}

    serial = client.hash_serial
    hostname = client.hostname

    # 检查在线
    if not ws_manager.is_online(serial):
        return {
            "error": f"终端 {hostname}（ID:{client_id}）当前离线",
            "hostname": hostname,
            "online": False,
        }

    # 创建 Task + TaskTarget（标准任务下发流程）
    task = Task(
        name=f"Agent Shell Exec: {hostname}",
        task_type="run_command",
        command=command,
        interpreter=interpreter,
        target_type="client",
        interactive=False,
        need_reboot=False,
        timeout=timeout,
        success_codes=[0],
        status="active",
        run_as="system",
    )
    db.add(task)
    await db.flush()

    tt = TaskTarget(
        task_id=task.id,
        client_id=client_id,
        status="pending",
    )
    db.add(tt)
    await db.commit()
    await db.refresh(tt)

    target_id = tt.id

    # 通过 WS 发送 task_push 通知（C# Agent 收到后会调 GET /api/tasks 拉取任务详情）
    ws_sent = await ws_manager.send(serial, {
        "type": "task_push",
        "task_name": task.name,
    })

    if not ws_sent:
        return {"error": f"WebSocket 推送失败（终端可能已断线）", "hostname": hostname}

    # 轮询等待 Agent 回报结果（最多 timeout+15 秒）
    deadline = time.time() + timeout + 15
    while time.time() < deadline:
        await asyncio.sleep(2)
        # 用独立 session 查询，避免当前 session 缓存看不到其他事务的提交
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as poll_db:
            res = await poll_db.execute(
                select(TaskTarget).where(TaskTarget.id == target_id)
            )
            tt_fresh = res.scalar_one_or_none()
            if tt_fresh and tt_fresh.status not in ("pending", "running"):
                return {
                    "task_id": task.id,
                    "target_id": target_id,
                    "hostname": hostname,
                    "status": tt_fresh.status,
                    "output": (tt_fresh.message or "")[:4000],
                    "executed_at": tt_fresh.executed_at.isoformat() if tt_fresh.executed_at else None,
                }

    return {
        "task_id": task.id,
        "target_id": target_id,
        "hostname": hostname,
        "status": "timeout",
        "output": f"命令执行超时（{timeout}秒），任务已下发但未收到回报",
    }


async def tool_get_client_software(
    db: AsyncSession,
    client_id: int,
    search: str = "",
) -> dict:
    """获取指定终端已安装的软件列表（从系统数据库读取，无需远程命令）"""
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        return {"error": f"终端 ID {client_id} 不存在"}

    # 查询最新的软件清单报告
    report_result = await db.execute(
        select(ClientReport)
        .where(ClientReport.client_id == client_id)
        .order_by(ClientReport.collected_at.desc())
        .limit(1)
    )
    report = report_result.scalar_one_or_none()
    if not report:
        return {
            "client_id": client_id,
            "hostname": client.hostname,
            "software": [],
            "count": 0,
            "message": "暂无软件清单数据（终端可能未上报过软件列表）",
        }

    software_list = report.software or []
    # 搜索过滤
    if search:
        search_lower = search.lower()
        software_list = [
            s for s in software_list
            if search_lower in (s.get("name", "") + " " + s.get("publisher", "")).lower()
        ]

    return {
        "client_id": client_id,
        "hostname": client.hostname,
        "software": software_list[:100],  # 限制返回数量
        "count": len(software_list),
        "total": len(report.software or []),
        "collected_at": report.collected_at.isoformat() if report.collected_at else None,
    }


async def tool_dispatch_task(
    db: AsyncSession,
    task_id: int,
    client_ids: list[int] = None,
) -> dict:
    """将已批准的修复任务下发到终端执行"""
    # 查找修复任务
    result = await db.execute(
        select(RemediationTask).where(RemediationTask.id == task_id)
    )
    rt = result.scalar_one_or_none()
    if not rt:
        return {"error": f"修复任务 #{task_id} 不存在"}

    if rt.status not in ("approved", "pending"):
        return {"error": f"修复任务 #{task_id} 当前状态为 {rt.status}，无法下发（需先批准）"}

    # 查找关联的 VulnFinding
    finding_result = await db.execute(
        select(VulnFinding).where(VulnFinding.id == rt.finding_id)
    )
    finding = finding_result.scalar_one_or_none()
    if not finding:
        return {"error": f"修复任务 #{task_id} 关联的漏洞条目不存在"}

    # 如果任务还是 pending，先批准
    if rt.status == "pending":
        rt.status = "approved"
        rt.approved_by = "agent"
        rt.approved_at = datetime.now(timezone.utc)
        await db.flush()

    # 调用 vuln.py 的 dispatch 逻辑
    from app.api.v1.vuln import _do_dispatch
    try:
        reason = await _do_dispatch(db, rt, finding, for_auto=False)
        if reason:
            return {"error": f"无法下发: {reason}", "task_id": task_id}
        await db.commit()
        return {
            "task_id": task_id,
            "status": "dispatched",
            "fix_type": rt.fix_type,
            "message": f"修复任务 #{task_id} 已下发到终端执行",
        }
    except Exception as e:
        logger.error(f"Agent dispatch task #{task_id} failed: {e}")
        return {"error": f"下发失败: {str(e)}"}


async def tool_get_client_status(
    db: AsyncSession,
    search: str = "",
    online_only: bool = False,
    limit: int = 0,
) -> dict:
    """查看终端在线状态"""
    q = select(Client).order_by(Client.hostname)
    if search:
        q = q.where(
            or_(
                Client.hostname.ilike(f"%{search}%"),
                Client.ip.ilike(f"%{search}%"),
            )
        )
    # 关闭数量限制：limit=0 或不传 → 返回全量（避免 LIMIT 0 变成空集）
    if limit and limit > 0:
        q = q.limit(limit)
    rows = (await db.execute(q)).scalars().all()

    clients = []
    online_count = 0
    for c in rows:
        is_online = ws_manager.is_online(c.hash_serial)
        if online_only and not is_online:
            continue
        if is_online:
            online_count += 1
        clients.append({
            "id": c.id,
            "hostname": c.hostname,
            "ip": c.ip,
            "os": c.os,
            "online": is_online,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            "group_id": c.group_id,
        })

    return {
        "clients": clients,
        "total": len(clients),
        "online_count": online_count,
    }


async def tool_update_rule(
    db: AsyncSession,
    qid: str,
    fix_type: str = None,
    action_template: dict = None,
    default_risk_level: str = None,
    status: str = None,
    notes: str = None,
) -> dict:
    """创建或修改 QID 修复规则（upsert：不存在则新建，已存在则更新）"""
    result = await db.execute(
        select(RemediationRule).where(RemediationRule.qid == qid)
    )
    rule = result.scalar_one_or_none()
    is_new = False

    if not rule:
        # 创建新规则
        if not fix_type:
            return {"error": f"创建新规则需要指定 fix_type"}
        rule = RemediationRule(
            qid=qid,
            fix_type=fix_type,
            default_risk_level=default_risk_level or "medium",
            status=status or "active",
            source="agent",
        )
        if action_template is not None:
            rule.action_template = action_template
        if notes is not None:
            rule.notes = notes
        db.add(rule)
        is_new = True
    else:
        # 更新已有规则
        if fix_type:
            rule.fix_type = fix_type
        if action_template is not None:
            rule.action_template = action_template
        if default_risk_level:
            rule.default_risk_level = default_risk_level
        if status:
            rule.status = status
        if notes is not None:
            rule.notes = notes

    await db.commit()
    await db.refresh(rule)
    return {
        "qid": qid,
        "rule_id": rule.id,
        "status": "created" if is_new else "updated",
        "fix_type": rule.fix_type,
        "risk_level": rule.default_risk_level,
        "rule_status": rule.status,
        "message": f"QID {qid} 规则已{'创建' if is_new else '更新'}",
    }


async def tool_manage_package(
    db: AsyncSession,
    action: str,
    package_id: int = None,
    task_id: int = None,
    search: str = "",
    name: str = None,
    version: str = None,
    silent_args: str = None,
    description: str = None,
) -> dict:
    """管理软件安装包"""
    if action == "list":
        q = select(Package).order_by(Package.name)
        if search:
            q = q.where(Package.name.ilike(f"%{search}%"))
        rows = (await db.execute(q.limit(50))).scalars().all()
        return {
            "packages": [
                {
                    "id": p.id,
                    "name": p.name,
                    "version": p.version,
                    "filename": p.filename,
                    "file_size": p.file_size,
                    "description": (p.description or "")[:100],
                }
                for p in rows
            ],
            "count": len(rows),
        }
    elif action == "associate":
        if not package_id or not task_id:
            return {"error": "associate 操作需要 package_id 和 task_id"}
        result = await db.execute(
            select(RemediationTask).where(RemediationTask.id == task_id)
        )
        rt = result.scalar_one_or_none()
        if not rt:
            return {"error": f"修复任务 #{task_id} 不存在"}
        rt.matched_package_id = package_id
        await db.commit()
        return {
            "task_id": task_id,
            "package_id": package_id,
            "status": "associated",
        }
    elif action == "delete":
        if not package_id:
            return {"error": "delete 操作需要 package_id"}
        result = await db.execute(select(Package).where(Package.id == package_id))
        pkg = result.scalar_one_or_none()
        if not pkg:
            return {"error": f"安装包 #{package_id} 不存在"}
        pkg_name = pkg.name
        pkg_filename = pkg.filename
        await db.delete(pkg)
        await db.commit()
        # 删除物理文件
        pkg_path = os.path.join(settings.PACKAGES_DIR, pkg_filename)
        if os.path.isfile(pkg_path):
            try:
                os.remove(pkg_path)
            except Exception as e:
                logger.warning(f"Failed to delete package file {pkg_filename}: {e}")
        return {"package_id": package_id, "status": "deleted", "message": f"安装包 '{pkg_name}' 已删除"}
    elif action == "update":
        if not package_id:
            return {"error": "update 操作需要 package_id"}
        result = await db.execute(select(Package).where(Package.id == package_id))
        pkg = result.scalar_one_or_none()
        if not pkg:
            return {"error": f"安装包 #{package_id} 不存在"}
        changed = []
        if name is not None:
            pkg.name = name
            changed.append("name")
        if version is not None:
            pkg.version = version
            changed.append("version")
        if silent_args is not None:
            pkg.silent_args = silent_args
            changed.append("silent_args")
        if description is not None:
            pkg.description = description
            changed.append("description")
        if not changed:
            return {"error": "未指定要修改的字段"}
        await db.commit()
        return {"package_id": package_id, "status": "updated", "changed_fields": changed}
    return {"error": f"未知操作: {action}"}


async def tool_deploy_software(
    db: AsyncSession,
    action: str,
    name: str,
    package_id: int = None,
    uninstall_target: str = None,
    command: str = None,
    interpreter: str = "powershell",
    client_ids: list[int] = None,
    group_id: int = None,
    target_all: bool = False,
    interactive: bool = False,
    need_reboot: bool = False,
    timeout: int = 600,
) -> dict:
    """软件部署：向终端推送安装/卸载/命令/注册表/清理任务"""
    # 参数校验
    if action == "install" and not package_id:
        return {"error": "install 操作需要 package_id"}
    if action == "uninstall" and not uninstall_target:
        return {"error": "uninstall 操作需要 uninstall_target"}
    if action == "run_command" and not command:
        return {"error": "run_command 操作需要 command"}

    # 解析目标终端
    target_type = "client"
    target_ids = client_ids or []

    if target_all:
        target_type = "all"
        target_ids = []
    elif group_id:
        target_type = "group"
        target_ids = [group_id]
    elif not target_ids:
        return {"error": "需要指定 client_ids、group_id 或 target_all=true"}

    # 创建 Task
    task = Task(
        name=name,
        task_type=action,
        uninstall_target=uninstall_target if action == "uninstall" else None,
        package_id=package_id if action == "install" else None,
        command=command if action == "run_command" else None,
        interpreter=interpreter if action == "run_command" else None,
        target_type=target_type,
        interactive=interactive,
        need_reboot=need_reboot,
        timeout=timeout,
        success_codes=[0],
        status="active",
        run_as="system",
    )
    db.add(task)
    await db.flush()

    # 解析实际 client_ids
    if target_type == "all":
        res = await db.execute(select(Client.id))
        actual_ids = [r[0] for r in res.all()]
    elif target_type == "group":
        res = await db.execute(select(Client.id).where(Client.group_id == group_id))
        actual_ids = [r[0] for r in res.all()]
    else:
        actual_ids = target_ids

    if not actual_ids:
        await db.delete(task)
        await db.commit()
        return {"error": "未找到目标终端"}

    for cid in actual_ids:
        db.add(TaskTarget(task_id=task.id, client_id=cid, status="pending"))

    await db.commit()

    return {
        "task_id": task.id,
        "action": action,
        "name": name,
        "target_count": len(actual_ids),
        "status": "created",
        "message": f"已创建{action}任务 '{name}' (#{task.id})，分发到 {len(actual_ids)} 个终端",
    }


async def tool_query_database(db: AsyncSession, sql: str, params: dict = None) -> dict:
    """
    只读数据库查询——覆盖没有专门工具的临时性信息需求。
    安全边界：在真正执行前用 `SET TRANSACTION READ ONLY` 把当前事务设成
    只读，这是 PostgreSQL 引擎自己强制的，不是靠正则/关键字黑名单猜——
    哪怕语句本身被拼接/绕过检测，Postgres 也会直接拒绝任何写操作。
    另外做的收紧：只允许单条 SELECT 语句、禁止分号叠加多条语句、结果行数上限 200、
    执行超时 10 秒，事务结束后强制 rollback（只读事务本来就没什么好 commit 的）。
    """
    stripped = sql.strip().rstrip(";").strip()
    if not stripped:
        return {"error": "SQL 不能为空"}
    if ";" in stripped:
        return {"error": "只允许单条语句，不能包含分号（防止语句叠加）"}
    first_word = stripped.split(None, 1)[0].lower() if stripped.split() else ""
    if first_word not in ("select", "with"):
        return {"error": "只允许 SELECT / WITH ... SELECT 查询语句"}

    try:
        await db.execute(text("SET LOCAL statement_timeout = '10s'"))
        await db.execute(text("SET TRANSACTION READ ONLY"))
        result = await db.execute(text(stripped), params or {})
        rows = result.mappings().all()
        truncated = len(rows) > 200
        rows = rows[:200]
        return {
            "row_count": len(rows),
            "truncated": truncated,
            "rows": [dict(r) for r in rows],
        }
    except Exception as e:
        return {"error": f"查询失败: {e}"}
    finally:
        await db.rollback()


async def tool_set_priority(
    db: AsyncSession,
    task_id: int,
    priority: str,
) -> dict:
    """调整任务优先级"""
    result = await db.execute(
        select(RemediationTask).where(RemediationTask.id == task_id)
    )
    rt = result.scalar_one_or_none()
    if not rt:
        # 查普通 Task
        result = await db.execute(select(Task).where(Task.id == task_id))
        t = result.scalar_one_or_none()
        if not t:
            return {"error": f"任务 #{task_id} 不存在"}
        # Task 没有直接的 priority 字段，用 maintenance_window 存
        t.maintenance_window = {"priority": priority}
        await db.commit()
        return {"task_id": task_id, "priority": priority, "type": "task"}

    # RemediationTask: 用 risk_level 模拟优先级
    risk_map = {"low": "low", "normal": "medium", "high": "high", "urgent": "high"}
    rt.risk_level = risk_map.get(priority, "medium")
    await db.commit()
    return {"task_id": task_id, "priority": priority, "risk_level": rt.risk_level, "type": "remediation"}


async def tool_manage_task(
    db: AsyncSession,
    task_id: int,
    action: str,
    reason: str = "",
) -> dict:
    """对漏洞修复任务执行状态变更：approve/reject/cancel/delete"""
    result = await db.execute(
        select(RemediationTask).where(RemediationTask.id == task_id)
    )
    rt = result.scalar_one_or_none()
    if not rt:
        return {"error": f"修复任务 #{task_id} 不存在"}

    if action == "approve":
        if rt.status not in ("pending", "rejected"):
            return {"error": f"任务 #{task_id} 当前状态为 {rt.status}，仅 pending/rejected 可批准"}
        rt.status = "approved"
        rt.approved_by = "agent"
        rt.approved_at = datetime.now(timezone.utc)
        await db.commit()
        return {"task_id": task_id, "status": "approved", "message": f"任务 #{task_id} 已批准"}

    elif action == "reject":
        if rt.status in ("done", "failed", "rejected"):
            return {"error": f"任务 #{task_id} 当前状态为 {rt.status}，无法拒绝"}
        rt.status = "rejected"
        rt.result_log = (rt.result_log or "") + f"\n[Agent 拒绝] {reason}"
        await db.commit()
        return {"task_id": task_id, "status": "rejected", "message": f"任务 #{task_id} 已拒绝"}

    elif action == "cancel":
        # 取消 = 关闭任务，改为 rejected 并标记
        if rt.status in ("done", "rejected"):
            return {"error": f"任务 #{task_id} 当前状态为 {rt.status}，无需取消"}
        rt.status = "rejected"
        rt.result_log = (rt.result_log or "") + f"\n[Agent 取消] {reason}"
        await db.commit()
        return {"task_id": task_id, "status": "cancelled", "message": f"任务 #{task_id} 已取消/关闭"}

    elif action == "delete":
        # 彻底删除任务
        await db.delete(rt)
        await db.commit()
        return {"task_id": task_id, "status": "deleted", "message": f"任务 #{task_id} 已删除"}

    return {"error": f"未知操作: {action}"}


async def tool_update_task(
    db: AsyncSession,
    task_id: int,
    action_json: dict = None,
    risk_level: str = None,
    fix_type: str = None,
) -> dict:
    """修改修复任务的动作内容"""
    result = await db.execute(
        select(RemediationTask).where(RemediationTask.id == task_id)
    )
    rt = result.scalar_one_or_none()
    if not rt:
        return {"error": f"修复任务 #{task_id} 不存在"}

    # 只允许在 pending/approved 状态下修改
    if rt.status not in ("pending", "approved"):
        return {"error": f"任务 #{task_id} 当前状态为 {rt.status}，仅 pending/approved 可修改"}

    changed = []
    if action_json is not None:
        rt.action_json = action_json
        changed.append("action_json")
    if risk_level:
        rt.risk_level = risk_level
        changed.append("risk_level")
    if fix_type:
        rt.fix_type = fix_type
        changed.append("fix_type")

    if not changed:
        return {"error": "未指定要修改的字段"}

    await db.commit()
    return {
        "task_id": task_id,
        "status": "updated",
        "changed_fields": changed,
        "fix_type": rt.fix_type,
        "risk_level": rt.risk_level,
    }
