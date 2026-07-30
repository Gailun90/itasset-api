"""
Agent 对话引擎 — API 路由

Phase 1: Agent 对话框 + 工具调用（核心）
Phase 2: 定时/触发任务调度器
Phase 3: @ 引用 + Shell 定向执行
Phase 4: Agent 工作区（文件上传 + AI 分析 + 包推送）

所有端点前缀 /api/agent，统一 GLPI Bearer Token 鉴权（require_glpi_token）。
LLM 调用走 openclaw 网关（OpenAI 兼容 /v1/chat/completions），支持 function-calling。
"""
import asyncio
import json
import logging
import os
import time
import shutil
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import (
    APIRouter, Depends, HTTPException, UploadFile, File,
    Form, Query as FastQuery,
)
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, update, and_, or_, Text, String, Integer, Boolean, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, Base
from app.core.deps import require_glpi_token
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
router = APIRouter(prefix="/api/agent", tags=["agent-chat"])


# ════════════════════════════════════════════════════════════════════════════
# Agent 对话审计日志模型
# ════════════════════════════════════════════════════════════════════════════

class AgentConversationLog(Base):
    """AI Agent 对话审计日志（关联 GLPI 用户）"""
    __tablename__ = "agent_conversation_logs"

    id:            Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id:    Mapped[str]           = mapped_column(String(64), nullable=False, index=True)
    timestamp:     Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    operator:      Mapped[str]           = mapped_column(String(255), nullable=False, default="unknown")
    role:          Mapped[str]           = mapped_column(String(16), nullable=False)  # user / assistant / tool_call / tool_result / error
    content:       Mapped[Optional[str]] = mapped_column(Text)          # 消息内容或错误信息
    tool_name:     Mapped[Optional[str]] = mapped_column(String(64))    # 工具名称（tool_call/tool_result 时）
    tool_args:     Mapped[Optional[str]] = mapped_column(Text)          # 工具参数 JSON
    tool_result:   Mapped[Optional[str]] = mapped_column(Text)          # 工具执行结果 JSON
    ip_address:    Mapped[Optional[str]] = mapped_column(String(45))    # 调用者 IP

    __table_args__ = (
        Index("ix_agent_logs_session_time", "session_id", "timestamp"),
        Index("ix_agent_logs_operator", "operator"),
    )


async def _log_conversation(
    db: AsyncSession,
    session_id: str,
    operator: str,
    role: str,
    content: str = None,
    tool_name: str = None,
    tool_args: dict = None,
    tool_result: dict = None,
    ip_address: str = None,
):
    """写入一条 Agent 对话审计日志"""
    log = AgentConversationLog(
        session_id=session_id,
        operator=operator,
        role=role,
        content=content[:8000] if content else None,
        tool_name=tool_name,
        tool_args=json.dumps(tool_args, ensure_ascii=False, default=str)[:8000] if tool_args else None,
        tool_result=json.dumps(tool_result, ensure_ascii=False, default=str)[:8000] if tool_result else None,
        ip_address=ip_address,
    )
    db.add(log)
    await db.commit()

# ════════════════════════════════════════════════════════════════════════════
# System Prompt — 基础模板（可被 GLPI 配置 ai.openclaw_prompt 覆盖/追加）
# ════════════════════════════════════════════════════════════════════════════

BASE_SYSTEM_PROMPT = """你是企业终端安全运维 Agent，部署在 IT 资产管理系统中。你的职责是协助运维人员管理漏洞修复任务、远程执行终端命令、管理软件包和修复规则。

## 你的能力

1. **查看待处理漏洞任务**（list_pending_tasks）：查询 pending/approved 状态的漏洞修复任务，支持按风险等级、修复类型过滤
2. **对指定终端执行远程命令**（shell_exec）：通过 Agent WebSocket 通道向指定终端下发 shell 命令并等待结果
3. **下发修复任务**（dispatch_task）：将已批准的修复任务下发到终端执行
4. **查看终端在线状态**（get_client_status）：查询终端在线/离线状态、最近上线时间
5. **修改 QID 规则**（update_rule）：更新漏洞修复规则库中的 QID 修复策略
6. **上传/关联安装包**（manage_package）：管理软件安装包，关联到修复任务
7. **安排定时/触发任务**（schedule_task）：创建定时或触发式任务
8. **设置任务优先级**（set_priority）：调整任务优先级
9. **批准/拒绝/取消/删除任务**（manage_task）：对漏洞修复任务执行状态变更或删除
10. **修改任务动作**（update_task）：更新修复任务的动作内容（如注册表修改值、命令等）
11. **查看终端软件清单**（get_client_software）：直接从数据库获取终端已安装的软件列表（无需远程命令）

## 使用规则

- 使用 @ 引用特定终端/QID/分组，例如 "对 @CNCDW-001 执行 shell_exec ipconfig"
- 执行高危操作前（如删除文件、修改注册表）需确认
- shell_exec 仅限运维目的，禁止执行破坏性命令
- 回复用中文，简洁专业
- 工具调用后，用自然语言总结结果给用户
"""


async def _build_system_prompt(db: AsyncSession) -> str:
    """构建 System Prompt：基础模板 + GLPI 配置中的自定义 Prompt"""
    ai_cfg = await get_ai_settings(db)
    custom_prompt = ai_cfg.get("openclaw_prompt", "")
    if custom_prompt:
        return BASE_SYSTEM_PROMPT + "\n\n# 企业自定义指令\n" + custom_prompt
    return BASE_SYSTEM_PROMPT

# ════════════════════════════════════════════════════════════════════════════
# 工具定义（OpenAI function-calling 格式）
# ════════════════════════════════════════════════════════════════════════════

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
                        "description": "返回数量上限，默认 20",
                        "default": 20,
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
                        "description": "返回数量上限，默认 50",
                        "default": 50,
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
]


# ════════════════════════════════════════════════════════════════════════════
# 工具函数实现
# ════════════════════════════════════════════════════════════════════════════

async def tool_list_pending_tasks(
    db: AsyncSession,
    status: str = "pending",
    risk_level: str = "all",
    fix_type: str = "all",
    limit: int = 20,
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
    ).limit(limit)

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
    limit: int = 50,
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


async def tool_schedule_task(
    db: AsyncSession,
    name: str,
    task_type: str,
    trigger_type: str,
    client_ids: list[int] = None,
    command: str = None,
    scheduled_at: str = None,
    priority: str = "normal",
) -> dict:
    """创建定时或触发式任务"""
    if task_type == "run_command" and not command:
        return {"error": "run_command 任务需要 command 参数"}

    if trigger_type == "immediate":
        # 立即创建并下发
        task = Task(
            name=name,
            task_type=task_type,
            command=command,
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


# 工具函数映射
TOOL_FUNCTIONS = {
    "list_pending_tasks": tool_list_pending_tasks,
    "shell_exec": tool_shell_exec,
    "dispatch_task": tool_dispatch_task,
    "get_client_status": tool_get_client_status,
    "update_rule": tool_update_rule,
    "manage_package": tool_manage_package,
    "schedule_task": tool_schedule_task,
    "set_priority": tool_set_priority,
    "manage_task": tool_manage_task,
    "update_task": tool_update_task,
    "deploy_software": tool_deploy_software,
    "get_client_software": tool_get_client_software,
}


# ════════════════════════════════════════════════════════════════════════════
# Phase 1: POST /api/agent/chat — Agent 对话 + 工具调用（流式 SSE）
# ════════════════════════════════════════════════════════════════════════════

@router.post("/chat")
async def agent_chat(
    body: dict,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """
    Agent 对话端点：接收消息 + 对话历史，调 LLM with tool-calling。
    返回 SSE 流（Server-Sent Events），前端逐 token 渲染。

    请求体:
    {
        "message": "用户消息",
        "history": [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}],
        "references": [{"type": "client", "id": 1, "name": "CNCDW-001"}]
    }
    """
    message = body.get("message", "").strip()
    history = body.get("history", [])
    references = body.get("references", [])
    operator = body.get("operator", "unknown")
    client_ip = body.get("client_ip", "")

    if not message:
        raise HTTPException(400, "消息不能为空")

    # 生成会话 ID（同一次对话的所有消息共享一个 session_id）
    import uuid as _uuid
    session_id = str(_uuid.uuid4())

    # 记录用户消息
    await _log_conversation(db, session_id, operator, "user", content=message, ip_address=client_ip)

    # 获取 AI 配置
    ai_cfg = await get_ai_settings(db)
    if not ai_cfg["llm_enabled"]:
        raise HTTPException(503, "LLM 功能未启用")
    if not ai_cfg["openclaw_token"]:
        raise HTTPException(503, "未配置 LLM Token")

    # 构建引用上下文
    ref_context = ""
    if references:
        ref_lines = []
        for ref in references:
            ref_lines.append(f"  - @{ref['name']} (type={ref['type']}, id={ref['id']})")
        ref_context = "\n\n## 当前引用的资产/对象\n" + "\n".join(ref_lines)

    # 构建消息列表（System Prompt 从 GLPI 配置动态加载）
    system_prompt = await _build_system_prompt(db)
    messages = [{"role": "system", "content": system_prompt + ref_context}]
    for msg in history[-10:]:  # 最多保留最近 10 条历史
        if msg.get("role") in ("user", "assistant") and msg.get("content"):
            messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": message})

    async def event_stream():
        """SSE 流式响应"""
        try:
            max_tool_rounds = 5  # 最多 5 轮工具调用
            current_messages = list(messages)

            for round_idx in range(max_tool_rounds):
                # 调用 LLM
                async with httpx.AsyncClient(timeout=ai_cfg["openclaw_timeout"]) as client:
                    resp = await client.post(
                        f"{ai_cfg['openclaw_url'].rstrip('/')}/chat/completions",
                        headers={"Authorization": f"Bearer {ai_cfg['openclaw_token']}"},
                        json={
                            "model": ai_cfg["openclaw_model"],
                            "messages": current_messages,
                            "tools": TOOL_DEFINITIONS,
                            "tool_choice": "auto",
                            "stream": False,
                            "max_tokens": 4096,
                        },
                    )

                if resp.status_code != 200:
                    error_text = resp.text[:500]
                    yield _sse({"type": "error", "content": f"LLM 调用失败 (HTTP {resp.status_code}): {error_text}"})
                    return

                data = resp.json()
                choice = data.get("choices", [{}])[0]
                msg = choice.get("message", {})

                # 如果 LLM 调用了工具
                tool_calls = msg.get("tool_calls", [])
                # DeepSeek thinking 模式：必须把 reasoning_content 传回 API
                reasoning_content = msg.get("reasoning_content")
                if tool_calls:
                    # 发送工具调用信息到前端
                    for tc in tool_calls:
                        fn = tc.get("function", {})
                        tool_name = fn.get("name", "")
                        tool_args_str = fn.get("arguments", "{}")
                        try:
                            tool_args = json.loads(tool_args_str)
                        except json.JSONDecodeError:
                            tool_args = {}

                        yield _sse({
                            "type": "tool_call",
                            "tool_name": tool_name,
                            "arguments": tool_args,
                        })

                        # 审计日志：记录工具调用
                        await _log_conversation(db, session_id, operator, "tool_call",
                            tool_name=tool_name, tool_args=tool_args, ip_address=client_ip)

                        # 构建带 reasoning_content 的 assistant 消息（DeepSeek thinking 模式要求）
                        assistant_msg = {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": tc.get("id", f"call_{round_idx}"),
                                    "type": "function",
                                    "function": {
                                        "name": tool_name,
                                        "arguments": tool_args_str,
                                    },
                                }
                            ],
                        }
                        if reasoning_content:
                            assistant_msg["reasoning_content"] = reasoning_content

                        # 执行工具
                        tool_fn = TOOL_FUNCTIONS.get(tool_name)
                        if tool_fn:
                            try:
                                tool_result = await tool_fn(db=db, **tool_args)
                                yield _sse({
                                    "type": "tool_result",
                                    "tool_name": tool_name,
                                    "result": tool_result,
                                })
                                # 审计日志：记录工具执行结果
                                await _log_conversation(db, session_id, operator, "tool_result",
                                    tool_name=tool_name, tool_result=tool_result, ip_address=client_ip)
                                # 把工具结果加入消息历史
                                current_messages.append(assistant_msg)
                                current_messages.append({
                                    "role": "tool",
                                    "tool_call_id": tc.get("id", f"call_{round_idx}"),
                                    "content": json.dumps(tool_result, ensure_ascii=False, default=str),
                                })
                            except Exception as e:
                                logger.error(f"Tool {tool_name} execution error: {e}")
                                yield _sse({
                                    "type": "tool_result",
                                    "tool_name": tool_name,
                                    "result": {"error": str(e)},
                                })
                                current_messages.append(assistant_msg)
                                current_messages.append({
                                    "role": "tool",
                                    "tool_call_id": tc.get("id", f"call_{round_idx}"),
                                    "content": json.dumps({"error": str(e)}),
                                })
                        else:
                            yield _sse({
                                "type": "tool_result",
                                "tool_name": tool_name,
                                "result": {"error": f"未知工具: {tool_name}"},
                            })
                    # 继续下一轮 LLM 调用（LLM 会基于工具结果生成回复）
                    continue

                else:
                    # LLM 没有调用工具，直接返回文本
                    content = msg.get("content", "")
                    if content:
                        yield _sse({"type": "content", "content": content})
                        # 审计日志：记录 AI 回复
                        await _log_conversation(db, session_id, operator, "assistant",
                            content=content, ip_address=client_ip)
                    yield _sse({"type": "done"})
                    return

            # 超过最大工具轮次
            yield _sse({"type": "content", "content": "（已达到最大工具调用轮次，停止处理）"})
            yield _sse({"type": "done"})

        except Exception as e:
            logger.error(f"Agent chat stream error: {e}", exc_info=True)
            # 审计日志：记录错误
            await _log_conversation(db, session_id, operator, "error",
                content=str(e), ip_address=client_ip)
            yield _sse({"type": "error", "content": f"内部错误: {str(e)}"})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ════════════════════════════════════════════════════════════════════════════
# Agent 对话审计日志查询：GET /api/agent/logs
# ════════════════════════════════════════════════════════════════════════════

@router.get("/logs")
async def get_agent_logs(
    session_id: str = FastQuery("", description="按会话 ID 过滤"),
    operator: str = FastQuery("", description="按操作者过滤"),
    role: str = FastQuery("", description="按角色过滤（user/assistant/tool_call/tool_result/error）"),
    limit: int = FastQuery(100, ge=1, le=500),
    offset: int = FastQuery(0, ge=0),
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """查询 Agent 对话审计日志"""
    q = select(AgentConversationLog).order_by(AgentConversationLog.timestamp.desc())
    if session_id:
        q = q.where(AgentConversationLog.session_id == session_id)
    if operator:
        q = q.where(AgentConversationLog.operator.ilike(f"%{operator}%"))
    if role:
        q = q.where(AgentConversationLog.role == role)
    q = q.limit(limit).offset(offset)

    rows = (await db.execute(q)).scalars().all()
    return {
        "logs": [
            {
                "id": r.id,
                "session_id": r.session_id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "operator": r.operator,
                "role": r.role,
                "content": (r.content or "")[:500],
                "tool_name": r.tool_name,
                "tool_args": r.tool_args,
                "tool_result": (r.tool_result or "")[:500] if r.tool_result else None,
                "ip_address": r.ip_address,
            }
            for r in rows
        ],
        "count": len(rows),
    }


@router.get("/logs/sessions")
async def get_agent_sessions(
    limit: int = FastQuery(50, ge=1, le=200),
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """获取对话会话列表（按最近活动排序）"""
    q = (
        select(
            AgentConversationLog.session_id,
            AgentConversationLog.operator,
            func.min(AgentConversationLog.timestamp).label("started_at"),
            func.max(AgentConversationLog.timestamp).label("last_at"),
            func.count(AgentConversationLog.id).label("msg_count"),
        )
        .group_by(AgentConversationLog.session_id, AgentConversationLog.operator)
        .order_by(func.max(AgentConversationLog.timestamp).desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).all()
    return {
        "sessions": [
            {
                "session_id": r[0],
                "operator": r[1],
                "started_at": r[2].isoformat() if r[2] else None,
                "last_at": r[3].isoformat() if r[3] else None,
                "msg_count": r[4],
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ════════════════════════════════════════════════════════════════════════════
# Agent Prompt 管理：GET/PUT /api/agent/prompt
# ════════════════════════════════════════════════════════════════════════════

@router.get("/prompt")
async def get_agent_prompt(
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """获取当前 Agent System Prompt（基础模板 + 企业自定义）"""
    from app.services.settings_service import get_setting, get_ai_settings
    ai_cfg = await get_ai_settings(db)
    custom_prompt = ai_cfg.get("openclaw_prompt", "")
    return {
        "base_prompt": BASE_SYSTEM_PROMPT,
        "custom_prompt": custom_prompt,
        "full_prompt": await _build_system_prompt(db),
    }


@router.put("/prompt")
async def set_agent_prompt(
    body: dict,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """更新 Agent 自定义 System Prompt（追加到基础模板之后）"""
    from app.services.settings_service import set_setting
    custom_prompt = body.get("custom_prompt", "")
    await set_setting(db, "ai.openclaw_prompt", custom_prompt or None, updated_by="agent")
    await db.commit()
    return {
        "ok": True,
        "message": "Agent Prompt 已更新",
        "custom_prompt": custom_prompt,
    }


def _sse(data: dict) -> str:
    """格式化 SSE 事件"""
    return f"data: {json.dumps(data, ensure_ascii=False, default=str)}\n\n"


# ════════════════════════════════════════════════════════════════════════════
# Phase 3: GET /api/agent/suggestions — @ 引用补全
# ════════════════════════════════════════════════════════════════════════════

@router.get("/suggestions")
async def agent_suggestions(
    q: str = FastQuery("", description="搜索关键词"),
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """@ 引用补全数据源：返回匹配的终端/QID/分组"""
    q_lower = q.lower().strip()
    results = {"clients": [], "qids": [], "groups": []}

    if not q_lower:
        return results

    # 搜索终端
    clients = (await db.execute(
        select(Client.id, Client.hostname, Client.ip)
        .where(or_(
            Client.hostname.ilike(f"%{q_lower}%"),
            Client.ip.ilike(f"%{q_lower}%"),
        ))
        .limit(10)
    )).all()
    results["clients"] = [
        {"id": r[0], "name": r[1], "ip": r[2], "type": "client"}
        for r in clients
    ]

    # 搜索 QID（去重）
    qids = (await db.execute(
        select(RemediationRule.qid, RemediationRule.fix_type, RemediationRule.status)
        .where(RemediationRule.qid.ilike(f"%{q_lower}%"))
        .limit(10)
    )).all()
    results["qids"] = [
        {"id": r[0], "name": f"QID {r[0]}", "fix_type": r[1], "status": r[2], "type": "qid"}
        for r in qids
    ]

    # 搜索分组
    groups = (await db.execute(
        select(Group.id, Group.name).where(Group.name.ilike(f"%{q_lower}%")).limit(10)
    )).all()
    results["groups"] = [
        {"id": r[0], "name": r[1], "type": "group"}
        for r in groups
    ]

    return results


# ════════════════════════════════════════════════════════════════════════════
# Phase 4: Agent 工作区 — 文件上传 + AI 分析 + 包推送
# ════════════════════════════════════════════════════════════════════════════

WORKSPACE_DIR = "/opt/itasset/workspace"


@router.post("/workspace/upload")
async def workspace_upload(
    file: UploadFile = File(...),
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """上传文件到 Agent 工作区"""
    os.makedirs(WORKSPACE_DIR, exist_ok=True)

    # 安全文件名
    safe_name = os.path.basename(file.filename or "unnamed")
    # 防止路径穿越
    safe_name = safe_name.replace("..", "").replace("/", "").replace("\\", "")

    # 生成唯一文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stored_name = f"{timestamp}_{safe_name}"
    stored_path = os.path.join(WORKSPACE_DIR, stored_name)

    # 读取并保存
    content = await file.read()
    max_size = 100 * 1024 * 1024  # 100MB
    if len(content) > max_size:
        raise HTTPException(413, f"文件超过 {max_size // 1024 // 1024}MB 上限")

    with open(stored_path, "wb") as f:
        f.write(content)

    file_size = len(content)
    file_hash = _sha256_file(stored_path)

    # 如果是安装包（.msi/.exe），自动注册到 packages 表
    ext = os.path.splitext(safe_name)[1].lower()
    is_package = ext in (".msi", ".exe", ".zip", ".7z")

    package_info = None
    if is_package:
        pkg = Package(
            name=os.path.splitext(safe_name)[0],
            version="1.0",
            filename=stored_name,
            file_hash=file_hash,
            file_size=file_size,
            description=f"Agent 工作区上传 - {datetime.now().isoformat()}",
        )
        db.add(pkg)
        await db.commit()
        await db.refresh(pkg)
        package_info = {"package_id": pkg.id, "name": pkg.name}

    return {
        "ok": True,
        "filename": safe_name,
        "stored_name": stored_name,
        "size": file_size,
        "hash": file_hash,
        "is_package": is_package,
        "package": package_info,
    }


@router.get("/workspace/files")
async def workspace_files(
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """获取工作区文件列表"""
    if not os.path.isdir(WORKSPACE_DIR):
        return {"files": []}

    files = []
    for name in sorted(os.listdir(WORKSPACE_DIR), reverse=True):
        path = os.path.join(WORKSPACE_DIR, name)
        if not os.path.isfile(path):
            continue
        stat = os.stat(path)
        files.append({
            "name": name,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "ext": os.path.splitext(name)[1].lower(),
        })

    return {"files": files}


@router.delete("/workspace/files/{filename}")
async def workspace_delete_file(
    filename: str,
    _: bool = Depends(require_glpi_token),
):
    """删除工作区文件"""
    safe_name = os.path.basename(filename)
    path = os.path.join(WORKSPACE_DIR, safe_name)
    if not os.path.isfile(path):
        raise HTTPException(404, "文件不存在")
    os.remove(path)
    return {"ok": True, "message": f"已删除 {safe_name}"}


@router.post("/workspace/analyze")
async def workspace_analyze(
    body: dict,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """AI 分析工作区文件内容"""
    filename = body.get("filename", "")
    question = body.get("question", "分析这个文件的用途和关键信息")

    safe_name = os.path.basename(filename)
    path = os.path.join(WORKSPACE_DIR, safe_name)
    if not os.path.isfile(path):
        raise HTTPException(404, "文件不存在")

    # 读取文件内容（文本类最多 10KB，二进制只读基本信息）
    ext = os.path.splitext(safe_name)[1].lower()
    file_content = ""
    if ext in (".txt", ".log", ".csv", ".json", ".xml", ".bat", ".ps1", ".cmd", ".py", ".sh"):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            file_content = f.read(10240)
    else:
        file_content = f"[二进制文件: {safe_name}, 大小: {os.path.getsize(path)} bytes, 扩展名: {ext}]"

    # 调 LLM 分析
    ai_cfg = await get_ai_settings(db)
    if not ai_cfg["llm_enabled"] or not ai_cfg["openclaw_token"]:
        raise HTTPException(503, "LLM 功能未启用或未配置 Token")

    async with httpx.AsyncClient(timeout=ai_cfg["openclaw_timeout"]) as client:
        resp = await client.post(
            f"{ai_cfg['openclaw_url'].rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {ai_cfg['openclaw_token']}"},
            json={
                "model": ai_cfg["openclaw_model"],
                "messages": [
                    {"role": "system", "content": "你是文件分析助手。分析文件内容并回答问题。用中文回复。"},
                    {"role": "user", "content": f"文件名: {safe_name}\n\n文件内容:\n{file_content}\n\n问题: {question}"},
                ],
                "stream": False,
                "max_tokens": 2048,
            },
        )

    if resp.status_code != 200:
        raise HTTPException(500, f"LLM 分析失败: {resp.text[:300]}")

    data = resp.json()
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    return {"analysis": content, "filename": safe_name}


def _sha256_file(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ════════════════════════════════════════════════════════════════════════════
# Phase 2: 终端上线触发 + 优先级排序 + 定时任务
# ════════════════════════════════════════════════════════════════════════════

# 优先级排序：registry_fix > cleanup > software_uninstall > patch_install
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


async def check_and_dispatch_on_connect(serial: str, client_id: int, db: AsyncSession):
    """
    Phase 2: 终端上线触发 — Agent WS 连接时检查该终端是否有 pending vuln tasks → 自动 dispatch
    由 websocket.py 在 Agent 连接时调用。
    """
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
    """
    while True:
        try:
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

            # 删除已触发的定时任务
            await db.execute(
                update(SystemSetting).where(
                    SystemSetting.id == trigger.id
                ).values(value=None)
            )
            await db.commit()
            logger.info(f"Scheduled trigger fired: {data['name']}")

        except Exception as e:
            logger.error(f"Scheduled trigger error: {e}")
