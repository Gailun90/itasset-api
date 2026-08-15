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
import hashlib
import logging
import os
import time
import shutil
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import httpx
from fastapi import (
    APIRouter, Depends, HTTPException, UploadFile, File,
    Form, Query as FastQuery, Request,
)
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, update, delete as sqldelete, text, and_, or_, Text, String, Integer, Boolean, DateTime, Index
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
# 模块化拆分：循环检测/提示词/工具/定时任务 拆到同包兄弟模块。
# 服务器以包方式加载（app.api.v1.agent_chat）走相对导入；
# 测试以 importlib 顶层模块加载（__package__ 为空）走 sys.path 绝对导入。
# ════════════════════════════════════════════════════════════════════════════
import sys as _sys

_HERE = os.path.dirname(os.path.abspath(__file__))

if __package__:
    from .agent_chat_loop import (
        _args_hash, _outcome_hash, _ToolLoopDetector, _format_tool_content,
        _find_safe_cut, _summarize_old, _maybe_compact, _scope_guard,
    )
    from .agent_chat_prompt import BASE_SYSTEM_PROMPT, _build_system_prompt
    from .agent_chat_tools import (
        TOOL_DEFINITIONS,
        tool_list_pending_tasks, tool_shell_exec, tool_get_client_software,
        tool_dispatch_task, tool_get_client_status, tool_update_rule,
        tool_manage_package, tool_deploy_software, tool_query_database,
        tool_set_priority, tool_manage_task, tool_update_task,
    )
    from .agent_chat_tasks import (
        tool_schedule_task, tool_list_scheduled_tasks, tool_update_scheduled_task,
        tool_cancel_scheduled_task, _get_agent_triggers, _consume_online_triggers,
        check_and_dispatch_on_connect, run_agent_scheduler, _check_scheduled_triggers,
        PRIORITY_ORDER,
    )
else:
    if _HERE not in _sys.path:
        _sys.path.insert(0, _HERE)
    from agent_chat_loop import (
        _args_hash, _outcome_hash, _ToolLoopDetector, _format_tool_content,
        _find_safe_cut, _summarize_old, _maybe_compact, _scope_guard,
    )
    from agent_chat_prompt import BASE_SYSTEM_PROMPT, _build_system_prompt
    from agent_chat_tools import (
        TOOL_DEFINITIONS,
        tool_list_pending_tasks, tool_shell_exec, tool_get_client_software,
        tool_dispatch_task, tool_get_client_status, tool_update_rule,
        tool_manage_package, tool_deploy_software, tool_query_database,
        tool_set_priority, tool_manage_task, tool_update_task,
    )
    from agent_chat_tasks import (
        tool_schedule_task, tool_list_scheduled_tasks, tool_update_scheduled_task,
        tool_cancel_scheduled_task, _get_agent_triggers, _consume_online_triggers,
        check_and_dispatch_on_connect, run_agent_scheduler, _check_scheduled_triggers,
        PRIORITY_ORDER,
    )


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


async def tool_record_feedback(
    db: AsyncSession,
    feedback: str,
    operator: str = "unknown",
) -> dict:
    """持久化一条操作员反馈（非破坏性，无需审批）。供后续回合/会话作为约束参考。"""
    feedback = (feedback or "").strip()
    if not feedback:
        return {"ok": False, "error": "feedback 为空"}
    _save_feedback(operator, feedback)
    return {"ok": True, "saved": feedback,
            "note": "已记住该反馈，后续对话会作为约束参考。"}


_PENDING_APPROVALS = {}


def _cleanup_stale_pending():
    now = time.time()
    for k in [k for k, v in _PENDING_APPROVALS.items() if now - v.get("ts", 0) > 600]:
        _PENDING_APPROVALS.pop(k, None)


# ── 风险分类 ──
_RISK_DESTRUCTIVE_ACTIONS = {"delete", "cancel", "reject"}
_RISK_BATCH_TOOLS = {"dispatch_task", "update_task", "deploy_software"}
_RISK_BATCH_THRESHOLD = 1  # client_ids 数量 > 阈值 视为批量


def _risk_of_tool(tool_name, tool_args):
    """返回该工具调用的风险说明；None 表示无需审批。"""
    if tool_name == "shell_exec":
        cmd = str(tool_args.get("command", ""))[:200]
        inter = tool_args.get("interpreter", "powershell")
        return f"将在终端 client_id={tool_args.get('client_id')} 上以 {inter} 执行命令：{cmd}"
    if tool_name == "manage_package":
        if tool_args.get("action") == "delete":
            return f"将永久删除安装包 package_id={tool_args.get('package_id')}（不可恢复）"
        return None
    if tool_name == "manage_task":
        act = tool_args.get("action")
        if act in _RISK_DESTRUCTIVE_ACTIONS:
            return f"将对修复任务 task_id={tool_args.get('task_id')} 执行破坏性操作：{act}"
        return None
    if tool_name == "update_scheduled_task":
        return f"将修改定时/触发任务 trigger_key={tool_args.get('trigger_key')}"
    if tool_name == "schedule_task":
        return f"将新建定时/触发任务：{tool_args.get('name', '')}"
    if tool_name == "cancel_scheduled_task":
        return f"将取消定时/触发任务 trigger_key={tool_args.get('trigger_key')}"
    if tool_name == "update_rule":
        return f"将修改漏洞修复规则（qid={tool_args.get('qid')}）"
    if tool_name in _RISK_BATCH_TOOLS:
        cids = tool_args.get("client_ids") or []
        if isinstance(cids, list) and len(cids) > _RISK_BATCH_THRESHOLD:
            return f"批量操作将影响 {len(cids)} 台终端：{cids[:20]}"
    return None


# ── 操作员反馈持久化（P2：跨回合/跨会话记忆，根治反复踩坑） ──
# 存储：追加式 JSONL 文件（轻量、无需迁移；单进程服务安全）。
# 路径：环境变量 AGENT_FEEDBACK_FILE，默认 /opt/itasset/data/agent_feedback.jsonl。
_FEEDBACK_MAX_INJECT = 20  # 注入系统提示的最大条数
logger = logging.getLogger(__name__)


def _feedback_path() -> str:
    return os.environ.get("AGENT_FEEDBACK_FILE",
                          "/opt/itasset/data/agent_feedback.jsonl")


def _load_feedback(limit: int = _FEEDBACK_MAX_INJECT) -> list:
    """读取最近 limit 条反馈文本；文件不存在或损坏返回 []。"""
    p = _feedback_path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        return []
    except OSError:
        return []
    out = []
    for ln in lines[-limit:]:
        try:
            rec = json.loads(ln)
            out.append(rec.get("feedback", ln))
        except json.JSONDecodeError:
            out.append(ln)
    return out


def _save_feedback(operator: str, feedback: str) -> None:
    """追加一条反馈；目录不存在则创建；IO 失败仅记录不抛出。"""
    p = _feedback_path()
    try:
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": int(time.time()),
                "operator": operator or "unknown",
                "feedback": feedback,
            }, ensure_ascii=False) + "\n")
    except OSError as e:
        logger.error(f"Failed to save feedback to {p}: {e}")


def _build_feedback_section(limit: int = _FEEDBACK_MAX_INJECT) -> str:
    """构造注入系统提示的反馈段落；无反馈返回空串。"""
    items = _load_feedback(limit)
    if not items:
        return ""
    bullet = "\n".join(f"- {it}" for it in items)
    return ("\n\n## 操作员的既往反馈（务必遵守，避免重复踩坑）\n"
            + bullet + "\n")


def _append_assistant_and_result(current_messages, tc, round_idx, tool_name, tool_args_str, result_content, reasoning_content=None):
    """把 assistant(tool_calls) + tool 结果 两行追加到 current_messages。

    reasoning_content 为 DeepSeek thinking 模式返回字段：模型产生 assistant 消息后，
    下一轮请求必须把该字段原样回传，否则 DeepSeek 直接 400
    （"The reasoning_content in the thinking mode must be passed back to the API"）。
    因此重建 assistant 消息时必须保留它。"""
    am = {
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": tc.get("id", f"call_{round_idx}"),
            "type": "function",
            "function": {"name": tool_name, "arguments": tool_args_str},
        }],
    }
    if reasoning_content:
        am["reasoning_content"] = reasoning_content
    current_messages.append(am)
    current_messages.append({
        "role": "tool",
        "tool_call_id": tc.get("id", f"call_{round_idx}"),
        "content": result_content,
    })


async def _execute_tool_call(tc, round_idx, current_messages, session_id, operator, client_ip,
                             referenced_client_ids, detector, db, ai_cfg, reasoning_content=None):
    """执行单个工具调用，返回 (events, updated_current_messages)。
    包含：引用作用域硬闸、实际执行、工具循环/卡死检测、上下文压缩。"""
    events = []
    fn = tc.get("function", {})
    tool_name = fn.get("name", "")
    tool_args_str = fn.get("arguments", "{}")
    try:
        tool_args = json.loads(tool_args_str)
    except json.JSONDecodeError:
        tool_args = {}

    # 引用作用域硬闸
    scope_err = _scope_guard(tool_name, tool_args, referenced_client_ids)
    if scope_err is not None:
        events.append({"type": "tool_result", "tool_name": tool_name, "result": scope_err})
        await _log_conversation(db, session_id, operator, "tool_result",
            tool_name=tool_name, tool_result=scope_err, ip_address=client_ip)
        _append_assistant_and_result(current_messages, tc, round_idx, tool_name,
                                     tool_args_str,
                                     json.dumps(scope_err, ensure_ascii=False, default=str),
                                     reasoning_content=reasoning_content)
        detector.record(tool_name, _args_hash(tool_name, tool_args), _outcome_hash(scope_err))
        level, _loop_msg = detector.check()
        if level == "crit":
            events.append({"type": "content", "content":
                "（检测到重复的无效操作请求，已自动停止。请明确目标终端后重试。）"})
            events.append({"type": "done"})
        return events, current_messages

    # 执行工具
    tool_fn = TOOL_FUNCTIONS.get(tool_name)
    if tool_fn:
        try:
            tool_result = await tool_fn(db=db, **tool_args)
            events.append({"type": "tool_result", "tool_name": tool_name, "result": tool_result})
            await _log_conversation(db, session_id, operator, "tool_result",
                tool_name=tool_name, tool_result=tool_result, ip_address=client_ip)
            _append_assistant_and_result(current_messages, tc, round_idx, tool_name,
                                         tool_args_str, _format_tool_content(tool_result),
                                         reasoning_content=reasoning_content)
            last_result = tool_result
        except Exception as e:
            logger.error(f"Tool {tool_name} execution error: {e}")
            err_res = {"error": str(e)}
            last_result = err_res
            events.append({"type": "tool_result", "tool_name": tool_name, "result": err_res})
            _append_assistant_and_result(current_messages, tc, round_idx, tool_name,
                                         tool_args_str,
                                         json.dumps(err_res, ensure_ascii=False, default=str),
                                         reasoning_content=reasoning_content)
    else:
        err_res = {"error": f"未知工具: {tool_name}"}
        last_result = err_res
        events.append({"type": "tool_result", "tool_name": tool_name, "result": err_res})
        _append_assistant_and_result(current_messages, tc, round_idx, tool_name,
                                     tool_args_str,
                                     json.dumps(err_res, ensure_ascii=False, default=str),
                                     reasoning_content=reasoning_content)

    # 工具循环/卡死检测
    detector.record(tool_name, _args_hash(tool_name, tool_args), _outcome_hash(last_result))
    level, loop_msg = detector.check()
    if level == "crit":
        events.append({"type": "content", "content":
            "（检测到工具调用陷入重复/无进展，已自动停止处理，避免无效重试。请调整指令或确认目标后重试。）"})
        events.append({"type": "done"})
        return events, current_messages
    if level == "warn" and loop_msg:
        current_messages.append({"role": "user", "content": "[系统强制提示] " + loop_msg})
    # 上下文压缩
    current_messages = await _maybe_compact(ai_cfg, current_messages)
    return events, current_messages


async def _run_agent_loop(current_messages, session_id, operator, client_ip, ai_cfg,
                          referenced_client_ids, db, detector, request):
    """智能体主循环（LLM 调用 + 工具执行）。yield SSE 事件字典。

    轮次无硬上限（已按需求取消工具调用次数限制）；循环检测熔断 (crit) 仍保留，
    作为“无进展死循环”的最后兜底。前端停止按钮 abort 连接后，循环开头检测
    request.is_disconnected() 立即退出，避免继续烧 token。
    """
    round_idx = 0
    while True:
        round_idx += 1
        # 用户中断：连接已断开（前端点了停止）→ 立即退出生成器
        if await request.is_disconnected():
            return
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
        tool_calls = msg.get("tool_calls", [])
        reasoning_content = msg.get("reasoning_content")

        if tool_calls:
            # ── P1 高危/批量操作审批闸 ──
            risks = []
            for tc in tool_calls:
                fn = tc.get("function", {})
                tname = fn.get("name", "")
                try:
                    targs = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    targs = {}
                r = _risk_of_tool(tname, targs)
                if r:
                    risks.append({"tool_name": tname, "args": targs, "risk": r})
            if risks:
                assistant_msgs = []
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    tname = fn.get("name", "")
                    targs_str = fn.get("arguments", "{}")
                    am = {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": tc.get("id", f"call_{round_idx}"),
                            "type": "function",
                            "function": {"name": tname, "arguments": targs_str},
                        }],
                    }
                    if reasoning_content:
                        am["reasoning_content"] = reasoning_content
                    assistant_msgs.append(am)
                _cleanup_stale_pending()
                _PENDING_APPROVALS[session_id] = {
                    "messages": list(current_messages),
                    "assistant_msgs": assistant_msgs,
                    "tool_calls": tool_calls,
                    "reasoning_content": reasoning_content,  # 恢复执行时重建 assistant 消息需回传
                    "operator": operator,
                    "client_ip": client_ip,
                    "referenced_client_ids": referenced_client_ids,
                    "ts": time.time(),
                }
                yield _sse({"type": "confirmation_required", "session_id": session_id,
                            "risks": risks, "count": len(tool_calls)})
                yield _sse({"type": "done"})
                return

            # 非高危：逐个执行
            for tc in tool_calls:
                fn = tc.get("function", {})
                tname = fn.get("name", "")
                try:
                    targs = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    targs = {}
                yield _sse({"type": "tool_call", "tool_name": tname, "arguments": targs})
                await _log_conversation(db, session_id, operator, "tool_call",
                    tool_name=tname, tool_args=targs, ip_address=client_ip)
                events, current_messages = await _execute_tool_call(
                    tc, round_idx, current_messages, session_id, operator, client_ip,
                    referenced_client_ids, detector, db, ai_cfg,
                    reasoning_content=reasoning_content)
                for ev in events:
                    yield _sse(ev)
                if any(ev.get("type") == "done" for ev in events):
                    return
            continue

        else:
            content = msg.get("content", "")
            if content:
                yield _sse({"type": "content", "content": content})
                await _log_conversation(db, session_id, operator, "assistant",
                    content=content, ip_address=client_ip)
            yield _sse({"type": "done"})
            return



# ════════════════════════════════════════════════════════════════════════════
# Phase 1: POST /api/agent/chat — Agent 对话 + 工具调用（流式 SSE）
# ════════════════════════════════════════════════════════════════════════════


@router.post("/chat")
async def agent_chat(
    body: dict,
    request: Request,
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
    # ── P1 审批恢复路径：前端对高危/批量操作的确认回传 ──
    confirm = body.get("confirm")
    if confirm:
        _cleanup_stale_pending()
        sid = confirm.get("session_id")
        decision = (confirm.get("decision") or "").lower()
        pending = _PENDING_APPROVALS.pop(sid, None) if sid else None
        _SSE_HEADERS = {"Cache-Control": "no-cache", "Connection": "keep-alive",
                         "X-Accel-Buffering": "no"}
        if not pending:
            async def _err_stream():
                yield _sse({"type": "error", "content": "未找到待确认的操作（可能已超时，请重新发起请求）"})
            return StreamingResponse(_err_stream(), media_type="text/event-stream", headers=_SSE_HEADERS)
        session_id = sid
        operator = pending["operator"]
        client_ip = pending["client_ip"]
        ai_cfg = await get_ai_settings(db)
        if not ai_cfg["llm_enabled"]:
            raise HTTPException(503, "LLM 功能未启用")
        if not ai_cfg["openclaw_token"]:
            raise HTTPException(503, "未配置 LLM Token")
        referenced_client_ids = pending.get("referenced_client_ids", [])
        # 注意：pending["messages"] 在风险检测时（_run_agent_loop 内）尚未追加
        # assistant(tool_calls) —— 该消息由下面的 _execute_tool_call 通过
        # _append_assistant_and_result 逐个补回。若此处再拼入 pending["assistant_msgs"]
        # 会造成 assistant(tool_calls) 被重复追加，导致"assistant 后未紧跟 tool 消息"
        # 从而触发 LLM 侧 HTTP 400（invalid_request_error）。
        current_messages = list(pending["messages"])
        detector = _ToolLoopDetector()

        async def event_stream():
            nonlocal current_messages
            try:
                if decision == "reject":
                    yield _sse({"type": "content", "content": "（已拒绝执行该高危/批量操作）"})
                    current_messages.append({"role": "user", "content":
                        "[系统] 用户已拒绝执行此前请求的高危/批量操作。请停止相关动作，并向用户简要说明，不要再次尝试。"})
                    await _log_conversation(db, session_id, operator, "tool_result",
                        tool_name="(approval)", tool_result={"rejected": True}, ip_address=client_ip)
                else:
                    for tc in pending["tool_calls"]:
                        fn = tc.get("function", {})
                        tname = fn.get("name", "")
                        try:
                            targs = json.loads(fn.get("arguments", "{}"))
                        except json.JSONDecodeError:
                            targs = {}
                        yield _sse({"type": "tool_call", "tool_name": tname, "arguments": targs})
                        await _log_conversation(db, session_id, operator, "tool_call",
                            tool_name=tname, tool_args=targs, ip_address=client_ip)
                        events, current_messages = await _execute_tool_call(
                            tc, 0, current_messages, session_id, operator, client_ip,
                            referenced_client_ids, detector, db, ai_cfg,
                            reasoning_content=pending.get("reasoning_content"))
                        for ev in events:
                            yield _sse(ev)
                        if any(ev.get("type") == "done" for ev in events):
                            return
                async for ev in _run_agent_loop(
                    current_messages, session_id, operator, client_ip,
                    ai_cfg, referenced_client_ids, db, detector, request
                ):
                    yield ev
            except Exception as e:
                logger.error(f"Agent confirm stream error: {e}", exc_info=True)
                yield _sse({"type": "error", "content": f"内部错误: {str(e)}"})
        return StreamingResponse(event_stream(), media_type="text/event-stream", headers=_SSE_HEADERS)

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

    # 构建引用上下文（结构化，并提取被引用终端的真实 ID 供作用域硬闸使用）
    ref_context = ""
    referenced_client_ids = []
    if references:
        ref_lines = []
        for ref in references:
            rid = ref.get("id")
            rtype = ref.get("type")
            rname = ref.get("name")
            ref_lines.append(f"  - type={rtype}, id={rid}, name={rname}")
            if rtype == "client" and str(rid).isdigit():
                referenced_client_ids.append(int(rid))
        ref_context = (
            "\n\n## 已确定的操作目标（务必使用下列真实 ID）\n"
            + "\n".join(ref_lines)
            + "\n\n**作用域规则**：当用户要求对某资产执行操作（如 shell_exec、get_client_software、"
            "dispatch_task 等）时，client_id/client_ids 必须取自上述已确定目标；"
            "若请求中的资产不在上述目标中且未明确给出 client_id，必须先向用户确认，"
            "绝不能凭名称猜测 ID 去操作其他终端。"
        )

    # 构建消息列表（System Prompt 从 GLPI 配置动态加载）
    system_prompt = await _build_system_prompt(db)
    feedback_section = _build_feedback_section()  # P2：跨会话持久化反馈
    _PLAN_HINT = (
        "\n\n## 批量/多步任务操作准则\n"
        "当用户请求涉及多台终端、批量下发或多项变更时，先给出简明执行方案"
        "（目标、范围、步骤、预期影响），待用户确认后再执行；不要未经确认就对大量终端执行变更类操作。"
    )
    current_messages = [{"role": "system", "content": system_prompt + feedback_section + ref_context + _PLAN_HINT}]
    for msg in history[-10:]:  # 最多保留最近 10 条历史
        role = msg.get("role")
        if role in ("user", "assistant") and msg.get("content"):
            cm = {"role": role, "content": msg["content"]}
            # DeepSeek thinking 模式：assistant 消息若带 reasoning_content 须原样回传，否则 400
            if role == "assistant" and msg.get("reasoning_content"):
                cm["reasoning_content"] = msg["reasoning_content"]
            current_messages.append(cm)
    current_messages.append({"role": "user", "content": message})

    async def event_stream():
        """SSE 流式响应（正常路径：先发 session_id，再跑智能体主循环）"""
        try:
            yield _sse({"type": "session", "session_id": session_id})
            detector = _ToolLoopDetector()  # 工具循环/卡死检测（P0）
            async for ev in _run_agent_loop(
                current_messages, session_id, operator, client_ip,
                ai_cfg, referenced_client_ids, db, detector, request
            ):
                yield ev
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

def _parse_log_time_range(start: str, end: str):
    """解析前端传入的本地(Asia/Shanghai)日期/时间，返回 (utc_start, utc_end) 边界 datetime(UTC)。

    仅日期时：start→当日 00:00:00，end→当日 23:59:59.999999；解析失败返回 None。
    """
    tz_local = timezone(timedelta(hours=8))

    def _one(v, is_end):
        if not v:
            return None
        v = str(v).strip()
        fmts = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d"]
        dt = None
        for f in fmts:
            try:
                dt = datetime.strptime(v, f)
                break
            except ValueError:
                continue
        if dt is None:
            return None
        # 仅日期 → 补齐当日边界
        if " " not in v and "T" not in v:
            if is_end:
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            else:
                dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        return dt.replace(tzinfo=tz_local).astimezone(timezone.utc)

    return _one(start, False), _one(end, True)


@router.get("/logs")
async def get_agent_logs(
    session_id: str = FastQuery("", description="按会话 ID 过滤"),
    operator: str = FastQuery("", description="按操作者过滤"),
    role: str = FastQuery("", description="按角色过滤（user/assistant/tool_call/tool_result/error）"),
    start: str = FastQuery("", description="起始时间（本地 YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS）"),
    end: str = FastQuery("", description="结束时间，同上；仅日期时含当天 23:59:59"),
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

    # 时间范围过滤（前端传本地时间 → 转换 UTC 与库内 UTC 时间戳比较）
    if start or end:
        b_start, b_end = _parse_log_time_range(start, end)
        conds = []
        if b_start is not None:
            conds.append(AgentConversationLog.timestamp >= b_start)
        if b_end is not None:
            conds.append(AgentConversationLog.timestamp <= b_end)
        if conds:
            q = q.where(and_(*conds))

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
# GET/DELETE /api/agent/triggers — AI 定时/上线触发任务列表（前台"软件分发"菜单下的展示页用）
# ════════════════════════════════════════════════════════════════════════════


@router.get("/triggers")
async def list_agent_triggers(
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    return {"triggers": await _get_agent_triggers(db)}


@router.delete("/triggers/{trigger_key}")
async def cancel_agent_trigger(
    trigger_key: str,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """取消一个还没触发的 AI 定时/上线任务"""
    from app.models.models import SystemSetting
    if not trigger_key.startswith("agent.trigger."):
        raise HTTPException(status_code=400, detail="非法的 trigger key")
    result = await db.execute(sqldelete(SystemSetting).where(SystemSetting.key == trigger_key))
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="未找到该触发任务（可能已经触发或被取消）")
    return {"ok": True, "message": f"已取消：{trigger_key}"}


@router.post("/triggers")
async def create_agent_trigger(
    body: dict,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """
    人工新建一个定时/上线触发任务——AI 对话里创建之外的补救入口，
    字段跟 schedule_task 工具完全一致，直接复用同一份逻辑，不重复实现。
    """
    result = await tool_schedule_task(
        db,
        name=body.get("name", ""),
        task_type=body.get("task_type", "run_command"),
        trigger_type=body.get("trigger_type", "online"),
        client_ids=body.get("client_ids") or [],
        command=body.get("command"),
        scheduled_at=body.get("scheduled_at"),
        priority=body.get("priority", "normal"),
        interpreter=body.get("interpreter", "powershell"),
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.put("/triggers/{trigger_key}")
async def update_agent_trigger(
    trigger_key: str,
    body: dict,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """
    编辑一个还没触发的定时/上线任务——AI 有时候会把命令/目标终端/时间安排错，
    这里让人工可以直接改，不用先删了再让 AI 重新建一遍。
    """
    from app.models.models import SystemSetting
    if not trigger_key.startswith("agent.trigger."):
        raise HTTPException(status_code=400, detail="非法的 trigger key")

    result = await db.execute(select(SystemSetting).where(SystemSetting.key == trigger_key))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="未找到该触发任务（可能已经触发或被取消）")

    try:
        data = json.loads(row.value) if row.value else {}
    except json.JSONDecodeError:
        data = {}

    for field in ("name", "task_type", "command", "interpreter", "priority", "client_ids", "scheduled_at"):
        if field in body:
            data[field] = body[field]

    row.value = json.dumps(data, ensure_ascii=False)
    row.updated_by = "admin_edit"
    await db.commit()
    return {"ok": True, "message": f"已更新：{trigger_key}", "data": data}


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


# ════════════════════════════════════════════════════════════════════════════
# 工具函数映射（实现分散在 agent_chat_tools / agent_chat_tasks / 本文件）
# ════════════════════════════════════════════════════════════════════════════
TOOL_FUNCTIONS = {
    "list_pending_tasks": tool_list_pending_tasks,
    "shell_exec": tool_shell_exec,
    "dispatch_task": tool_dispatch_task,
    "get_client_status": tool_get_client_status,
    "update_rule": tool_update_rule,
    "manage_package": tool_manage_package,
    "schedule_task": tool_schedule_task,
    "list_scheduled_tasks": tool_list_scheduled_tasks,
    "update_scheduled_task": tool_update_scheduled_task,
    "cancel_scheduled_task": tool_cancel_scheduled_task,
    "query_database": tool_query_database,
    "set_priority": tool_set_priority,
    "manage_task": tool_manage_task,
    "update_task": tool_update_task,
    "deploy_software": tool_deploy_software,
    "get_client_software": tool_get_client_software,
    "record_feedback": tool_record_feedback,
}
