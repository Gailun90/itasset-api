# -*- coding: utf-8 -*-
"""Agent 对话引擎 — 工具循环检测 / 结果裁剪 / 上下文压缩 / 引用作用域（纯逻辑）。

从 agent_chat.py 拆分而来；无副作用、不依赖 app 包，供 agent_chat.py 导入。
"""
import json
import hashlib
import logging

import httpx

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════════════════════
# P0 增强：工具循环检测 / 结果裁剪 / 上下文压缩 / 引用作用域
# （对照 OpenClaw tool-loop-detection / compaction-safeguard 思路，Python 移植）
# ════════════════════════════════════════════════════════════════════════════

from collections import deque, defaultdict  # hashlib 见顶部 import；json/httpx 已导入

# ---- 工具循环/卡死检测参数 ----
_TOOL_LOOP_WINDOW = 30            # 滑动窗口大小
_TOOL_LOOP_REPEAT_WARN = 3        # 同 (tool,args) 无进展重复 → 警告
_TOOL_LOOP_REPEAT_CRIT = 6        # → 熔断
_TOOL_LOOP_GLOBAL_CRIT = 25       # 窗口内总调用无进展 → 全局熔断
_TOOL_LOOP_CHURN_WARN = 4         # 单工具参数来回变且无进展 → 警告

# ---- 工具结果裁剪参数 ----
# ⚠️ 已按需求关闭所有输出限制：0 表示不截断 / 不抽样（全量返回）。
# token 体量风险由模型侧自行承担（用户明确接受）。
_MAX_TOOL_RESULT_CHARS = 0        # 单条工具结果硬上限；0 = 不截断
_MAX_LIST_ITEMS = 0               # 列表型字段最多保留条数；0 = 不抽样

# ---- 上下文压缩参数 ----
_COMPACT_THRESHOLD_CHARS = 28000  # ≈7k token，超过才压缩
_COMPACT_KEEP_RECENT = 12         # 保留最近 N 条原文

# ---- 引用作用域：被引用（type=client）的真实 ID 集合 ----
_SINGLE_TARGET_TOOLS = {"shell_exec", "get_client_software"}
_LIST_TARGET_TOOLS = {"dispatch_task", "update_task", "schedule_task", "manage_task"}


def _args_hash(tool_name: str, tool_args: dict) -> str:
    try:
        norm = json.dumps(tool_args, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        norm = str(tool_args)
    return hashlib.sha256(f"{tool_name}|{norm}".encode("utf-8")).hexdigest()[:16]


def _outcome_hash(tool_result) -> str:
    try:
        s = json.dumps(tool_result, ensure_ascii=False, default=str)
    except Exception:
        s = str(tool_result)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


class _ToolLoopDetector:
    """滑动窗口检测工具循环/卡死，命中即提醒模型停止重试，critical 熔断。"""

    def __init__(self):
        self.calls = deque(maxlen=_TOOL_LOOP_WINDOW)  # (tool, args_hash, outcome_hash)
        self.total = 0
        self._warned_keys = set()

    def record(self, tool_name, args_hash, outcome_hash):
        self.total += 1
        self.calls.append((tool_name, args_hash, outcome_hash))

    def check(self):
        """返回 (level, message)，level ∈ {None,'warn','crit'}。"""
        if not self.calls:
            return (None, "")
        by_key = defaultdict(list)
        for tool, ahash, ohash in self.calls:
            by_key[(tool, ahash)].append(ohash)

        # 1) 同 (tool,args) 结果完全一致 → 无进展重复
        worst = (None, "")
        for (tool, ahash), ohashes in by_key.items():
            n = len(ohashes)
            if len(set(ohashes)) == 1:
                if n >= _TOOL_LOOP_REPEAT_CRIT:
                    return ("crit",
                            f"检测到你已连续 {n} 次以完全相同参数调用 {tool} 且结果完全一致（无任何进展）。"
                            f"必须立即停止重试，向用户简要说明当前障碍，并请求必要的信息或确认，不要再调用该工具。")
                if n >= _TOOL_LOOP_REPEAT_WARN:
                    key = (tool, ahash)
                    if key not in self._warned_keys:
                        self._warned_keys.add(key)
                        worst = ("warn",
                                 f"你已重复 {n} 次调用 {tool} 且结果无变化。若继续无进展，请停止重试，"
                                 f"改为向用户说明问题并请求确认，不要盲目反复调用同一工具。")

        # 2) 参数来回变（瞎试）但单工具多次且无进展
        per_tool = defaultdict(list)
        for tool, ahash, _ in self.calls:
            per_tool[tool].append(ahash)
        for tool, ahashes in per_tool.items():
            if len(ahashes) >= _TOOL_LOOP_CHURN_WARN:
                distinct = len(set(ahashes))
                if 2 <= distinct <= 4:
                    key = ("churn", tool)
                    if key not in self._warned_keys:
                        self._warned_keys.add(key)
                        worst = ("warn",
                                 f"你正在对 {tool} 在少数几个参数间反复尝试但均无进展。请停止参数瞎试，"
                                 f"改为向用户说明遇到的问题并请求明确指示。")

        # 3) 全局熔断
        if self.total >= _TOOL_LOOP_GLOBAL_CRIT:
            return ("crit",
                    f"已连续执行 {self.total} 次工具调用但整体无实质进展。请立即停止，"
                    f"向用户总结当前状态并说明需要其确认或补充的信息。")
        return worst


def _format_tool_content(tool_result) -> str:
    """裁剪工具结果：列表字段抽样 + 总长度硬截断，避免淹没上下文。"""
    if isinstance(tool_result, dict):
        trimmed = {}
        notes = []
        for k, v in tool_result.items():
            if _MAX_LIST_ITEMS and isinstance(v, list) and len(v) > _MAX_LIST_ITEMS:
                trimmed[k] = v[:_MAX_LIST_ITEMS]
                notes.append(f"{k}: 仅显示前 {_MAX_LIST_ITEMS}/{len(v)} 条")
            else:
                trimmed[k] = v
        if notes:
            trimmed["_truncation_note"] = "; ".join(notes)
        s = json.dumps(trimmed, ensure_ascii=False, default=str)
    else:
        s = json.dumps(tool_result, ensure_ascii=False, default=str)

    if _MAX_TOOL_RESULT_CHARS and len(s) > _MAX_TOOL_RESULT_CHARS:
        return s[:_MAX_TOOL_RESULT_CHARS] + f"...[结果过长已截断，原始 {len(s)} 字符]"
    return s


def _find_safe_cut(rest, keep_n):
    """找到安全切割点 i，使 rest[:i] 可摘要、rest[i:] 保留且不构成悬空 tool_call 引用。找不到返回 None。"""
    if keep_n >= len(rest):
        return None
    start = max(0, len(rest) - keep_n)
    for i in range(start, len(rest)):
        role = rest[i].get("role")
        if role in ("user", "system"):
            if i > 0 and rest[i - 1].get("role") == "assistant" and rest[i - 1].get("tool_calls"):
                continue
            return i
        if role == "assistant" and not rest[i].get("tool_calls"):
            if i > 0 and rest[i - 1].get("role") == "assistant" and rest[i - 1].get("tool_calls"):
                continue
            return i
    return None


async def _summarize_old(ai_cfg, old_messages) -> str:
    """用一次 LLM 调用把旧轮对话压成结构化摘要，失败兜底返回占位。"""
    try:
        compact_text = "\n".join(
            f"[{m.get('role', '?')}] {str(m.get('content') or m.get('tool_calls') or '')[:1500]}"
            for m in old_messages
        )
        async with httpx.AsyncClient(timeout=ai_cfg["openclaw_timeout"]) as client:
            resp = await client.post(
                f"{ai_cfg['openclaw_url'].rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {ai_cfg['openclaw_token']}"},
                json={
                    "model": ai_cfg["openclaw_model"],
                    "messages": [
                        {"role": "system", "content": "你是一个对话压缩器。请把下面的运维 Agent 对话历史压缩成简洁的结构化摘要，"
                         "保留：用户的核心诉求、已确认的事实（终端ID/任务ID/状态）、已执行的动作及其结果、未解决的问题。不要编造信息。"},
                        {"role": "user", "content": compact_text},
                    ],
                    "stream": False,
                    "max_tokens": 1024,
                },
            )
        if resp.status_code == 200:
            d = resp.json()
            return d.get("choices", [{}])[0].get("message", {}).get("content", "") or "(摘要生成失败)"
        return f"(早期对话共 {len(old_messages)} 条，已省略)"
    except Exception:
        return f"(早期对话共 {len(old_messages)} 条，已省略)"


async def _maybe_compact(ai_cfg, current_messages):
    """若上下文过长则压缩旧轮，返回（可能更新后的）messages。"""
    if len(current_messages) <= _COMPACT_KEEP_RECENT + 1:
        return current_messages
    rest = current_messages[1:]
    total_chars = sum(len(json.dumps(m, ensure_ascii=False, default=str)) for m in rest)
    if total_chars < _COMPACT_THRESHOLD_CHARS:
        return current_messages
    i = _find_safe_cut(rest, _COMPACT_KEEP_RECENT)
    if i is None:
        return current_messages  # 无安全切点，跳过压缩
    system_msg = current_messages[0]
    old = rest[:i]
    keep = rest[i:]
    summary = await _summarize_old(ai_cfg, old)
    summary_msg = {"role": "system", "content": "## 对话早期摘要（已自动压缩）\n" + summary}
    return [system_msg, summary_msg] + keep


def _scope_guard(tool_name, tool_args, referenced_client_ids):
    """引用作用域硬闸：当用户已明确引用某终端，而工具要操作不在引用内的终端时拦截。
    返回 None 表示放行；返回 dict 表示拦截错误（直接作为 tool_result）。"""
    if not referenced_client_ids:
        return None
    if tool_name in _SINGLE_TARGET_TOOLS:
        cid = tool_args.get("client_id")
        if cid is not None:
            try:
                cid = int(cid)
            except (TypeError, ValueError):
                return None
            if cid not in referenced_client_ids:
                return {"error": f"操作目标 client_id={cid} 不在当前引用资产 {referenced_client_ids} 中。"
                                 f"为避免误操作其他终端已拦截；如需操作该终端请先加入引用或明确说明。"}
    elif tool_name in _LIST_TARGET_TOOLS:
        cids = tool_args.get("client_ids")
        if cids:
            try:
                cids = [int(x) for x in cids]
            except (TypeError, ValueError):
                return None
            bad = [c for c in cids if c not in referenced_client_ids]
            if bad:
                return {"error": f"操作目标 client_ids={bad} 不在当前引用资产 {referenced_client_ids} 中。"
                                 f"为避免误操作其他终端已拦截；如需操作请先加入引用或明确说明。"}
    return None


# ════════════════════════════════════════════════════════════════════════════
# P1 增强：高危/批量操作审批闸（对照 OpenClaw approval-gate 思路）
# ════════════════════════════════════════════════════════════════════════════

# 跨请求的待确认状态（进程内字典；重启即失，用户重发即可）
