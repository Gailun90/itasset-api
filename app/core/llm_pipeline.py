"""
最终形态·四：LLM 处理管线核心（Action Validator + 接地）与 最终形态·三：对话式纠正闭环

本模块是「无规则 → LLM 规划 → Action 校验 → 策略引擎落库」管线的纯逻辑内核：

1. validate_action()  —— Action Validator（P0 安全闸门）
   对 LLM / 规则生成的修复动作做结构化校验与归一化：
     - fix_type 合法性（必须在 FIX_TYPES）
     - registry_fix：changes 数组逐项归一（root/subkey/name/value/type/action）
     - patch_install：生成的补丁脚本必须经过重启/关机关键词黑名单扫描（命中即拦截）
     - software_upgrade / software_uninstall：必须给出 software 名称
     - EOL / 停止支持：强制兜底为 manual_review + high（不允许自动修复）
   返回 ActionValidationResult(ok, reason, fix_type, action, risk_override, requires_reboot)，
   上游据此决定落库为 draft 规则还是转人工。

2. lookup_correction() / record_correction() —— 对话式纠正闭环（最终形态·三）
   基于 Correction 表的精确匹配键（match_key）做「即时纠偏缓存」：
     - 解析阶段命中已有纠正 → 直接复用人类纠正后的正确动作，不再盲信 LLM；
     - 人类在管理面纠正某任务并确认 → 记录纠正，必要时沉淀为正式规则（source=manual）。

3. ground_prompt_with_samples() —— 少样本接地
   把 app.data.qid_samples 里与当前 QID/标题相近的真实样本拼进 LLM 提示，
   提升规划器产出结构规范 action_json 的命中率。

所有函数均为纯逻辑或可单测（lookup/record 仅需一个 async session，可用内存 SQLite 验证）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select

from app.core.vuln_engine import (
    scan_reboot_blacklist,
    build_patch_install_script,
)
from app.models.vuln import FIX_TYPES, Correction

# ── 值类型映射（LLM/规则输出 → 客户端 RegistryOp.type）────────────────────────
_VTYPE_MAP = {
    "REG_SZ": "string", "REG_EXPAND_SZ": "expand",
    "REG_DWORD": "dword", "REG_QWORD": "qword",
    "REG_BINARY": "binary", "REG_MULTI_SZ": "string",
    "DWORD": "dword", "QWORD": "qword", "SZ": "string", "EXPAND_SZ": "expand",
}

# ── EOL / 停止支持关键词（与 vuln_service 保持一致，本地定义避免循环导入）──────
EOL_KEYWORDS = [
    "eol", "end of life", "end-of-life", "end of support", "end-of-support",
    "obsolete", "no longer supported", "unsupported version",
]


def _is_eol(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in EOL_KEYWORDS)


def _split_registry_path(path: str) -> tuple[str, str]:
    """'HKLM\\SOFTWARE\\X' / 'HKEY_LOCAL_MACHINE\\SOFTWARE\\X' → ('HKLM', 'SOFTWARE\\X')"""
    p = (path or "").strip().strip("\\")
    root, _, sub = p.partition("\\")
    root_map = {
        "HKLM": "HKLM", "HKEY_LOCAL_MACHINE": "HKLM",
        "HKCU": "HKCU", "HKEY_CURRENT_USER": "HKCU",
    }
    return root_map.get(root.upper(), "HKLM"), sub


def _norm_registry_op(ch: dict) -> dict:
    """归一化单个 registry 变更项为客户端可消费的 ops 结构。

    兼容两种输入：
      - changes 数组格式：path 不含 hive，由显式 hive 字段拼接（HKLM\\...）；
      - 旧单键格式：registry_path 已含 hive 前缀（HKLM\\SOFTWARE\\X），直接拆分。
    """
    cp = (ch.get("path") or "").strip().strip("\\")
    if cp.upper().startswith(("HKLM", "HKCU", "HKEY")):
        # path 已含 hive 前缀（旧单键格式）
        root, subkey = _split_registry_path(cp)
    else:
        hive = (ch.get("hive") or "HKLM").strip()
        root, subkey = _split_registry_path(f"{hive}\\{cp}" if cp else hive)
    if not subkey:
        # 缺子键：返回原样由上层判非法
        return {"_error": "path 缺少子键", "raw": ch}
    vtype = _VTYPE_MAP.get((ch.get("type") or "REG_SZ").upper(), "string")
    raw = ch.get("data")
    val = "" if raw is None else (raw if isinstance(raw, int) else str(raw))
    act = (ch.get("action") or "set").lower()
    return {
        "action": act,
        "root": root,
        "subkey": subkey,
        "name": ch.get("value") or ch.get("value_name") or "",
        "value": "" if act == "delete" else val,
        "type": vtype,
    }


@dataclass
class ActionValidationResult:
    ok: bool
    reason: Optional[str]
    fix_type: str
    action: dict
    risk_override: Optional[str] = None      # 校验后强制的风险等级（如 EOL→high）
    requires_reboot: bool = False


def validate_action(
    fix_type: str,
    action: Optional[dict],
    *,
    qid: str = "",
    title: str = "",
    solution: str = "",
    results: str = "",
) -> ActionValidationResult:
    """
    Action Validator：结构化校验 + 归一化 LLM/规则产出的修复动作。

    返回 ok=False 时 reason 给出拦截原因（上游应转 manual_review 或拒绝落库）。
    ok=True 时 action 已是归一化后的结构，可直接用于落库 / 下发。
    """
    action = dict(action or {})
    text = f"{title} {solution} {results}"

    # 1) fix_type 合法性
    if fix_type not in FIX_TYPES:
        return ActionValidationResult(
            False, f"非法 fix_type: {fix_type}（必须在 {FIX_TYPES}）", fix_type, action)

    # 2) EOL / 停止支持 → 强制人工评审 + high（不允许任何自动修复动作）
    if _is_eol(text):
        mr = {
            "reason": "检测到 EOL / 停止支持，需业务负责人确认处置方式（不允许自动修复）",
            "description": (title or "")[:200],
        }
        return ActionValidationResult(
            True, None, "manual_review", mr, risk_override="high")

    # 3) 按类型结构校验 + 归一化
    if fix_type == "registry_fix":
        changes = action.get("changes") or []
        if not changes:
            # 兼容旧单键格式
            path = action.get("registry_path") or ""
            if not path:
                return ActionValidationResult(
                    False, "registry_fix 缺少 changes 数组或 registry_path", fix_type, action)
            ops = [_norm_registry_op({
                "hive": "HKLM",
                "path": path,
                "value": action.get("value_name") or "",
                "type": action.get("value_type") or "REG_SZ",
                "data": action.get("value_data"),
                "action": "set",
            })]
        else:
            ops = []
            for ch in changes:
                op = _norm_registry_op(ch)
                if op.get("_error"):
                    return ActionValidationResult(
                        False, f"registry_fix changes 中某项非法：{op['_error']}", fix_type, action)
                ops.append(op)
        action["changes"] = ops
        action.setdefault("requires_reboot", False)
        return ActionValidationResult(
            True, None, fix_type, action,
            requires_reboot=bool(action["requires_reboot"]))

    if fix_type in ("software_upgrade", "software_uninstall"):
        if not action.get("software"):
            return ActionValidationResult(
                False, f"{fix_type} 缺少 software 名称", fix_type, action)
        return ActionValidationResult(True, None, fix_type, action)

    if fix_type == "patch_install":
        kb_ids = action.get("kb_ids") or []
        # 生成补丁脚本并扫描重启/关机关键词（P0 安全：绝不自动重启）
        script = build_patch_install_script(kb_ids)
        hit = scan_reboot_blacklist(script)
        if hit:
            return ActionValidationResult(
                False,
                f"SECURITY_BLOCKED: 生成的补丁安装脚本命中禁止的重启/关机关键词: {hit}",
                fix_type, action)
        action.setdefault("requires_reboot", False)
        return ActionValidationResult(True, None, fix_type, action)

    if fix_type in ("manual_review", "unsupported"):
        action.setdefault("reason", (title or "")[:200])
        return ActionValidationResult(True, None, fix_type, action)

    # 兜底（理论上不会到这，因为前面已校验 fix_type ∈ FIX_TYPES）
    return ActionValidationResult(True, None, fix_type, action)


# ─────────────────────────────────────────────────────────────────────────────
# 对话式纠正闭环（最终形态·三）
# ─────────────────────────────────────────────────────────────────────────────
def derive_match_fields(risk_level: str, os_name: str = "windows") -> dict:
    """
    由任务上下文派生纠正的精确匹配键（match_fields）。

    约定：默认只用风险等级 + 操作系统两个稳定维度，保证解析阶段与「纠正任务」阶段
    生成一致的 match_key。特殊场景可在 API 层显式传入更细的 match_fields 覆盖。
    """
    return {"risk": risk_level or "medium", "os": os_name or "windows"}


async def lookup_correction(
    db, qid: str, fix_type: str, match_fields: dict
) -> Optional[Correction]:
    """
    精确查找人类纠正缓存。命中则 usage_count+1（落库待 commit）。
    返回 Correction 或 None。
    """
    key = Correction.build_match_key(qid, fix_type, match_fields)
    row = (await db.execute(
        select(Correction).where(
            Correction.qid == qid,
            Correction.fix_type == fix_type,
            Correction.match_key == key,
        )
    )).scalar_one_or_none()
    if row:
        row.usage_count = (row.usage_count or 0) + 1
    return row


async def record_correction(
    db,
    *,
    qid: str,
    fix_type: str,
    match_fields: dict,
    corrected_action: dict,
    rule_id: Optional[int] = None,
    note: Optional[str] = None,
) -> Correction:
    """
    记录/更新一条人类纠正（即时纠偏缓存）。
    按 (qid, fix_type, match_key) 幂等 upsert：已存在则刷新 corrected_action/note 并 usage_count+1。
    返回 Correction 实例（已 flush，待 commit）。
    """
    key = Correction.build_match_key(qid, fix_type, match_fields)
    existing = (await db.execute(
        select(Correction).where(
            Correction.qid == qid,
            Correction.fix_type == fix_type,
            Correction.match_key == key,
        )
    )).scalar_one_or_none()
    if existing:
        existing.corrected_action = corrected_action
        existing.match_fields = match_fields
        existing.rule_id = rule_id
        existing.note = note
        existing.usage_count = (existing.usage_count or 0) + 1
        corr = existing
    else:
        corr = Correction(
            qid=qid,
            fix_type=fix_type,
            rule_id=rule_id,
            match_fields=match_fields,
            corrected_action=corrected_action,
            note=note,
            match_key=key,
            usage_count=0,
        )
        db.add(corr)
    await db.flush()
    return corr


# ─────────────────────────────────────────────────────────────────────────────
# 少样本接地（最终形态·四）
# ─────────────────────────────────────────────────────────────────────────────
def ground_prompt_with_samples(qid: str = "", title: str = "", limit: int = 4) -> str:
    """
    把相近的真实 QID 样本拼成 few-shot 示例文本，追加到 LLM 系统提示末尾，
    引导规划器产出结构规范的 action_json。
    """
    from app.data.qid_samples import find_samples
    samples = find_samples(qid=qid, title=title, limit=limit)
    if not samples:
        return ""
    lines = ["\n\n# 参考样本（仅供格式与取值参考，最终以扫描结果为准，禁止凭空编造 KB/键值）"]
    for s in samples:
        lines.append(
            f"- QID {s['qid']}（{s['title_hint']}）→ {s['fix_type']}："
            f"{s['action']!r}"
        )
    return "\n".join(lines)
