"""
漏洞自愈引擎 — 纯逻辑函数（无 FastAPI / 数据库依赖，可直接单测）

本模块提供：
  - REBOOT_BLACKLIST / scan_reboot_blacklist：重启/关机关键词黑名单
  - can_transition / CAN_TRANSITION：状态机跃迁表
  - gate_reason：下发门禁（纯参数版，不依赖 ORM 对象）
  - build_registry_rollback_plan：从 verify_snapshot 自动生成 registry_fix 回滚方案
  - build_patch_install_script：生成 Windows Update 触发脚本（测试用产出参考）
"""
from __future__ import annotations
import json
import re
from typing import Optional

# ── P0 安全：禁止重启/关机关键词黑名单 ──────────────────────────────────────
# 覆盖 PowerShell cmdlet、CMD 命令、exe 可执行文件名、Windows Update 强制重启参数
# 注意：Restart-Computer / Stop-Computer 必须在 \brestart\b 前面，
#       否则 bare restart 会先捕获 Restart-Computer 中的 restart 前缀
REBOOT_BLACKLIST = re.compile(
    r'Restart-Computer|Stop-Computer'
    r'|wuauclt\s+/restart'
    r'|shutdown\.exe'
    r'|\bshutdown\b'
    r'|\breboot\b'
    r'|\brestart\b',
    re.IGNORECASE
)


def scan_reboot_blacklist(command_text: str) -> str | None:
    """扫描命令内容，若命中重启/关机黑名单则返回匹配到的关键词；否则返回 None。"""
    if not command_text:
        return None
    m = REBOOT_BLACKLIST.search(command_text)
    if m:
        return m.group(0)
    return None


# ── 状态机跃迁表 ────────────────────────────────────────────────────────────
CAN_TRANSITION: dict[str, tuple[str, ...]] = {
    "pending":          ("approved", "rejected", "needs_manual"),
    "approved":         ("dispatched",),
    "dispatched":       ("done", "failed", "pending_verify"),
    "pending_verify":   ("done", "rollback_required"),
    "rollback_required": ("done",),
}


def can_transition(cur: str, nxt: str) -> bool:
    """检查 RemediationTask 状态跃迁是否合法。"""
    return nxt in CAN_TRANSITION.get(cur, ())


# ── 下发门禁（纯参数版）────────────────────────────────────────────────────
# 不可逆操作类型：software_uninstall 卸载了就没了，必须配 rollback_plan 才允许自动下发。
# 注：registry_fix 天然可逆（有 before 快照可回滚），不在此列；
#     service_config 之类未来若纳入 FIX_TYPES，再显式加入本元组即可。
IRREVERSIBLE_FIX_TYPES = ("software_uninstall",)
AUTO_DISPATCH_FIX_TYPES = ("registry_fix", "software_uninstall",
                           "software_upgrade", "patch_install")

# ── 自动下发排除角色 ──────────────────────────────────────────────────────────
# 属于这些角色的资产即使命中 active 规则也不走自动下发，必须人工「确认下发」。
# 这是「最终形态·二」的细粒度分组闸门：域控 / 数据库 / 关键业务服务器等
# 不允许被自动修复脚本无值守触碰。
DEFAULT_EXCLUDED_DISPATCH_ROLES = (
    "domain_controller", "sql_server", "critical_app_server", "production_db",
)


def gate_reason(
    fix_type: str,
    asset_id: Optional[int],
    risk_level: str,
    for_auto: bool,
    rule_status: Optional[str] = None,            # RemediationRule.status
    rule_rollback_plan: Optional[dict] = None,     # RemediationRule.rollback_plan
    task_rollback_plan: Optional[dict] = None,     # RemediationTask.rollback_plan
    matched_package_id: Optional[int] = None,      # software_upgrade 专属
    asset_role: Optional[str] = None,             # 资产角色（来自 AssetProfile.role）
    excluded_roles: Optional[tuple] = None,        # 自动下发排除角色集合
) -> str | None:
    """
    下发门禁（三道闸 + 角色排除 + 回滚方案硬闸门）。返回 None 表示允许下发，否则返回阻止原因：

      闸0·角色排除：资产角色在 excluded_roles 中（如域控 / 数据库）时，
           即使规则 active 也不允许自动下发，必须人工「确认下发」；
      闸1·规则转正：规则必须存在且为 active（人工已确认）。
           draft / 无规则 = 纯 LLM 猜测，禁止自动下发——需人工先在 QID 规则库转正；
      闸2·高风险：for_auto=True（随批准自动下发）时 high 风险不下发，
           需另一次显式「确认下发」动作；
      闸3·回滚方案：不可逆操作（software_uninstall）
           必须有 rollback_plan，否则禁止自动下发（安全底线，前端不可绕过）。
    """
    if fix_type not in AUTO_DISPATCH_FIX_TYPES:
        return f"fix_type={fix_type} 不支持自动下发"
    if asset_id is None:
        return "未匹配资产，无法下发"
    # 闸0·角色排除（细粒度分组闸门，最终形态·二）
    roles = excluded_roles if excluded_roles is not None else DEFAULT_EXCLUDED_DISPATCH_ROLES
    if asset_role is not None and asset_role in roles:
        return (f"资产角色 {asset_role} 在自动下发排除列表中"
                f"（{', '.join(roles)}），需人工在管理面确认下发")
    # software_upgrade 专属前置条件
    if fix_type == "software_upgrade" and matched_package_id is None:
        return "未匹配到软件安装包，需在软件部署库关联对应安装包后点「重新匹配」"
    if rule_status is None:
        return "无关联规则（纯 LLM 现场解析），需人工先在 QID 规则库确认转正"
    if rule_status != "active":
        return f"规则为 {rule_status}（未经人工转正），需先在 QID 规则库转正"
    if for_auto and risk_level == "high":
        return "高风险任务需显式「确认下发」，不随批准自动执行"
    # 闸3·回滚方案硬闸门
    has_rp = rule_rollback_plan is not None or task_rollback_plan is not None
    if fix_type in IRREVERSIBLE_FIX_TYPES and not has_rp:
        return f"不可逆操作 fix_type={fix_type} 缺少回滚方案（rollback_plan），需先在规则库中录入回滚方案后再下发"
    return None


def build_grouping_key(qid: str, fix_type: str, risk: str,
                       ou: Optional[str], role: Optional[str],
                       maintenance_window: Optional[dict | str]) -> str:
    """
    细粒度分组键（最终形态·二）：把任务按 6 个维度归一为稳定字符串。

      分组键 = QID | fix_type | risk | OU | role | maintenance_window

    用途：金丝雀「同组同批」——同一资产画像组（同 OU / 同角色 / 同维护窗口）
    的机器进入同一小批量观察，避免把关键服务器与普通工作站混在同一金丝雀样本。
    maintenance_window 统一序列化为 JSON 字符串（dict）或原样（str），未提供则为空段。
    """
    if maintenance_window is None:
        mw = ""
    elif isinstance(maintenance_window, dict):
        # 紧凑序列化（无空格）+ 键排序，保证跨进程确定性
        mw = json.dumps(maintenance_window, sort_keys=True,
                        ensure_ascii=False, separators=(",", ":"))
    else:
        mw = str(maintenance_window)
    return "|".join([
        str(qid or ""),
        str(fix_type or ""),
        str(risk or ""),
        str(ou or ""),
        str(role or ""),
        mw,
    ])


# ── registry_fix 回滚方案自动生成 ───────────────────────────────────────────
def build_registry_rollback_plan(vs: dict) -> dict | None:
    """
    从 Agent 上报的 verify_snapshot 自动生成 registry_fix 回滚方案。

    vs 结构（多 ops 时 vs 是列表，单 ops 时可能是单个 dict）：
      { "ops": [{"before": {...}, "after": {...}}, ...] }
      或兼容旧格式：{ "before": {...}, "after": {...} }

    返回 { "type": "registry_fix", "action": {"ops": [{...}, ...]} } 或 None。
    """
    if not isinstance(vs, dict):
        return None

    # 支持多 ops 列表格式（前面已确保 vs 是 dict）
    op_list = vs.get("ops")
    if op_list and isinstance(op_list, list):
        snapshots = op_list
    else:
        # 兼容旧单条格式
        if "before" in vs:
            snapshots = [vs]
        else:
            return None

    rollback_ops = []
    for snap in snapshots:
        before = snap.get("before") if isinstance(snap, dict) else None
        if not before or not isinstance(before, dict):
            continue

        root   = before.get("root", "HKLM")
        subkey = before.get("subkey", "")
        name   = before.get("name", "")

        if not subkey:
            continue

        value = before.get("value", "")
        type_str = (before.get("type") or "").lower()
        op_type = "string"
        if "dword" in type_str:
            op_type = "dword"
        elif "qword" in type_str:
            op_type = "qword"
        elif "expand" in type_str:
            op_type = "expand"

        # 原值为空/不存在 → 回滚 = delete；否则回滚 = set 回原值
        if value == "" or value is None:
            rollback_ops.append({
                "action": "delete", "root": root, "subkey": subkey, "name": name
            })
        else:
            rollback_ops.append({
                "action": "set", "root": root, "subkey": subkey,
                "name": name, "value": value, "type": op_type,
            })

    if not rollback_ops:
        return None

    return {
        "type": "registry_fix",
        "action": {"ops": rollback_ops},
    }


# ── patch_install 脚本生成（用于测试验证黑名单不会误杀正常脚本）────────────
# ── 自动金丝雀机制（纯逻辑，可单测）────────────────────────────────────────
# 状态 / 决策常量
CANARY_STATUS_PENDING = "pending"
CANARY_STATUS_IN_PROGRESS = "in_progress"
CANARY_STATUS_VERIFIED = "verified"

CANARY_DECISION_DISPATCH = "dispatch"   # 本机在金丝雀批次内，立即下发
CANARY_DECISION_QUEUE = "queue"         # 本机排队等待放量（系统记着，不卡人工）

CANARY_OUTCOME_RELEASE = "release"      # 观察窗口达标 → 自动放量剩余机器
CANARY_OUTCOME_PAUSE = "pause"          # 观察窗口不达标 → 自动暂停规则


def canary_dispatch_decision(canary_status: str,
                             dispatched_in_batch: int,
                             batch_size: int) -> str:
    """决定本次命中 canary 规则的新任务是否立即下发。

    - verified：直接全量下发（不再走小批量）
    - pending / in_progress：已下发数 < batch_size → dispatch（本机进入首批）；
      否则 → queue（排队等待放量，系统自己记着，不卡人工）
    其它未知状态一律按保守处理（queue）。
    """
    if canary_status == CANARY_STATUS_VERIFIED:
        return CANARY_DECISION_DISPATCH
    if canary_status in (CANARY_STATUS_PENDING, CANARY_STATUS_IN_PROGRESS):
        if dispatched_in_batch < batch_size:
            return CANARY_DECISION_DISPATCH
        return CANARY_DECISION_QUEUE
    return CANARY_DECISION_QUEUE


def evaluate_canary_outcome(dispatched_count: int,
                            rollback_required_count: int,
                            threshold: int) -> str:
    """观察窗口结束时评估首批结果（真实代码，scheduler 直接调用）。

    threshold 表示「允许的最大回滚台数（含边界）」：
      rollback_required_count > threshold → pause（超过允许上限，自动暂停规则）
      否则 → release（在允许上限内，自动放量剩余机器）
    默认 threshold=0 即「一台都不能出问题」（任何 1 台 rollback_required 即暂停）。
    没有实际下发的样本（dispatched_count<=0）按保守处理 → pause（不放量）。
    """
    if dispatched_count <= 0:
        return CANARY_OUTCOME_PAUSE
    if rollback_required_count > threshold:
        return CANARY_OUTCOME_PAUSE
    return CANARY_OUTCOME_RELEASE


def resolve_autonomy_params(fix_type: str, risk_level: str,
                            rules: dict) -> dict:
    """按 (fix_type, risk_level) 解析金丝雀参数。

    rules: {(fix_type, risk_level): {"canary_batch_size", "canary_window_minutes",
                                      "rollback_threshold"}}
    解析顺序：(fix_type, risk_level) → (fix_type, "*") → 全局兜底默认值。
    """
    exact = (fix_type, risk_level)
    if exact in rules:
        return rules[exact]
    wildcard = (fix_type, "*")
    if wildcard in rules:
        return rules[wildcard]
    return {"canary_batch_size": 5, "canary_window_minutes": 30, "rollback_threshold": 0}


def build_patch_install_script(kb_ids: list | None = None) -> str:
    """生成 Windows Update 触发脚本（显式禁止自动重启）。"""
    kb_ids = kb_ids or []
    kb_arr = ", ".join(f"'{k}'" for k in kb_ids)
    header = "# 漏洞补丁安装（禁止自动重启） 目标KB: " + (kb_arr or "(全部适用更新)") + "\n"
    body = r'''
$ErrorActionPreference = 'SilentlyContinue'
$log = @()

# ── 方式一：PSWindowsUpdate（若已安装）──
$usePSWU = $false
if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
    $usePSWU = $true
}

if ($usePSWU) {
    $kbs = @(__KB__)
    if ($kbs.Count -gt 0) {
        Install-WindowsUpdate -KBArticleID $kbs -AcceptAll -IgnoreReboot -Verbose 2>&1 | ForEach-Object { $log += $_.ToString() }
    } else {
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -Verbose 2>&1 | ForEach-Object { $log += $_.ToString() }
    }
} else {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 AND IsHidden=0")
    if ($result.Updates.Count -gt 0) {
        $updates = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $result.Updates) {
            if ($u.EulaAccepted -eq $false) { $u.AcceptEula() }
            $updates.Add($u) | Out-Null
        }
        $installer = $session.CreateUpdateInstaller()
        try { $installer.AllowRestart = $false } catch {}
        $installer.Updates = $updates
        $installer.Install() | Out-Null
    }
}

# ── 检测「是否有更新在等待重启」（绝不执行重启）──
$rebootRequired = $false
try {
    $sysInfo = New-Object -ComObject Microsoft.Update.SystemInfo
    if ($sysInfo.RebootRequired) { $rebootRequired = $true }
} catch {}
if (-not $rebootRequired) {
    $keys = @(
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )
    foreach ($k in $keys) { if (Test-Path $k) { $rebootRequired = $true; break } }
}
if (-not $rebootRequired) {
    $pfr = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfr) { $rebootRequired = $true }
}

if ($rebootRequired) {
    Write-Output "PATCH_REBOOT_REQUIRED=YES"
    Write-Output "需要重启，未自动执行。请管理员在维护窗口内手动重启该终端。"
} else {
    Write-Output "PATCH_REBOOT_REQUIRED=NO"
}
exit 0
'''
    body = body.replace("__KB__", kb_arr)
    return header + body
