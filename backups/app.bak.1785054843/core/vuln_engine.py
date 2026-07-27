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
# 不可逆操作类型（software_uninstall 卸载了就没了，service_config 改了服务可能
# 导致业务中断；registry_fix 天然可逆，不在此列）
# 注：service_config 当前不在 FIX_TYPES 常量中，此处仅为预留。
IRREVERSIBLE_FIX_TYPES = ("software_uninstall", "service_config")
AUTO_DISPATCH_FIX_TYPES = ("registry_fix", "software_uninstall",
                           "software_upgrade", "patch_install")


def gate_reason(
    fix_type: str,
    asset_id: Optional[int],
    risk_level: str,
    for_auto: bool,
    rule_status: Optional[str] = None,            # RemediationRule.status
    rule_rollback_plan: Optional[dict] = None,     # RemediationRule.rollback_plan
    task_rollback_plan: Optional[dict] = None,     # RemediationTask.rollback_plan
    matched_package_id: Optional[int] = None,      # software_upgrade 专属
) -> str | None:
    """
    下发门禁（三道闸 + 回滚方案硬闸门）。返回 None 表示允许下发，否则返回阻止原因：

      闸1·规则转正：规则必须存在且为 active（人工已确认）。
           draft / 无规则 = 纯 LLM 猜测，禁止自动下发——需人工先在 QID 规则库转正；
      闸2·高风险：for_auto=True（随批准自动下发）时 high 风险不下发，
           需另一次显式「确认下发」动作；
      闸3·回滚方案：不可逆操作（software_uninstall / service_config）
           必须有 rollback_plan，否则禁止自动下发（安全底线，前端不可绕过）。
    """
    if fix_type not in AUTO_DISPATCH_FIX_TYPES:
        return f"fix_type={fix_type} 不支持自动下发"
    if asset_id is None:
        return "未匹配资产，无法下发"
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

    # 支持多 ops 列表格式
    op_list = vs.get("ops") if isinstance(vs, dict) else None
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
