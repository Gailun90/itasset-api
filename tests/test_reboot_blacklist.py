"""
P0 安全测试：禁止重启/关机关键词黑名单

测试生产代码 app.core.vuln_engine 中的：
  - REBOOT_BLACKLIST 正则（直接导）
  - scan_reboot_blacklist() 函数（直接调用）
  - build_patch_install_script() 产出脚本（直接调用）

验证：
  1. 正常 patch_install 脚本能通过扫描
  2. 含 Restart-Computer -Force 的脚本被拒绝
  3. shutdown /r 被拒绝
  4. shutdown.exe 被拒绝
  5. wuauclt /restart 被拒绝
  6. 模拟绕过服务端 → 客户端独立拦截
"""
import pytest
from app.core.vuln_engine import (
    REBOOT_BLACKLIST,
    scan_reboot_blacklist,
    build_patch_install_script,
)


class TestRebootBlacklist:
    """测试重启/关机关键词黑名单 — 导入真实生产代码"""

    def test_normal_patch_install_passes(self):
        """测试1：现有 build_patch_install_script 产出必须能通过扫描"""
        script = build_patch_install_script(["KB123456"])
        assert REBOOT_BLACKLIST.search(script) is None, \
            f"正常补丁安装脚本不应命中黑名单，但命中了"

    def test_restart_computer_blocked(self):
        """测试2：含 Restart-Computer -Force 的脚本必须被拒绝"""
        hit = scan_reboot_blacklist("Restart-Computer -Force")
        assert hit is not None, "Restart-Computer 应被黑名单命中"
        assert "Restart-Computer" in hit

    def test_shutdown_r_blocked(self):
        """测试3：shutdown /r 必须被拒绝"""
        hit = scan_reboot_blacklist('cmd.exe /c "shutdown /r /t 0"')
        assert hit is not None, "shutdown 应被黑名单命中"

    def test_shutdown_exe_blocked(self):
        """测试4：shutdown.exe 必须被拒绝"""
        hit = scan_reboot_blacklist("shutdown.exe /r /t 0")
        assert hit is not None, "shutdown.exe 应被黑名单命中"

    def test_wuauclt_restart_blocked(self):
        """测试5：wuauclt /restart 必须被拒绝"""
        hit = scan_reboot_blacklist("wuauclt /restart")
        assert hit is not None, "wuauclt /restart 应被黑名单命中"

    def test_stop_computer_blocked(self):
        """测试6：Stop-Computer 必须被拒绝"""
        hit = scan_reboot_blacklist("Stop-Computer -Force")
        assert hit is not None, "Stop-Computer 应被黑名单命中"

    def test_reboot_bare_blocked(self):
        """测试7：独立 reboot 命令必须被拒绝"""
        hit = scan_reboot_blacklist("reboot")
        assert hit is not None, "reboot 应被黑名单命中"
        assert hit.lower() == "reboot"

    def test_restart_bare_blocked(self):
        """测试8：独立 restart 命令必须被拒绝"""
        hit = scan_reboot_blacklist("restart")
        assert hit is not None, "restart 应被黑名单命中"
        assert hit.lower() == "restart"

    def test_normal_commands_pass(self):
        """测试9：正常命令不应该被黑名单误杀"""
        safe_commands = [
            "powershell -Command Get-Service",
            "net stop wuauserv",
            "net start wuauserv",
            "echo hello world",
            'Write-Output "System is healthy"',
            "Get-Process",
            "msiexec /i package.msi /quiet",
        ]
        for cmd in safe_commands:
            assert scan_reboot_blacklist(cmd) is None, \
                f"安全命令不应命中黑名单: {cmd}"

    def test_case_insensitive(self):
        """测试10：大小写不敏感"""
        variants = [
            "RESTART-COMPUTER -FORCE",
            "SHUTDOWN /r",
            "ShutDown /r",
            "Restart-Computer",
            "Reboot",
        ]
        for v in variants:
            assert scan_reboot_blacklist(v) is not None, \
                f"大小写变体应被命中: {v}"

    def test_allow_restart_not_blocked(self):
        """测试11：AllowRestart（合法COM属性）不应被误杀"""
        safe = "$installer.AllowRestart = $false"
        assert scan_reboot_blacklist(safe) is None, \
            "AllowRestart 是合法COM属性，不应被黑名单误杀"

    def test_reboot_required_not_blocked(self):
        """测试12：RebootRequired（合法属性/变量名）不应被误杀"""
        safe_variants = [
            "Write-Output 'PATCH_REBOOT_REQUIRED=YES'",
            "$rebootRequired = $true",
            "$sysInfo.RebootRequired",
            "HKLM:\\...\\RebootRequired",
        ]
        for s in safe_variants:
            assert scan_reboot_blacklist(s) is None, \
                f"RebootRequired/rebootRequired 为合法变量名，不应被误杀: {s}"

    def test_client_side_independent_check(self):
        """
        测试13：模拟「服务端没拦住」的场景 — 构造一条包含重启命令的脚本，
        验证 scan_reboot_blacklist 能独立拦截。
        （此场景对应服务端某条路径漏扫但客户端独立扫描兜底）
        """
        bypass_script = "# 假设此脚本绕过了服务端扫描\nRestart-Computer -Force"
        hit = scan_reboot_blacklist(bypass_script)
        assert hit is not None, \
            "客户端必须独立拦截 — 即使脚本「绕过了服务端」，客户端也必须拦下 Restart-Computer"
        assert "Restart-Computer" in hit


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
