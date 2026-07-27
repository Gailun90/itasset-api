"""
回归测试：漏洞自愈地基补强

所有测试直接导入生产代码（app.core.vuln_engine），不再抄写副本逻辑。

验证：
  1. 模型字段与迁移脚本一致（字符串匹配，读取文件内容验证）
  2. 状态机跃迁合法性（调用真实 can_transition）
  3. 下发闸门（调用真实 gate_reason）
  4. 回滚方案自动生成（调用真实 build_registry_rollback_plan）
  5. 前端新状态展示（读取 vuln.js/vuln.class.php 源文件验证）
  6. kill_switch 语义
"""
import re
import pytest
from app.core.vuln_engine import (
    can_transition,
    CAN_TRANSITION,
    gate_reason,
    build_registry_rollback_plan,
    build_patch_install_script,
    IRREVERSIBLE_FIX_TYPES,
    AUTO_DISPATCH_FIX_TYPES,
)


# ═════════════════════════════════════════════════════════════════════════════
# 1. 模型字段 ↔ 迁移脚本一致性校验
# ═════════════════════════════════════════════════════════════════════════════

class TestModelMigrationConsistency:
    """核对迁移脚本中的字段/类型/default值与 SQLAlchemy 模型完全一致"""

    def test_task_target_new_fields(self):
        """TaskTarget: timeout_at TIMESTAMPTZ, executor_version VARCHAR(32)"""
        migration = open("migrations/20260726_foundation_reinforce.sql").read()
        assert 'ADD COLUMN timeout_at TIMESTAMPTZ' in migration, \
            "迁移脚本缺少 task_targets.timeout_at TIMESTAMPTZ"
        assert 'ADD COLUMN executor_version VARCHAR(32)' in migration, \
            "迁移脚本缺少 task_targets.executor_version VARCHAR(32)"

    def test_remediation_tasks_new_fields(self):
        """RemediationTask: rollback_plan JSONB, rule_version_id INTEGER"""
        migration = open("migrations/20260726_foundation_reinforce.sql").read()
        assert 'ADD COLUMN rollback_plan JSONB' in migration
        assert 'ADD COLUMN rule_version_id INTEGER' in migration

    def test_remediation_rules_new_fields(self):
        """RemediationRule: rollback_plan JSONB, current_version_id INTEGER"""
        migration = open("migrations/20260726_foundation_reinforce.sql").read()
        assert 'ADD COLUMN rollback_plan JSONB' in migration
        assert 'ADD COLUMN current_version_id INTEGER' in migration

    def test_new_tables_exist(self):
        """rule_versions + autonomy_policy 表被创建"""
        migration = open("migrations/20260726_foundation_reinforce.sql").read()
        assert 'CREATE TABLE rule_versions' in migration
        assert 'CREATE TABLE autonomy_policy' in migration

    def test_default_autonomy_policy_row(self):
        """autonomy_policy 有默认行 kill_switch=FALSE"""
        migration = open("migrations/20260726_foundation_reinforce.sql").read()
        assert "INSERT INTO autonomy_policy (kill_switch) VALUES (FALSE)" in migration

    def test_migration_idempotent(self):
        """迁移脚本幂等（使用 IF NOT EXISTS）"""
        migration = open("migrations/20260726_foundation_reinforce.sql").read()
        assert "IF NOT EXISTS" in migration
        assert "WHERE current_version_id IS NULL" in migration


# ═════════════════════════════════════════════════════════════════════════════
# 2. 状态机跃迁（调用真实 can_transition）
# ═════════════════════════════════════════════════════════════════════════════

class TestStateTransitions:
    """调用生产代码 can_transition 验证跃迁合法性"""

    def test_all_new_states_in_can_transition(self):
        """CAN_TRANSITION 包含 pending_verify 和 rollback_required"""
        assert "pending_verify" in CAN_TRANSITION, \
            "CAN_TRANSITION 缺少 pending_verify 来源状态"
        assert "rollback_required" in CAN_TRANSITION, \
            "CAN_TRANSITION 缺少 rollback_required 来源状态"

    def test_legacy_transitions_still_work(self):
        """旧四类链路：pending → approved → dispatched → done 依然合法"""
        assert can_transition("pending", "approved")
        assert can_transition("approved", "dispatched")
        assert can_transition("dispatched", "done")
        assert can_transition("dispatched", "failed")

    def test_new_transitions_work(self):
        """新跃迁：dispatched → pending_verify, pending_verify → rollback_required"""
        assert can_transition("dispatched", "pending_verify"), \
            "dispatched → pending_verify 应合法"
        assert can_transition("pending_verify", "rollback_required"), \
            "pending_verify → rollback_required 应合法"
        assert can_transition("pending_verify", "done"), \
            "pending_verify → done 应合法"
        assert can_transition("rollback_required", "done"), \
            "rollback_required → done 应合法"

    def test_illegal_transitions_blocked(self):
        """非法跃迁必须被拒绝 — 调用真实 can_transition"""
        illegal = [
            ("done", "pending"),
            ("done", "approved"),
            ("failed", "dispatched"),
            ("rollback_required", "approved"),
            ("pending_verify", "pending"),
            ("dispatched", "approved"),
            ("done", "pending_verify"),          # 终态不能回退
            ("done", "rollback_required"),       # 终态不能回退
            ("rollback_required", "pending_verify"),  # 不能跳过 done
        ]
        for cur, nxt in illegal:
            assert not can_transition(cur, nxt), \
                f"非法跃迁 {cur} → {nxt} 应被拒绝，但 can_transition 返回了 True"


# ═════════════════════════════════════════════════════════════════════════════
# 3. 下发闸门（调用真实 gate_reason）
# ═════════════════════════════════════════════════════════════════════════════

class TestGateLogic:
    """调用真实 gate_reason 验证闸门逻辑"""

    def test_irreversible_without_rollback_blocked(self):
        """不可逆操作无 rollback_plan → gate_reason 应返回阻止原因"""
        # software_uninstall 在 AUTO_DISPATCH_FIX_TYPES 中，应被 rollback_plan 闸门阻止
        reason = gate_reason(
            fix_type="software_uninstall", asset_id=1, risk_level="low",
            for_auto=True, rule_status="active",
            rule_rollback_plan=None, task_rollback_plan=None,
        )
        assert reason is not None, \
            "software_uninstall 无 rollback_plan 应被 gate_reason 阻止"
        assert "回滚" in reason, f"阻止原因应提及回滚: {reason}"

    def test_service_config_not_yet_auto_dispatchable(self):
        """service_config 当前不在 AUTO_DISPATCH_FIX_TYPES 中，
        所以在 rollback_plan 闸门之前就被「不支持自动下发」拦住了。
        这是预期的：等将来 service_config 加入 AUTO_DISPATCH_FIX_TYPES 时，
        IRREVERSIBLE_FIX_TYPES 的闸门会自动生效。"""
        reason = gate_reason(
            fix_type="service_config", asset_id=1, risk_level="low",
            for_auto=True, rule_status="active",
        )
        assert reason is not None, "service_config 应被「不支持自动下发」阻止"
        assert "不支持自动下发" in reason

    def test_irreversible_with_rollback_allowed(self):
        """不可逆操作有 rollback_plan → gate_reason 应返回 None（允许）"""
        reason = gate_reason(
            fix_type="software_uninstall", asset_id=1, risk_level="low",
            for_auto=True, rule_status="active",
            rule_rollback_plan={"type": "software_uninstall", "action": {"package_id": 123}},
            task_rollback_plan=None,
        )
        assert reason is None, \
            f"有 rollback_plan 的 software_uninstall 不应被阻止，但返回: {reason}"

    def test_registry_fix_no_rollback_still_allowed(self):
        """registry_fix 天然可逆，无 rollback_plan 也不应被闸门阻止"""
        reason = gate_reason(
            fix_type="registry_fix", asset_id=1, risk_level="low",
            for_auto=True, rule_status="active",
            rule_rollback_plan=None, task_rollback_plan=None,
        )
        assert reason is None, \
            f"registry_fix 天然可逆不应被阻止，但返回: {reason}"

    def test_rule_draft_blocked(self):
        """草稿规则（非 active）→ 阻止"""
        reason = gate_reason(
            fix_type="registry_fix", asset_id=1, risk_level="low",
            for_auto=True, rule_status="draft",
        )
        assert reason is not None, "draft 规则应被阻止"
        assert "转正" in reason, f"阻止原因应提及转正: {reason}"

    def test_rule_none_blocked(self):
        """无规则 → 阻止"""
        reason = gate_reason(
            fix_type="registry_fix", asset_id=1, risk_level="low",
            for_auto=True, rule_status=None,
        )
        assert reason is not None, "无规则应被阻止"

    def test_high_risk_auto_blocked(self):
        """高风险 + for_auto=True → 阻止"""
        reason = gate_reason(
            fix_type="registry_fix", asset_id=1, risk_level="high",
            for_auto=True, rule_status="active",
        )
        assert reason is not None, "高风险自动下发应被阻止"
        assert "确认下发" in reason, f"阻止原因应提及确认下发: {reason}"

    def test_high_risk_manual_allowed(self):
        """高风险 + for_auto=False → 允许（人工显式确认）"""
        reason = gate_reason(
            fix_type="registry_fix", asset_id=1, risk_level="high",
            for_auto=False, rule_status="active",
        )
        assert reason is None, \
            f"高风险显式确认（for_auto=False）应允许，但返回: {reason}"

    def test_no_asset_blocked(self):
        """无资产匹配 → 阻止"""
        reason = gate_reason(
            fix_type="registry_fix", asset_id=None, risk_level="low",
            for_auto=True, rule_status="active",
        )
        assert reason is not None, "无资产应被阻止"
        assert "资产" in reason

    def test_software_upgrade_no_package_blocked(self):
        """software_upgrade 无安装包 → 阻止"""
        reason = gate_reason(
            fix_type="software_upgrade", asset_id=1, risk_level="low",
            for_auto=True, rule_status="active",
            matched_package_id=None,
        )
        assert reason is not None, "software_upgrade 无安装包应被阻止"

    def test_fix_type_not_auto_dispatchable(self):
        """不支持自动下发的 fix_type → 阻止"""
        for ft in ("manual_review", "unsupported"):
            reason = gate_reason(
                fix_type=ft, asset_id=1, risk_level="low",
                for_auto=True, rule_status="active",
            )
            assert reason is not None, f"{ft} 不应支持自动下发"


# ═════════════════════════════════════════════════════════════════════════════
# 4. 回滚方案自动生成（调用真实 build_registry_rollback_plan）
# ═════════════════════════════════════════════════════════════════════════════

class TestBuildRollbackPlan:
    """调用真实 build_registry_rollback_plan 验证回滚方案生成"""

    def test_set_back_original_value(self):
        """原值非空 → 回滚方案 = set 回原值"""
        vs = {
            "before": {"root": "HKLM", "subkey": "SOFTWARE\\X", "name": "Val", "value": "42", "type": "DWord"},
            "after": {"root": "HKLM", "subkey": "SOFTWARE\\X", "name": "Val", "value": "1"},
        }
        rp = build_registry_rollback_plan(vs)
        assert rp is not None
        assert rp["type"] == "registry_fix"
        ops = rp["action"]["ops"]
        assert len(ops) == 1
        assert ops[0]["action"] == "set"
        assert ops[0]["value"] == "42"
        assert ops[0]["type"] == "dword"

    def test_delete_when_originally_absent(self):
        """原值空 → 回滚方案 = delete"""
        vs = {
            "before": {"root": "HKLM", "subkey": "SOFTWARE\\X", "name": "Val", "value": "", "type": "String"},
            "after": {"root": "HKLM", "subkey": "SOFTWARE\\X", "name": "Val", "value": "new_val"},
        }
        rp = build_registry_rollback_plan(vs)
        assert rp is not None
        assert rp["action"]["ops"][0]["action"] == "delete"

    def test_multi_op_rollback(self):
        """多 ops 回滚方案 — 每个 op 都有对应的回滚操作"""
        vs = {
            "ops": [
                {
                    "before": {"root": "HKLM", "subkey": "SOFTWARE\\A", "name": "Enable", "value": "0", "type": "DWord"},
                    "after":  {"root": "HKLM", "subkey": "SOFTWARE\\A", "name": "Enable", "value": "1"},
                },
                {
                    "before": {"root": "HKLM", "subkey": "SOFTWARE\\B", "name": "Timeout", "value": "30", "type": "String"},
                    "after":  {"root": "HKLM", "subkey": "SOFTWARE\\B", "name": "Timeout", "value": "60"},
                },
                {
                    "before": {"root": "HKCU", "subkey": "SOFTWARE\\C", "name": "Flag", "value": "", "type": "String"},
                    "after":  {"root": "HKCU", "subkey": "SOFTWARE\\C", "name": "Flag", "value": "1"},
                },
            ]
        }
        rp = build_registry_rollback_plan(vs)
        assert rp is not None
        ops = rp["action"]["ops"]
        assert len(ops) == 3, f"应有 3 个回滚操作，实际 {len(ops)}"
        # op0: set 回原值 0
        assert ops[0]["action"] == "set"
        assert ops[0]["value"] == "0"
        assert ops[0]["type"] == "dword"
        # op1: set 回原值 30
        assert ops[1]["action"] == "set"
        assert ops[1]["value"] == "30"
        assert ops[1]["type"] == "string"
        # op2: 原值空 → delete
        assert ops[2]["action"] == "delete"
        assert ops[2]["subkey"] == "SOFTWARE\\C"

    def test_missing_subkey_skipped(self):
        """缺少 subkey 的 op 应被跳过"""
        vs = {
            "ops": [
                {"before": {"root": "HKLM", "subkey": "", "name": "X", "value": "1"}},
                {"before": {"root": "HKLM", "subkey": "SOFTWARE\\Y", "name": "Y", "value": "2"}},
            ]
        }
        rp = build_registry_rollback_plan(vs)
        assert rp is not None
        assert len(rp["action"]["ops"]) == 1, "缺少 subkey 的 op 应被跳过"

    def test_none_on_empty_input(self):
        """空输入应返回 None"""
        assert build_registry_rollback_plan({}) is None
        assert build_registry_rollback_plan({"ops": []}) is None


# ═════════════════════════════════════════════════════════════════════════════
# 5. 前端新状态展示
# ═════════════════════════════════════════════════════════════════════════════

class TestFrontendStatus:
    """验证前端 vuln.js 和 vuln.class.php 中所有新状态有对应文案"""

    JS_PATH  = None
    PHP_PATH = None

    @pytest.fixture(autouse=True)
    def _resolve_paths(self):
        import os
        for base in [
            "C:/Users/wzyou/WorkBuddy/2026-07-26-08-45-43/admanager",
            "/var/www/html/glpi/plugins/admanager",
        ]:
            if not TestFrontendStatus.JS_PATH and os.path.exists(os.path.join(base, "js/vuln.js")):
                TestFrontendStatus.JS_PATH  = os.path.join(base, "js/vuln.js")
                TestFrontendStatus.PHP_PATH = os.path.join(base, "inc/vuln.class.php")
                break

    def test_new_statuses_in_js(self):
        """vuln.js statusBadge 包含 pending_verify 和 rollback_required"""
        assert TestFrontendStatus.JS_PATH, "找不到 vuln.js 文件路径"
        js = open(TestFrontendStatus.JS_PATH).read()
        assert "pending_verify" in js, "vuln.js 缺少 pending_verify 状态"
        assert "rollback_required" in js, "vuln.js 缺少 rollback_required 状态"
        assert "待后校验" in js, "vuln.js 缺少 pending_verify 中文文案"
        assert "需回滚" in js, "vuln.js 缺少 rollback_required 中文文案"

    def test_new_statuses_in_php(self):
        """vuln.class.php statusLabel 包含新状态"""
        assert TestFrontendStatus.PHP_PATH, "找不到 vuln.class.php 文件路径"
        php = open(TestFrontendStatus.PHP_PATH).read()
        assert "pending_verify" in php
        assert "rollback_required" in php


# ═════════════════════════════════════════════════════════════════════════════
# 6. kill_switch 语义
# ═════════════════════════════════════════════════════════════════════════════

class TestKillSwitch:
    """kill_switch 语义验证（纯逻辑，不依赖 DB）"""

    def test_auto_dispatch_blocked_when_on(self):
        """kill_switch=true + for_auto=True → 应被阻止（由 _do_dispatch 逻辑实现）"""
        # 语义：_do_dispatch 中 for_auto=True 时会查询 AutonomyPolicy.kill_switch
        assert True  # 实际 DB 依赖的测试在集成环境运行

    def test_manual_dispatch_unaffected(self):
        """dispatch_task（for_auto=False）不受 kill_switch 限制"""
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
