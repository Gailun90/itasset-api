-- 每规则自动下发排除角色（最终形态·二细化）
-- 在全局 DEFAULT_EXCLUDED_DISPATCH_ROLES 之外，规则可追加自身禁发的角色；
-- 下发门禁取「全局 ∪ 规则级」的并集。NULL = 不追加（仅用全局默认）。
ALTER TABLE remediation_rules ADD COLUMN IF NOT EXISTS excluded_roles JSONB;
