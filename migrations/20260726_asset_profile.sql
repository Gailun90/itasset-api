-- ============================================================================
-- 迁移：资产画像表 + 修复任务细粒度分组键
-- 对应「最终形态·第二节 资产画像 + 细粒度分组」
-- 幂等：可重复执行。
-- 生产执行（需用 postgres 超级用户，与之前迁移一致）：
--   psql -h 127.0.0.1 -U itasset -d itasset -f migrations/20260726_asset_profile.sql
-- ============================================================================

-- ── 1. 资产画像表 ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS asset_profiles (
    id                 BIGSERIAL PRIMARY KEY,
    client_id          INTEGER NOT NULL UNIQUE
                         REFERENCES clients(id) ON DELETE CASCADE,
    role               VARCHAR(64),
    ou                 VARCHAR(255),
    installed_software JSONB,
    business_owner     VARCHAR(255),
    criticality        VARCHAR(16) NOT NULL DEFAULT 'medium',
    maintenance_window JSONB,
    captured_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_asset_profiles_client_id ON asset_profiles (client_id);
CREATE INDEX IF NOT EXISTS ix_asset_profiles_role      ON asset_profiles (role);
CREATE INDEX IF NOT EXISTS ix_asset_profiles_ou        ON asset_profiles (ou);

-- ── 2. 修复任务增加 dispatch_group_key（金丝雀同组同批分组键）────────────────
ALTER TABLE remediation_tasks
    ADD COLUMN IF NOT EXISTS dispatch_group_key VARCHAR(255);

CREATE INDEX IF NOT EXISTS ix_remediation_tasks_group_key
    ON remediation_tasks (dispatch_group_key);

-- ── 3. 关键度合法性（应用层枚举：low/medium/high/critical）────────────────
--    不强制 CHECK 约束（保留扩展弹性），仅建立索引便于按关键度筛查询下发。
CREATE INDEX IF NOT EXISTS ix_asset_profiles_criticality
    ON asset_profiles (criticality);
