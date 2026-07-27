-- ============================================================================
-- 迁移：自动金丝雀机制（漏洞自愈最终形态 · 第五节）
-- 适用：itasset FastAPI（PostgreSQL）
-- 说明：本节是「拿掉人工首审闸门」后唯一的安全网，务必在部署新代码前执行本脚本。
--       以 postgres 超级用户执行（建 FK 需要 REFERENCES 权限），执行后对新角色 GRANT。
-- ============================================================================

-- ── 1. remediation_rules 增加金丝雀字段 ─────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='remediation_rules' AND column_name='canary_status'
    ) THEN
        ALTER TABLE remediation_rules
            ADD COLUMN canary_status VARCHAR(16) NOT NULL DEFAULT 'pending';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='remediation_rules' AND column_name='canary_started_at'
    ) THEN
        ALTER TABLE remediation_rules
            ADD COLUMN canary_started_at TIMESTAMPTZ;
    END IF;
END $$;

-- 存量 active 规则视为已验证（避免对已在跑的规则重新走金丝雀观察期）；
-- draft / disabled 本就不会自动下发，置 verified 亦无副作用。
UPDATE remediation_rules SET canary_status = 'verified'
 WHERE canary_status IS DISTINCT FROM 'verified';

-- ── 2. remediation_tasks 增加金丝雀批次标记与规则外键 ───────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='remediation_tasks' AND column_name='canary_batch'
    ) THEN
        ALTER TABLE remediation_tasks
            ADD COLUMN canary_batch BOOLEAN NOT NULL DEFAULT FALSE;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='remediation_tasks' AND column_name='rule_id'
    ) THEN
        ALTER TABLE remediation_tasks
            ADD COLUMN rule_id INTEGER REFERENCES remediation_rules(id) ON DELETE SET NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_remediation_tasks_rule_id
    ON remediation_tasks (rule_id);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_canary_batch
    ON remediation_tasks (canary_batch);

-- ── 3. autonomy_rules 分级参数表 ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS autonomy_rules (
    id                     SERIAL PRIMARY KEY,
    fix_type               VARCHAR(32)  NOT NULL,
    risk_level             VARCHAR(8)   NOT NULL DEFAULT '*',
    canary_batch_size      INTEGER       NOT NULL DEFAULT 5,
    canary_window_minutes  INTEGER       NOT NULL DEFAULT 30,
    -- 观察窗口内 rollback_required 超过该阈值 → 自动暂停规则（默认 0 = 一台都不能出问题）
    rollback_threshold     INTEGER       NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ   NOT NULL DEFAULT now()
);

-- risk_level='*' 表示通配；resolve_autonomy_params 按 (fix_type, risk_level) → (fix_type,'*') 回退
CREATE UNIQUE INDEX IF NOT EXISTS ix_autonomy_rules_fix_risk
    ON autonomy_rules (fix_type, risk_level);

-- 种子数据：按 fix_type 配不同保守程度（数值在 spec 给定区间内取中值）
--   registry_fix   : 首批 8 台，观察 30 分钟（回滚能力最强）
--   software_upgrade: 首批 4 台，观察 60 分钟（回滚=重装，能力中等）
--   software_uninstall:首批 4 台，观察 60 分钟
--   patch_install  : 首批 2 台，观察 24 小时（无回滚概念，靠小批量+长窗口兜底）
INSERT INTO autonomy_rules (fix_type, risk_level, canary_batch_size, canary_window_minutes, rollback_threshold)
SELECT 'registry_fix',    '*', 8,  30,   0 WHERE NOT EXISTS (SELECT 1 FROM autonomy_rules WHERE fix_type='registry_fix'    AND risk_level='*');
INSERT INTO autonomy_rules (fix_type, risk_level, canary_batch_size, canary_window_minutes, rollback_threshold)
SELECT 'software_upgrade', '*', 4,  60,   0 WHERE NOT EXISTS (SELECT 1 FROM autonomy_rules WHERE fix_type='software_upgrade' AND risk_level='*');
INSERT INTO autonomy_rules (fix_type, risk_level, canary_batch_size, canary_window_minutes, rollback_threshold)
SELECT 'software_uninstall','*', 4,  60,   0 WHERE NOT EXISTS (SELECT 1 FROM autonomy_rules WHERE fix_type='software_uninstall' AND risk_level='*');
INSERT INTO autonomy_rules (fix_type, risk_level, canary_batch_size, canary_window_minutes, rollback_threshold)
SELECT 'patch_install',    '*', 2,  1440, 0 WHERE NOT EXISTS (SELECT 1 FROM autonomy_rules WHERE fix_type='patch_install'    AND risk_level='*');
