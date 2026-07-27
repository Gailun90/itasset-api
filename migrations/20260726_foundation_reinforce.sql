-- ============================================================================
-- 迁移：漏洞自愈地基补强 — 状态机 + 回滚 + 版本化 + 熔断
-- 对应模型：app/models/vuln.py, app/models/models.py
-- 适用：PostgreSQL（生产）。本地 SQLite 测试由 create_all 自动建表，无需本脚本。
-- ============================================================================

DO $$
DECLARE
    _rule RECORD;
    _ver_id INT;
    _existing_version INT;
BEGIN
    -- ═══════════════════════════════════════════════════════════════════════
    -- 1) task_targets 新增字段
    -- ═══════════════════════════════════════════════════════════════════════
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'task_targets' AND column_name = 'timeout_at'
    ) THEN
        ALTER TABLE task_targets
            ADD COLUMN timeout_at TIMESTAMPTZ;
        RAISE NOTICE 'added task_targets.timeout_at';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'task_targets' AND column_name = 'executor_version'
    ) THEN
        ALTER TABLE task_targets
            ADD COLUMN executor_version VARCHAR(32);
        RAISE NOTICE 'added task_targets.executor_version';
    END IF;

    -- ═══════════════════════════════════════════════════════════════════════
    -- 2) remediation_tasks 新增字段
    -- ═══════════════════════════════════════════════════════════════════════
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_tasks' AND column_name = 'rollback_plan'
    ) THEN
        ALTER TABLE remediation_tasks
            ADD COLUMN rollback_plan JSONB;
        RAISE NOTICE 'added remediation_tasks.rollback_plan';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_tasks' AND column_name = 'rule_version_id'
    ) THEN
        ALTER TABLE remediation_tasks
            ADD COLUMN rule_version_id INTEGER;
        RAISE NOTICE 'added remediation_tasks.rule_version_id';
    END IF;

    -- ═══════════════════════════════════════════════════════════════════════
    -- 3) remediation_rules 新增字段
    -- ═══════════════════════════════════════════════════════════════════════
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_rules' AND column_name = 'rollback_plan'
    ) THEN
        ALTER TABLE remediation_rules
            ADD COLUMN rollback_plan JSONB;
        RAISE NOTICE 'added remediation_rules.rollback_plan';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_rules' AND column_name = 'current_version_id'
    ) THEN
        ALTER TABLE remediation_rules
            ADD COLUMN current_version_id INTEGER;
        RAISE NOTICE 'added remediation_rules.current_version_id';
    END IF;

    -- ═══════════════════════════════════════════════════════════════════════
    -- 4) 新建 rule_versions 表
    -- ═══════════════════════════════════════════════════════════════════════
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'rule_versions'
    ) THEN
        CREATE TABLE rule_versions (
            id                 SERIAL PRIMARY KEY,
            rule_id            INTEGER NOT NULL REFERENCES remediation_rules(id) ON DELETE CASCADE,
            version            INTEGER NOT NULL DEFAULT 1,
            action_template    JSONB,
            rollback_plan      JSONB,
            fix_type           VARCHAR(32) NOT NULL,
            default_risk_level VARCHAR(8)  NOT NULL DEFAULT 'medium',
            status             VARCHAR(16) NOT NULL DEFAULT 'active',
            source             VARCHAR(16) NOT NULL DEFAULT 'manual',
            notes              TEXT,
            created_by         VARCHAR(255),
            approved_by        VARCHAR(255),
            deprecated         BOOLEAN NOT NULL DEFAULT FALSE,
            created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX ix_rule_versions_rule_id ON rule_versions(rule_id);
        CREATE UNIQUE INDEX ix_rule_versions_rule_version ON rule_versions(rule_id, version);
        RAISE NOTICE 'created table rule_versions';
    END IF;

    -- ═══════════════════════════════════════════════════════════════════════
    -- 5) 存量 remediation_rules → 各生成一条 version=1 的 rule_versions 记录
    --    处理策略：
    --    - source=manual 且 status=active：approved_by 填占位值 'system:migration'
    --    - source=llm 且 status=active：approved_by=NULL（表示 LLM 生成但无人类确认）
    --    - source=llm 且 status=draft：approved_by=NULL（草稿尚未转正）
    --    - status=disabled 的规则同样写入 version=1，deprecated=TRUE
    -- ═══════════════════════════════════════════════════════════════════════
    FOR _rule IN
        SELECT * FROM remediation_rules
        WHERE current_version_id IS NULL
    LOOP
        -- 查该规则是否已有 version 记录（幂等）
        SELECT id INTO _ver_id FROM rule_versions
        WHERE rule_id = _rule.id AND version = 1
        LIMIT 1;

        IF _ver_id IS NULL THEN
            INSERT INTO rule_versions (
                rule_id, version, action_template, rollback_plan,
                fix_type, default_risk_level, status, source, notes,
                created_by, approved_by, deprecated, created_at
            ) VALUES (
                _rule.id, 1, _rule.action_template, _rule.rollback_plan,
                _rule.fix_type, _rule.default_risk_level,
                _rule.status, _rule.source, _rule.notes,
                NULL,   -- created_by: 存量无法追溯是谁创建的
                CASE
                    WHEN _rule.source = 'manual' THEN 'system:migration'
                    WHEN _rule.source = 'llm' AND _rule.status = 'active' THEN NULL
                    WHEN _rule.source = 'llm' AND _rule.status = 'draft' THEN NULL
                    ELSE NULL
                END,
                CASE WHEN _rule.status = 'disabled' THEN TRUE ELSE FALSE END,
                _rule.created_at
            )
            RETURNING id INTO _ver_id;

            -- 更新主表的 current_version_id 指向新创建的 version 记录
            UPDATE remediation_rules
            SET current_version_id = _ver_id
            WHERE id = _rule.id;
        END IF;
    END LOOP;

    -- ═══════════════════════════════════════════════════════════════════════
    -- 6) 新建 autonomy_policy 表 + 插入默认行
    -- ═══════════════════════════════════════════════════════════════════════
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'autonomy_policy'
    ) THEN
        CREATE TABLE autonomy_policy (
            id          SERIAL PRIMARY KEY,
            kill_switch BOOLEAN NOT NULL DEFAULT FALSE,
            updated_by  VARCHAR(255),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        -- 插入默认行（kill_switch=false，熔断关闭）
        INSERT INTO autonomy_policy (kill_switch) VALUES (FALSE);
        RAISE NOTICE 'created table autonomy_policy with default row';
    END IF;

END $$;
