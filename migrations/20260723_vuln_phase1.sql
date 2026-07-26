-- ============================================================================
-- 漏洞扫描 AI 辅助修复 — 第一阶段数据层迁移脚本（PostgreSQL）
-- 目标库：itasset（DATABASE_URL=postgresql+asyncpg://itasset:...@localhost:5432/itasset）
-- 执行方式（服务器上）：
--   sudo -u postgres psql -d itasset -f 20260723_vuln_phase1.sql
-- 说明：
--   itasset 当前无 Alembic，靠 lifespan create_all 自动建表；
--   本脚本与 app/models/vuln.py 等价，供 DBA 手工执行/审计用，幂等（IF NOT EXISTS）。
-- ============================================================================

BEGIN;

-- 1. 上传批次
CREATE TABLE IF NOT EXISTS vuln_scan_imports (
    id              SERIAL PRIMARY KEY,
    filename        VARCHAR(255) NOT NULL,
    uploaded_by     VARCHAR(255),
    uploaded_at     TIMESTAMPTZ DEFAULT now(),
    row_count       INTEGER DEFAULT 0,
    processed_count INTEGER DEFAULT 0,
    status          VARCHAR(16) DEFAULT 'pending',   -- pending|parsing|completed|failed
    error_message   TEXT
);
CREATE INDEX IF NOT EXISTS ix_vuln_scan_imports_status ON vuln_scan_imports (status);

-- 2. 原始漏洞行
CREATE TABLE IF NOT EXISTS vuln_findings (
    id               SERIAL PRIMARY KEY,
    import_id        INTEGER NOT NULL REFERENCES vuln_scan_imports(id) ON DELETE CASCADE,
    ip               VARCHAR(45),
    dns_name         VARCHAR(255),
    qid              VARCHAR(32) NOT NULL,
    title            TEXT,
    results_raw      TEXT,
    solution_raw     TEXT,
    asset_id         INTEGER REFERENCES clients(id) ON DELETE SET NULL,
    match_confidence VARCHAR(16) DEFAULT 'unmatched',  -- exact_hostname|exact_ip|fuzzy|unmatched
    created_at       TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_vuln_findings_import_id ON vuln_findings (import_id);
CREATE INDEX IF NOT EXISTS ix_vuln_findings_qid       ON vuln_findings (qid);
CREATE INDEX IF NOT EXISTS ix_vuln_findings_asset_id  ON vuln_findings (asset_id);

-- 3. 结构化修复任务（批准后，可执行类型自动下发客户端代理）
CREATE TABLE IF NOT EXISTS remediation_tasks (
    id              SERIAL PRIMARY KEY,
    finding_id      INTEGER NOT NULL REFERENCES vuln_findings(id) ON DELETE CASCADE,
    asset_id        INTEGER REFERENCES clients(id) ON DELETE SET NULL,
    fix_type        VARCHAR(32) NOT NULL,
    -- registry_fix|software_upgrade|software_uninstall|patch_install|manual_review|unsupported
    action_json     JSONB,
    risk_level      VARCHAR(8) DEFAULT 'medium',      -- low|medium|high
    auto_approve    BOOLEAN DEFAULT FALSE,             -- 低风险 UI 默认勾选（不自动执行）
    status          VARCHAR(16) DEFAULT 'pending',
    -- pending|approved|rejected|needs_manual|dispatched|done|failed
    approved_by     VARCHAR(255),
    approved_at     TIMESTAMPTZ,
    result_log      TEXT,                              -- 执行通道回写
    verified_at     TIMESTAMPTZ,                       -- 复扫验证（后续阶段）
    verified_result VARCHAR(32),
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_status     ON remediation_tasks (status);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_asset_id   ON remediation_tasks (asset_id);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_finding_id ON remediation_tasks (finding_id);

-- 4. QID → 修复策略规则库
CREATE TABLE IF NOT EXISTS remediation_rules (
    id                 SERIAL PRIMARY KEY,
    qid                VARCHAR(32) NOT NULL UNIQUE,
    fix_type           VARCHAR(32) NOT NULL,
    action_template    JSONB,
    default_risk_level VARCHAR(8) DEFAULT 'medium',
    status             VARCHAR(16) DEFAULT 'active',  -- active|draft(LLM草稿待转正)|disabled
    source             VARCHAR(16) DEFAULT 'manual',  -- manual|llm
    notes              TEXT,
    created_at         TIMESTAMPTZ DEFAULT now(),
    updated_at         TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_remediation_rules_status ON remediation_rules (status);

-- 5. 执行通道联动列：task_targets.remediation_task_id
--    下发到客户端的 TaskTarget 记录来源修复任务；客户端回报结果时回写 remediation_tasks。
--    注意：lifespan create_all 不会给已存在的 task_targets 表加列，此处必须显式 ALTER。
ALTER TABLE task_targets
    ADD COLUMN IF NOT EXISTS remediation_task_id INTEGER
    REFERENCES remediation_tasks(id) ON DELETE SET NULL;

COMMIT;

-- 回滚脚本（如需撤销本次迁移，按依赖顺序删除）：
-- ALTER TABLE task_targets DROP COLUMN IF EXISTS remediation_task_id;
-- DROP TABLE IF EXISTS remediation_tasks;
-- DROP TABLE IF EXISTS vuln_findings;
-- DROP TABLE IF EXISTS vuln_scan_imports;
-- DROP TABLE IF EXISTS remediation_rules;
