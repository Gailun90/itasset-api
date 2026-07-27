-- 最终形态·三：对话式规则纠正表（结构化精确匹配缓存，不做 embedding）
-- 幂等：可重复执行。
CREATE TABLE IF NOT EXISTS corrections (
    id               SERIAL PRIMARY KEY,
    qid              VARCHAR(64)  NOT NULL,
    fix_type         VARCHAR(32)  NOT NULL,
    rule_id          INTEGER REFERENCES remediation_rules(id) ON DELETE SET NULL,
    match_key        VARCHAR(1024) NOT NULL DEFAULT '',
    match_fields     JSONB        NOT NULL,
    corrected_action JSONB        NOT NULL,
    note             TEXT,
    usage_count      INTEGER      NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_corrections_qid_fix ON corrections(qid, fix_type);
CREATE INDEX IF NOT EXISTS ix_corrections_lookup ON corrections(qid, fix_type, match_key);
