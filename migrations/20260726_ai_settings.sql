-- AI 设置 + 通用命令下发功能 迁移脚本
BEGIN;

CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TIMESTAMPTZ DEFAULT now(),
    updated_by  VARCHAR(100)
);

COMMIT;

-- 回滚：
-- DROP TABLE IF EXISTS system_settings;
