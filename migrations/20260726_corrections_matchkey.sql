-- 最终形态·三：corrections 表补齐 match_key 列（若 20260726_corrections.sql 已在
-- 缺失 match_key 时执行过，用本脚本幂等补齐；新环境直接跑带 match_key 的建表即可）。
-- 幂等：列已存在则跳过。

-- PostgreSQL
ALTER TABLE corrections ADD COLUMN IF NOT EXISTS match_key VARCHAR(1024) NOT NULL DEFAULT '';

-- 回填：把已有行的 match_key 用 (qid, fix_type, match_fields) 归一补上
-- （match_fields 为 JSONB；用 jsonb_build_object 取键值后排序拼接成本高，
--   直接调用应用层 Correction.match_key 更安全；这里给出 SQL 兜底仅覆盖简单情形）
-- 备注：生产回填建议在应用层执行（Python 调用 Correction.match_key），本 SQL 仅保证列存在。

CREATE INDEX IF NOT EXISTS ix_corrections_lookup ON corrections(qid, fix_type, match_key);
