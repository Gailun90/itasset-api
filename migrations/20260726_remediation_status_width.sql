-- 修复 remediation_tasks.status 列宽不足导致的后校验 500
-- 后校验不达标时写入 status='rollback_required'（17 字符），
-- 但原列定义为 VARCHAR(16)，Postgres 拒绝写入 → StringDataRightTruncationError →
-- 提交回滚 → 任务卡死在 pending_verify。
-- remediation_tasks / task_targets / tasks 三张表的状态列统一为 VARCHAR(32)。
ALTER TABLE remediation_tasks ALTER COLUMN status TYPE VARCHAR(32);
