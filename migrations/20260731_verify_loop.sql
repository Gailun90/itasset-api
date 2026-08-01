-- 验证循环（声明式判定条件 + 自动重试）相关字段
-- task_targets.is_verify：本 target 为「验证子任务」（修复成功后下发的判定条件检查），回报时走验证分支
ALTER TABLE task_targets
    ADD COLUMN IF NOT EXISTS is_verify BOOLEAN NOT NULL DEFAULT FALSE;

-- remediation_tasks.verify_attempts / verify_max_attempts：修复+验证循环次数与上限
ALTER TABLE remediation_tasks
    ADD COLUMN IF NOT EXISTS verify_attempts INTEGER NOT NULL DEFAULT 0;

ALTER TABLE remediation_tasks
    ADD COLUMN IF NOT EXISTS verify_max_attempts INTEGER NULL;
