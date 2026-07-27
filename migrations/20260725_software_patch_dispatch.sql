-- ============================================================================
-- 迁移：software_upgrade / patch_install 自动下发通道（remediation_tasks 扩展）
-- 对应模型字段：app/models/vuln.py :: RemediationTask.matched_package_id / needs_reboot
-- 与模型逐字段对应（模型未为该列建索引，迁移亦不额外建索引，保持一致）。
-- 适用：PostgreSQL（生产）。本地 SQLite 测试由 tests 的 create_all 自动建表，无需本脚本。
-- ============================================================================

DO $$
BEGIN
    -- 1) matched_package_id：软件升级匹配到的安装包（NULL=需人工关联后重新匹配）
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_tasks' AND column_name = 'matched_package_id'
    ) THEN
        ALTER TABLE remediation_tasks
            ADD COLUMN matched_package_id INTEGER
            REFERENCES packages(id) ON DELETE SET NULL;
        RAISE NOTICE 'added remediation_tasks.matched_package_id';
    END IF;

    -- 2) needs_reboot：补丁安装装完但等待重启才生效（区别于真正的 done）
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_tasks' AND column_name = 'needs_reboot'
    ) THEN
        ALTER TABLE remediation_tasks
            ADD COLUMN needs_reboot BOOLEAN NOT NULL DEFAULT FALSE;
        RAISE NOTICE 'added remediation_tasks.needs_reboot';
    END IF;
END $$;
