-- RBAC 审计员(auditor)只读角色: 显式授予的合规审阅身份。
-- 审计员可读审计日志与管理员/审计员名册, 但不能做任何变更(所有写操作 403)。
-- 与 env AEGIS_AUDITOR_USERS 合并, 由 lib/auth.auditorAllowlist() 消费。
CREATE TABLE IF NOT EXISTS auditors (employee_no TEXT PRIMARY KEY);
