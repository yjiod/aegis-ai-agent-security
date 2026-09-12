-- Aegis console state — PostgreSQL schema (VPS deployment, alternative to Cloudflare D1)
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  hostname TEXT, owner TEXT, agent_type TEXT,
  agent_version TEXT, policy_version TEXT, status TEXT,
  last_seen BIGINT, registered_at BIGINT,
  findings JSONB DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS tickets (
  ticket_id TEXT PRIMARY KEY,
  title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
  source TEXT, device_id TEXT, description TEXT, finding_ref TEXT,
  assignee TEXT, created_at BIGINT, updated_at BIGINT, resolved_at BIGINT
);
CREATE TABLE IF NOT EXISTS ticket_history (
  id BIGSERIAL PRIMARY KEY, ticket_id TEXT NOT NULL,
  action TEXT NOT NULL, actor TEXT, ts BIGINT, note TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY, ts BIGINT NOT NULL, actor TEXT,
  action TEXT NOT NULL, resource_type TEXT, resource_id TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS admins (employee_no TEXT PRIMARY KEY);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
