-- 阶段E: 自定义安全编码基线 + 全局设置(扫描模式等)
CREATE TABLE IF NOT EXISTS baselines (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  source      TEXT NOT NULL DEFAULT 'custom',   -- custom | upstream
  version     TEXT NOT NULL DEFAULT '1.0.0',
  rules_json  TEXT NOT NULL DEFAULT '[]',       -- 规则列表(JSON 数组)
  scan_modes  TEXT NOT NULL DEFAULT '["standard"]',
  updated_by  TEXT NOT NULL DEFAULT '',
  updated_at  BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
INSERT INTO settings(key,value) VALUES ('scan_mode','standard') ON CONFLICT(key) DO NOTHING;
