-- Aegis 资产标签与处置（skill / MCP 打标 + 加白/观察/拉黑）
-- asset_type: 'skill' | 'mcp'
-- disposition: '' (未处置) | 'allow' (加白) | 'monitor' (观察) | 'deny' (拉黑)
-- tags: JSON 数组字符串（业务标签，如 ["研发工具","第三方SaaS"]）
CREATE TABLE IF NOT EXISTS asset_labels (
  asset_type  TEXT NOT NULL,
  asset_key   TEXT NOT NULL,
  tags        TEXT NOT NULL DEFAULT '[]',
  disposition TEXT NOT NULL DEFAULT '',
  note        TEXT NOT NULL DEFAULT '',
  updated_by  TEXT NOT NULL DEFAULT '',
  updated_at  BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (asset_type, asset_key)
);
CREATE INDEX IF NOT EXISTS idx_asset_labels_disposition ON asset_labels(disposition);
