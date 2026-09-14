-- 签名策略发布：把控制台的处置决定编译成终端可验签强制的 aegis.policy/v1 发布件。
-- 每次发布 version 单调递增，旧版本置 superseded；终端据此判断策略代次与回执。
CREATE TABLE IF NOT EXISTS policy_releases (
  release_id     TEXT PRIMARY KEY,
  version        BIGINT NOT NULL,
  created_at     BIGINT NOT NULL,
  created_by     TEXT NOT NULL DEFAULT '',
  signing_key_id TEXT NOT NULL DEFAULT '',
  signature      TEXT NOT NULL DEFAULT '',
  policy_json    TEXT NOT NULL DEFAULT '{}',
  note           TEXT NOT NULL DEFAULT '',
  status         TEXT NOT NULL DEFAULT 'published'
);
CREATE INDEX IF NOT EXISTS idx_policy_releases_version ON policy_releases(version DESC);
