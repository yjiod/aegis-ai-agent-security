-- 策略签名密钥治理：轮换/退役的元数据与审计。
-- 安全红线：本表只存密钥的「元数据」（key_id / 指纹 / 状态 / 时间 / 操作人），
-- 绝不存密钥料本身——密钥料只经 env/KMS(AEGIS_POLICY_SIGNING_KEYS) 提供（SEC-AGT-04）。
CREATE TABLE IF NOT EXISTS policy_signing_keys (
  key_id      TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'active',   -- active | retiring | retired
  created_at  BIGINT NOT NULL DEFAULT 0,
  created_by  TEXT NOT NULL DEFAULT '',
  rotated_at  BIGINT,
  rotated_by  TEXT,
  retired_at  BIGINT,
  retired_by  TEXT,
  note        TEXT
);
