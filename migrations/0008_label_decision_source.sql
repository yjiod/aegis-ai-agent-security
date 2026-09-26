-- Apply before deploying readers/writers that use decision_source.
-- Do not infer trusted provenance from mutable tags, actor names or asset names.
ALTER TABLE asset_labels ADD COLUMN IF NOT EXISTS decision_source TEXT NOT NULL
  DEFAULT 'legacy' CHECK (decision_source IN ('manual','preset','automatic','legacy'));
