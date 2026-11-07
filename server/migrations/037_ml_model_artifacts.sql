CREATE TABLE IF NOT EXISTS ml_model_artifacts (
  model_id text NOT NULL,
  version text NOT NULL,
  trained_at timestamptz NOT NULL,
  artifact jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','STANDBY_ROLLBACK','DEGRADED')),
  rollback_trigger text,
  PRIMARY KEY (model_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS ml_model_one_active_version
  ON ml_model_artifacts(model_id) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ml_model_artifact_history
  ON ml_model_artifacts(model_id, trained_at DESC);

INSERT INTO schema_migrations(version) VALUES(37) ON CONFLICT DO NOTHING;