-- Operator-tunable pre-CVE cluster window (see server/correlation/clusters.ts).
-- A window that is too short fragments one zero-day into several clusters when
-- follow-up coverage arrives late; one that is too long merges distinct
-- zero-days in the same product and shares their dispositions. The bounds
-- prevent either failure from becoming a matter of operator configuration
-- drift, and the constraint is added idempotently so re-running is safe.
ALTER TABLE correlation_policy
  ADD COLUMN IF NOT EXISTS pre_cve_cluster_window_days integer NOT NULL DEFAULT 30;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'correlation_policy_cluster_window_bounds'
  ) THEN
    ALTER TABLE correlation_policy
      ADD CONSTRAINT correlation_policy_cluster_window_bounds
      CHECK (pre_cve_cluster_window_days BETWEEN 1 AND 180);
  END IF;
END $$;

INSERT INTO schema_migrations(version) VALUES(21) ON CONFLICT DO NOTHING;
