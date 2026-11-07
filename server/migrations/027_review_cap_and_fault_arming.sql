--
-- 027 — bounded review queue, zombie-advisory reaping, and fleet-wide
--       fault-simulation arming.
--
-- 1. `review_row_cap` bounds how many low-confidence review rows one advisory
--    may create. A REVIEW verdict is applied to every asset of the product, so
--    the previous shape was O(estate size) rows and round trips inside a single
--    3.5 s ingest transaction; a 40,000-seat product flooded the operator queue
--    and could exceed the statement timeout, dead-lettering the advisory that
--    produced it. The cap is a queue budget, not a correctness limit: affected
--    assets beyond it are reported through `ingestion.review_capped`.
--
-- 2. `fault_simulation_armed` is the per-database half of the simulation gate.
--    The endpoint's effect is fleet-wide (it writes this row), so an
--    environment variable on one replica must not be the only thing standing
--    between a misconfigured deployment and a fleet-wide forced outage.

ALTER TABLE correlation_policy
  ADD COLUMN IF NOT EXISTS review_row_cap integer NOT NULL DEFAULT 200;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'correlation_policy_review_row_cap_bounds'
  ) THEN
    ALTER TABLE correlation_policy
      ADD CONSTRAINT correlation_policy_review_row_cap_bounds
      CHECK (review_row_cap BETWEEN 1 AND 10000);
  END IF;
END $$;

ALTER TABLE correlation_policy
  ADD COLUMN IF NOT EXISTS fault_simulation_armed boolean NOT NULL DEFAULT false;

-- A simulation window is only ever five seconds long (supervisor.simulate()).
-- A row that still says otherwise is a crash orphan: the process that would
-- have expired it is gone, and no live replica owns the intent any more.
UPDATE correlation_policy
  SET simulated_fault=NULL, simulated_until=NULL
  WHERE simulated_fault IS NOT NULL
    AND (simulated_until IS NULL OR simulated_until < now());

-- Retention for unreviewed, unprocessed advisories. A row that was inserted but
-- whose matching never committed (crash between INSERT and the match writes)
-- carries no `processed_at`. The supervisor re-queues these for correlation
-- instead of leaving an advisory permanently in limbo.
--
-- Built by applyIndexMigrations() with CREATE INDEX CONCURRENTLY: on a live
-- installation `unstructured_advisories` is populated and this build must not
-- take SHARE on it (see server/migrations/indexes/003_unprocessed_advisories.sql).

INSERT INTO schema_migrations(version) VALUES(27) ON CONFLICT DO NOTHING;
