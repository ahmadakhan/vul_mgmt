--
-- 026 — retire leftover transactional index builds on operational_events.
--
-- The plain CREATE INDEX statements on operational_events came from the retired
-- 014 file, not from a migration the current runner applies. A database created
-- while that file was still live can still carry them:
--   - `operational_events_timestamp` on (timestamp DESC). Redundant: the 022
--     sync trigger writes `timestamp` and `occurred_at` from one clock, and
--     every read path uses occurred_at.
--   - `operational_events_tracking_id_idx`, which 022 already drops. A database
--     upgraded through 022 no longer has it.
--
-- The hazard being removed is not these indexes' existence but how they were
-- created: a plain CREATE INDEX inside the migration transaction takes SHARE for
-- the whole build, blocking every pipeline writer for minutes on an established
-- event log, and ties the build to the schema upgrade so a cancelled build rolls
-- the upgrade back. The authoritative builds live in
-- server/migrations/indexes/002_operational_events_indexes.sql and are applied by
-- applyIndexMigrations() with CREATE INDEX CONCURRENTLY outside any transaction.
--
-- IMPORTANT: `operational_events_occurred_at` and `operational_events_tracking`
-- are the CANONICAL names owned by the concurrent runner. This migration must
-- never drop them; an earlier draft did, which would have removed the only
-- index on the retention column during the deploy.
--
-- Nothing here is unconditional. A wrong DROP during a deploy is a self-inflicted
-- outage, which is the exact failure this change exists to remove.

-- 1. An INVALID index is a cancelled CONCURRENTLY build: the catalogue entry
--    outlives the abort, so `IF NOT EXISTS` would treat the wreckage as a
--    finished build and never rebuild it. It is never useful, so it always goes.
DO $$
DECLARE invalid_idx text;
BEGIN
  SELECT c.relname INTO invalid_idx
  FROM pg_index i
  JOIN pg_class c ON c.oid = i.indexrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_class t ON t.oid = i.indrelid
  WHERE n.nspname = current_schema()
    AND t.relname = 'operational_events'
    AND c.relname IN (
      'operational_events_timestamp',
      'operational_events_tracking_id_idx'
    )
    AND NOT i.indisvalid
  LIMIT 1;
  IF invalid_idx IS NOT NULL THEN
    EXECUTE format('DROP INDEX %I', invalid_idx);
  END IF;
END $$;

-- 2. `timestamp` duplicates `occurred_at` and is not read by anything. Drop it
--    only when an index on occurred_at exists (or the deploy is covered by the
--    concurrent runner immediately afterwards), so the retention sweep — which
--    is the only reason either index exists — is never left scanning.
DO $$
BEGIN
  IF to_regclass('operational_events_timestamp') IS NOT NULL
     AND to_regclass('operational_events_occurred_at') IS NOT NULL THEN
    DROP INDEX operational_events_timestamp;
  END IF;
END $$;

-- 3. `tracking_id_idx` was superseded by `operational_events_tracking` (the
--    runner's canonical name, same column and predicate) and 022 already drops
--    it. Retire any remainder only when the canonical index exists, so the admin
--    event viewer's tracking lookup is never unindexed.
DO $$
BEGIN
  IF to_regclass('operational_events_tracking_id_idx') IS NOT NULL
     AND to_regclass('operational_events_tracking') IS NOT NULL THEN
    DROP INDEX operational_events_tracking_id_idx;
  END IF;
END $$;

INSERT INTO schema_migrations(version) VALUES(26) ON CONFLICT DO NOTHING;
