--
-- 025 — deployment-safety fixes found by auditing the migration runner.
--
-- 1. The correlation index builds move to server/migrations/indexes/ and are
--    applied by applyIndexMigrations() with CREATE INDEX CONCURRENTLY, outside
--    a transaction. Plain CREATE INDEX takes SHARE for the whole build and
--    dead-letters every in-flight advisory (ingest workers run under a 3500ms
--    statement timeout). This migration only RETIRES the transactional builds
--    so the two runners cannot disagree about the same index.
--
--    The DROPs are identity-only (same table, same shape, same partial
--    predicate). An operator-created index with a different shape is left
--    alone: nothing the application does depends on it, and an index is not
--    correctness-critical the way a column or a constraint is.
--
-- 2. The supervisor circuit breaker and fault-simulation window are process
--    state today. A crash-loop restart cleared a five-minute pause and poured
--    work straight back into the outage that opened it. They now live on the
--    pinned policy row, which already survives restarts and is already polled
--    by the supervisor heartbeat.
--
-- 3. `shedding_since` makes the memory hysteresis span at least one sample
--    interval. Under a 1s poll a brief allocation spike legitimately crossed
--    85% on one sample only and still halved the whole pipeline.

-- --- 1. Retire transactional index builds -----------------------------------
DROP INDEX IF EXISTS correlation_assets_cpe;
DROP INDEX IF EXISTS correlation_assets_purl;
DROP INDEX IF EXISTS correlation_assets_names;
DROP INDEX IF EXISTS correlation_advisory_fingerprint;
DROP INDEX IF EXISTS correlation_advisory_url;
DROP INDEX IF EXISTS correlation_advisory_search;
DROP INDEX IF EXISTS correlation_alias_lookup;

-- --- 2. Durable breaker + simulation state ----------------------------------
ALTER TABLE correlation_policy
  ADD COLUMN IF NOT EXISTS circuit_open_until timestamptz,
  ADD COLUMN IF NOT EXISTS circuit_reason text,
  ADD COLUMN IF NOT EXISTS circuit_instance text,
  ADD COLUMN IF NOT EXISTS simulated_fault text,
  ADD COLUMN IF NOT EXISTS simulated_until timestamptz,
  ADD COLUMN IF NOT EXISTS shedding_since timestamptz;

DO $$
BEGIN
  -- Named CHECK constraints on an ALTER ... ADD COLUMN cannot be added
  -- idempotently, so guard them the same way migration 021 does.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'correlation_policy_simulated_fault'
  ) THEN
    ALTER TABLE correlation_policy
      ADD CONSTRAINT correlation_policy_simulated_fault
      CHECK (simulated_fault IS NULL OR simulated_fault IN ('memory','database'));
  END IF;
END $$;

-- --- 3. Preflight-owned generated columns -----------------------------------
-- Registry of generated columns the preflight is allowed to demand. It is
-- populated from pg_attribute, so it describes reality rather than intent.
-- Migration 016 adds `vendor_product_aliases.normalized_alias` only when
-- pg_trgm is usable, and older databases legitimately lack it; registering it
-- unconditionally made the preflight reject an installation whose migration
-- history predates the conditional branch. 016 now registers it in the same
-- transaction that creates it — only when the ALTER actually ran.
CREATE TABLE IF NOT EXISTS correlation_generated_columns (
  table_name text NOT NULL,
  column_name text NOT NULL,
  PRIMARY KEY (table_name, column_name)
);
DO $$
BEGIN
  INSERT INTO correlation_generated_columns(table_name,column_name)
  SELECT c.relname, a.attname
  FROM pg_attribute a
  JOIN pg_class c ON c.oid = a.attrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = current_schema()
    AND a.attgenerated = 's'
    AND c.relname IN ('unstructured_advisories','vendor_product_aliases')
    AND NOT a.attisdropped
  ON CONFLICT DO NOTHING;
END $$;

INSERT INTO schema_migrations(version) VALUES(25) ON CONFLICT DO NOTHING;
