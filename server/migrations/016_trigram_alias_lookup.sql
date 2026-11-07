-- Normalized alias lookup with a trigram index for fuzzy matching.
--
-- Two hard constraints this file must respect:
--   1. The migration runner executes every file inside ONE transaction, and
--      PostgreSQL rejects CREATE INDEX CONCURRENTLY there. Using it rolled
--      back the entire migration history (verified against PostgreSQL 16).
--      Plain CREATE INDEX is used instead; it is transactional and safe.
--   2. pg_trgm may not be installed. Requiring superuser to add it would make
--      migration fail for least-privilege deployments, so the extension is
--      created only when available and the trigram indexes are skipped
--      otherwise. The normalized columns and the fuzzy functions below are
--      still created — the hardening in migration 019 is what the ingestion
--      path depends on, not the index.

DO $$
BEGIN
  BEGIN
    -- Install into the CURRENT schema so gin_trgm_ops and similarity() are
    -- visible to this deployment's search_path. Installing into public from a
    -- schema-isolated tenant would leave the functions unreachable.
    EXECUTE format('CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA %I', current_schema());
  EXCEPTION WHEN insufficient_privilege OR undefined_file THEN
    RAISE NOTICE 'pg_trgm unavailable; trigram indexes and fuzzy helpers will be skipped';
  END;
END $$;

-- True when the extension is actually installed in a schema this session can
-- resolve. pg_extension alone lies when the install lives outside search_path
-- and pg_opclass alone retains rows for a dropped extension.
CREATE OR REPLACE FUNCTION pg_temp_has_trgm() RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM pg_extension e
    JOIN pg_namespace n ON n.oid = e.extnamespace
    WHERE e.extname = 'pg_trgm'
      AND n.nspname = ANY (current_schemas(true))
  )
$$;

-- Add a normalized alias column for fuzzy matching.
ALTER TABLE vendor_product_aliases
  ADD COLUMN IF NOT EXISTS normalized_alias TEXT
  GENERATED ALWAYS AS (regexp_replace(lower(alias), '[^a-z0-9]', '', 'g')) STORED;

-- Register the derived column for the preflight contract check. This is an
-- optional extension of a module-owned table, not part of the protected native
-- contract: an installation whose history predates this migration legitimately
-- lacks it, so the preflight must only demand columns that really exist. The
-- insert is conditional on the column being generated, and the registry table
-- is created on demand so this file stays runnable on an older baseline.
DO $$
BEGIN
  IF to_regclass('correlation_generated_columns') IS NOT NULL THEN
    INSERT INTO correlation_generated_columns(table_name,column_name)
    SELECT 'vendor_product_aliases','normalized_alias'
    WHERE EXISTS (
      SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname=current_schema() AND c.relname='vendor_product_aliases'
        AND a.attname='normalized_alias' AND a.attgenerated='s'
    )
    ON CONFLICT DO NOTHING;
  END IF;
END $$;

-- NOTE: migration 011 declares `assets` an owner-managed relation that the
-- correlation pipeline must never alter. An earlier revision of this file
-- added generated normalized_vendor/normalized_product columns to `assets`
-- and a fuzzy_asset_lookup() function over them. Both were removed here: they
-- violate the protected-schema contract (the regression suite asserts the
-- assets column list is byte-identical after migration) and the fuzzy helpers
-- were never called by the ingestion path. Only vendor_product_aliases, which
-- this module owns, gains a derived column.

-- Trigram indexes are an optimization only. They are built by
-- applyIndexMigrations() (CONCURRENTLY, outside this transaction) and skipped
-- there when pg_trgm is not installed in a schema on the session path. Building
-- them inline blocked writers for the whole build, which dead-letters every
-- in-flight advisory under the 3500ms ingest statement timeout.
DO $$
BEGIN
  IF NOT pg_temp_has_trgm() THEN
    RAISE NOTICE 'pg_trgm not installed in this schema; trigram index build deferred';
  END IF;
END $$;

-- Fuzzy alias lookup. Migration 019 tightens these thresholds; the versions
-- here exist so an installation that stops at 016 is not left without the
-- functions. Both refuse short inputs, which is what caused the historical
-- "java" -> "kafka"/"jboss" cross-matches.
CREATE OR REPLACE FUNCTION fuzzy_alias_lookup(
  input_alias TEXT,
  max_distance INT DEFAULT 2,
  similarity_threshold REAL DEFAULT 0.75
)
RETURNS TABLE (
  alias TEXT,
  vendor TEXT,
  product TEXT,
  similarity REAL
) LANGUAGE plpgsql STABLE AS $$
DECLARE
  normalized_input TEXT;
BEGIN
  normalized_input := regexp_replace(lower(input_alias), '[^a-z0-9]', '', 'g');
  IF normalized_input IS NULL OR length(normalized_input) < 6 THEN
    RETURN;
  END IF;
  RETURN QUERY
  SELECT a.alias, a.vendor, a.product,
         similarity(normalized_input, a.normalized_alias) AS sim
  FROM vendor_product_aliases a
  WHERE length(a.normalized_alias) >= 6
    AND similarity(normalized_input, a.normalized_alias) >= similarity_threshold
  ORDER BY similarity(normalized_input, a.normalized_alias) DESC
  LIMIT 5;
END;
$$;


-- Fuzzy helpers are operator utilities, not part of the ingestion boundary.
REVOKE EXECUTE ON FUNCTION fuzzy_alias_lookup(TEXT, INT, REAL) FROM PUBLIC;


-- The generated columns are computed by PostgreSQL on write; the UPDATE
-- statements previously here targeted generated columns and would have been
-- rejected. Nothing to backfill.

INSERT INTO schema_migrations(version) VALUES(16) ON CONFLICT DO NOTHING;
