--
-- FIX 3 — Schema-contract verification before trusting CREATE TABLE IF NOT EXISTS.
--
-- The flaw: CREATE TABLE IF NOT EXISTS is a silent no-op against a
-- pre-existing table. If that table is missing an expected column, nothing
-- fails here — the failure surfaces much later as an opaque runtime query
-- error (e.g. "column fingerprint does not exist"), far from its cause.
--
-- The fix: after the CREATE TABLE statements, explicitly check
-- information_schema.columns for every column the pipeline depends on and
-- RAISE EXCEPTION, naming exactly what's missing, if the contract doesn't
-- hold. This ships as its own migration file (DDL cannot be merged into
-- the TypeScript fix module).
--
-- 011 already created these relations on first application and stamped its
-- own (one-shot) contract DO-block. This migration re-asserts the same
-- contract for installations that already passed 011 and will never re-run
-- it, so a manually altered protected table is caught at deploy time
-- instead of degrading at runtime. correlationPreflight() provides the
-- read-only, every-migrate re-verification at a separate layer.

CREATE TABLE IF NOT EXISTS assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor text NOT NULL,
  product text NOT NULL,
  version text,
  cpe_23 text,
  purl text
);

CREATE TABLE IF NOT EXISTS unstructured_advisories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title varchar(200) NOT NULL,
  content text NOT NULL,
  url varchar(255) NOT NULL UNIQUE,
  fingerprint char(64) NOT NULL UNIQUE,
  tsv_content tsvector GENERATED ALWAYS AS
    (to_tsvector('simple', coalesce(title,'') || ' ' || coalesce(content,''))) STORED,
  processed_at timestamptz
);

CREATE TABLE IF NOT EXISTS vendor_product_aliases (
  alias text PRIMARY KEY,
  vendor text NOT NULL,
  product text NOT NULL
);

-- Existing installations must expose the contract. Never silently proceed
-- on a mismatch between what this migration expects and what already exists.
DO $$
DECLARE missing text;
BEGIN
  SELECT string_agg(required.t || '.' || required.c, ', ') INTO missing
  FROM (VALUES
    ('assets','id'),('assets','vendor'),('assets','product'),
    ('assets','version'),('assets','cpe_23'),('assets','purl'),
    ('unstructured_advisories','id'),('unstructured_advisories','title'),
    ('unstructured_advisories','content'),('unstructured_advisories','url'),
    ('unstructured_advisories','fingerprint'),('unstructured_advisories','tsv_content'),
    ('unstructured_advisories','processed_at'),
    ('vendor_product_aliases','alias'),('vendor_product_aliases','vendor'),
    ('vendor_product_aliases','product')
  ) required(t,c)
  WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.columns actual
    WHERE actual.table_schema = current_schema()
      AND actual.table_name = required.t
      AND actual.column_name = required.c
  );
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'Correlation schema contract missing columns: %. Supply a mapping migration approved by the database owner; protected tables have not been altered.', missing;
  END IF;
END $$;

-- Indexes, created only once the contract above is confirmed to hold. They are
-- built OUTSIDE this transaction by applyIndexMigrations() using CREATE INDEX
-- CONCURRENTLY; see server/migrations/indexes/001_correlation_indexes.sql.
-- Building them inline here took SHARE for the whole build and blocked live
-- writers for its duration, dead-lettering every in-flight advisory.

-- Re-assert the newest contract version so the production gate and the
-- migration runner agree on the schema level this build requires.
INSERT INTO schema_migrations(version) VALUES(23) ON CONFLICT DO NOTHING;
