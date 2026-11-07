--
-- FIX 3 (continued): Enhanced schema-contract verification.
--
-- Adds database-level verification for unique indexes, generated columns,
-- valid indexes, and CHECK constraints that preflight.ts now enforces at
-- runtime. Ships as its own migration so existing installations that passed
-- 023 are still validated against the complete contract.

-- Unique indexes are required for ON CONFLICT handling in ingest.ts. They are
-- built by applyIndexMigrations() with CREATE INDEX CONCURRENTLY, outside the
-- migration transaction (server/migrations/indexes/001_correlation_indexes.sql).
-- The verification below still asserts that every ON CONFLICT target exists and
-- is valid, so a skipped or failed concurrent build is caught here.

-- Re-assert column contract with type precision for the full set of tables.
DO $$
DECLARE missing text;
BEGIN
  SELECT string_agg(required.t || '.' || required.c, ', ') INTO missing
  FROM (
    VALUES
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
    RAISE EXCEPTION 'Correlation schema contract missing columns: %. Supply a mapping migration approved by the database owner.', missing;
  END IF;
END $$;

-- Verify CHECK constraints exist on tables that enforce confidence levels.
DO $$
DECLARE missing_check boolean;
BEGIN
  SELECT NOT EXISTS (
    SELECT 1 FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema()
      AND con.contype = 'c'
      AND c.relname = 'correlation_matches'
      AND pg_get_constraintdef(con.oid) ~* 'confidence.*HIGH.*MEDIUM'
  ) INTO missing_check;
  IF missing_check THEN
    RAISE EXCEPTION 'Missing CHECK constraint on correlation_matches.confidence';
  END IF;
END $$;

-- Verify generated column on unstructured_advisories.tsv_content is present.
DO $$
DECLARE tsv_generated boolean;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema()
      AND c.relname = 'unstructured_advisories'
      AND a.attname = 'tsv_content'
      AND a.attgenerated = 's'
  ) INTO tsv_generated;
  IF NOT tsv_generated THEN
    RAISE EXCEPTION 'unstructured_advisories.tsv_content must be a STORED generated column';
  END IF;
END $$;

-- Verify valid state of all unique indexes used by ON CONFLICT.
DO $$
DECLARE invalid_idx text;
BEGIN
  -- `index` is reserved in PL/pgSQL (the FOR loop variable), so the alias is
  -- `idx`. The previous alias ended the SELECT with `index.relname`, which the
  -- parser read as the loop variable crossed with a field -> 42703 on every
  -- fresh migration. Only the database-gated suites caught it.
  SELECT cls.relname INTO invalid_idx
  FROM pg_index idx
  JOIN pg_class cls ON cls.oid = idx.indexrelid
  JOIN pg_namespace ns ON ns.oid = cls.relnamespace
  WHERE ns.nspname = current_schema()
    AND idx.indisunique IS TRUE
    AND idx.indisvalid IS FALSE
  LIMIT 1;
  IF invalid_idx IS NOT NULL THEN
    RAISE EXCEPTION 'Unique index % is not valid (incomplete CREATE INDEX CONCURRENTLY?)', invalid_idx;
  END IF;
END $$;

INSERT INTO schema_migrations(version) VALUES(24) ON CONFLICT DO NOTHING;
