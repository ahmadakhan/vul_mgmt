-- Additive only: protected inventory/advisory/alias relations are never altered.
CREATE TABLE IF NOT EXISTS assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), vendor text NOT NULL,
  product text NOT NULL, version text, cpe_23 text, purl text
);
CREATE TABLE IF NOT EXISTS unstructured_advisories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), title varchar(200) NOT NULL,
  content text NOT NULL, url varchar(255) NOT NULL UNIQUE,
  fingerprint char(64) NOT NULL UNIQUE,
  tsv_content tsvector GENERATED ALWAYS AS
    (to_tsvector('simple', coalesce(title,'') || ' ' || coalesce(content,''))) STORED,
  processed_at timestamptz
);
CREATE TABLE IF NOT EXISTS vendor_product_aliases (
  alias text PRIMARY KEY, vendor text NOT NULL, product text NOT NULL
);
-- Existing installations must expose the contract. Never silently replace a column.
DO $$
DECLARE missing text;
BEGIN
  SELECT string_agg(required.t || '.' || required.c, ', ') INTO missing
  FROM (VALUES ('assets','id'),('assets','vendor'),('assets','product'),
    ('assets','version'),('assets','cpe_23'),('assets','purl'),
    ('unstructured_advisories','id'),('unstructured_advisories','title'),
    ('unstructured_advisories','content'),('unstructured_advisories','url'),
    ('unstructured_advisories','fingerprint'),('unstructured_advisories','tsv_content'),
    ('unstructured_advisories','processed_at'),('vendor_product_aliases','alias'),
    ('vendor_product_aliases','vendor'),('vendor_product_aliases','product')) required(t,c)
  WHERE NOT EXISTS (SELECT 1 FROM information_schema.columns actual
    WHERE actual.table_schema=current_schema() AND actual.table_name=required.t AND actual.column_name=required.c);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'Correlation schema contract missing columns: %. Supply a mapping migration approved by the database owner; protected tables have not been altered.', missing;
  END IF;
END $$;
-- Indexes are NOT built here: a plain CREATE INDEX takes SHARE for the whole
-- build and blocks live writers, which dead-letters every in-flight advisory
-- under the 3500ms ingest statement timeout. See server/migrations/indexes/ and
-- applyIndexMigrations() in server/db.ts (CREATE INDEX CONCURRENTLY, outside a
-- transaction).
INSERT INTO vendor_product_aliases(alias,vendor,product)
SELECT seed.alias,seed.vendor,seed.product FROM (VALUES
  ('k8s','kubernetes','kubernetes'),('kubernetes','kubernetes','kubernetes'),
  ('httpd','apache','http_server'),('apache http server','apache','http_server'),
  ('openssh','openbsd','openssh'),('postgres','postgresql','postgresql'),
  ('postgresql','postgresql','postgresql'),('nginx','nginx','nginx'),
  ('exchange server','microsoft','exchange_server'),('fortios','fortinet','fortios'),
  ('pan-os','paloaltonetworks','pan-os')) seed(alias,vendor,product)
WHERE NOT EXISTS (SELECT 1 FROM vendor_product_aliases a WHERE lower(a.alias)=seed.alias)
ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS low_confidence_review_buffer (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), advisory_id uuid NOT NULL,
  asset_id uuid, reason text NOT NULL, confidence text NOT NULL DEFAULT 'LOW' CHECK(confidence='LOW'),
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(advisory_id,asset_id)
);
CREATE INDEX IF NOT EXISTS correlation_review_created ON low_confidence_review_buffer(created_at);
-- Isolated dimensions deliberately avoid foreign keys against owner-managed relations.
CREATE TABLE IF NOT EXISTS correlation_matches (
  advisory_id uuid NOT NULL, asset_id uuid NOT NULL, vendor text NOT NULL, product text NOT NULL,
  confidence text NOT NULL CHECK(confidence IN ('HIGH','MEDIUM')), reason text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(advisory_id,asset_id)
);
CREATE INDEX IF NOT EXISTS correlation_matches_created ON correlation_matches(created_at DESC);
CREATE TABLE IF NOT EXISTS correlation_dead_letters (
  id uuid PRIMARY KEY, tracking_id uuid NOT NULL, error_code text NOT NULL,
  -- Only authenticated ciphertext is retained; raw feed content never enters logs.
  encrypted_payload text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS correlation_dead_letters_created ON correlation_dead_letters(created_at);
CREATE TABLE IF NOT EXISTS correlation_pending (
  id text PRIMARY KEY, payload jsonb NOT NULL, lease_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS correlation_pending_lease ON correlation_pending(lease_until,created_at);
INSERT INTO schema_migrations(version) VALUES(11) ON CONFLICT DO NOTHING;
