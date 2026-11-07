-- Index builds for the correlation pipeline.
--
-- These statements are DELIBERATELY not in server/migrations/*.sql. The
-- transactional migration runner executes every file inside one BEGIN/COMMIT,
-- and PostgreSQL rejects CREATE INDEX CONCURRENTLY there. A plain CREATE INDEX
-- takes SHARE on the table for the whole build, which blocks every INSERT and
-- UPDATE against `assets`, `unstructured_advisories` and
-- `vendor_product_aliases` while a multi-million-row index is built. Ingest
-- workers run under `SET LOCAL statement_timeout='3500ms'`, so every advisory in
-- flight times out, rolls back, exhausts its retry ladder and is dead-lettered.
--
-- server/db.ts applies this file through `applyIndexMigrations()`, outside any
-- transaction, one statement at a time, with retry on a failed CONCURRENTLY
-- build. Adding an index means adding it here, never to a NNN_*.sql file.
--
-- `lower(alias)` must match the expression exactly, because the engine looks up
-- `WHERE lower(alias)=ANY($1)` and only an expression index with the identical
-- form is usable for that predicate.

CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_assets_cpe
  ON assets(cpe_23) WHERE cpe_23 IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_assets_purl
  ON assets(purl) WHERE purl IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_assets_names
  ON assets(lower(vendor), lower(product));
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS correlation_advisory_fingerprint
  ON unstructured_advisories(fingerprint);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS correlation_advisory_url
  ON unstructured_advisories(url);
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_advisory_search
  ON unstructured_advisories USING gin(tsv_content);
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_alias_lookup
  ON vendor_product_aliases(lower(alias));
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS correlation_alias_identity
  ON vendor_product_aliases(alias);
-- The trigram index is skipped when the extension is not installed in a schema
-- on this session's search_path. applyIndexMigrations() detects that case from
-- the build error and records the index as intentionally absent, rather than
-- retrying a statement that can never succeed.
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_alias_trigram
  ON vendor_product_aliases USING GIN (normalized_alias gin_trgm_ops);
