-- Index builds for the correlation advisory store (see migration 027).
--
-- `unstructured_advisories` is owner-managed and populated on a live
-- installation, so the build must be CONCURRENTLY and outside the migration
-- transaction. The partial predicate keeps the index proportional to the
-- unprocessed backlog (normally near-empty) rather than to the whole table.

CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_advisory_unprocessed
  ON unstructured_advisories(processed_at, id) WHERE processed_at IS NULL;
