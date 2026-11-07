-- Register the schema version for the executions-active index (indexes/035).
--
-- Index files in ./migrations/indexes/ are applied outside the transactional
-- migration (CREATE INDEX CONCURRENTLY cannot run inside a transaction block),
-- so they carry no schema_migrations row of their own. This tiny transactional
-- migration is the version marker: bumping REQUIRED_SCHEMA_VERSION to 35
-- without it would leave production startup refusing to boot against an
-- un-migrated database.
INSERT INTO schema_migrations(version) VALUES(35) ON CONFLICT DO NOTHING;
