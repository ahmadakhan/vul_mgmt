-- Version comparison suffix policy: the JavaScript comparator in
-- server/correlation/version.ts is the single source of truth for how
-- distribution/backport suffixes are interpreted. This migration only records
-- the policy so operators can audit it without reading source.
INSERT INTO schema_migrations(version) VALUES(17) ON CONFLICT DO NOTHING;
