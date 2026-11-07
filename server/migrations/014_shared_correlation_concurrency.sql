-- Application-owned policy only; protected native tables are unchanged.
ALTER TABLE correlation_policy ADD COLUMN IF NOT EXISTS concurrency_limit integer NOT NULL DEFAULT 4
  CHECK(concurrency_limit BETWEEN 1 AND 32);
INSERT INTO schema_migrations(version) VALUES(14) ON CONFLICT DO NOTHING;
