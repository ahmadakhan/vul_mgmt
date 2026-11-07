CREATE TABLE IF NOT EXISTS operational_events (
  id bigserial PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  category text NOT NULL CHECK (category IN ('PIPELINE','FEED','MATCHING','EMAIL','SYSTEM','ISSUE','EVENT')),
  level text NOT NULL CHECK (level IN ('INFO','WARNING','ERROR')),
  code text NOT NULL,
  message text NOT NULL,
  run_id uuid,
  context jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_category_recent ON operational_events(category,id DESC);
CREATE INDEX IF NOT EXISTS events_run_recent ON operational_events(run_id,id DESC);
CREATE INDEX IF NOT EXISTS events_level_recent ON operational_events(level,id DESC);
CREATE INDEX IF NOT EXISTS events_search ON operational_events USING gin(to_tsvector('simple',code || ' ' || message || ' ' || context::text));
INSERT INTO schema_migrations(version) VALUES(2) ON CONFLICT DO NOTHING;
