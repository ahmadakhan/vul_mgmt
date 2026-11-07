-- Operational-event indexes, built outside the migration transaction.
--
-- `operational_events` is an append-heavy table on an established installation:
-- every pipeline run writes to it, and retention prunes it on a timer. A plain
-- CREATE INDEX holds SHARE for the whole build, so the build itself is the
-- outage. These are applied by applyIndexMigrations() with CREATE INDEX
-- CONCURRENTLY, one statement at a time, on an autocommit connection; an
-- interrupted build leaves an INVALID index that the retry path drops before
-- rebuilding.
--
-- ORDER AND TYPE MATTER HERE; neither is cosmetic:
--
--   * `occurred_at DESC` serves the retention DELETE, which filters
--     `occurred_at < cutoff ORDER BY ... LIMIT 10000` and runs in a loop. An
--     ASC index still serves that range scan, but DESC keeps the most recent
--     rows contiguous at the head of the heap order retention walks.
--   * `tracking_id` is uuid, added by migration 022. Its index is built here,
--     after the schema transaction commits, so the column is present — but a
--     build ordering bug would otherwise surface as a deployment failure on a
--     brand-new database and nowhere else.
--   * The partial predicate `tracking_id IS NOT NULL` is not an optimisation
--     detail: every pipeline writer leaves tracking_id NULL, so the subset is
--     tiny and the index stays cheap on the highest-write table.

CREATE INDEX CONCURRENTLY IF NOT EXISTS operational_events_occurred_at
  ON operational_events (occurred_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS operational_events_tracking
  ON operational_events (tracking_id) WHERE tracking_id IS NOT NULL;


