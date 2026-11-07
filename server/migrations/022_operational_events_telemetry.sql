-- operational_events was created in migration 002 with only the pipeline-event
-- shape (category/code/message/run_id/context), but the correlation telemetry
-- writer (server/correlation/telemetry.ts) persists a different, per-worker
-- shape. On a fresh database every advisory ingest therefore failed with
-- "column sequence does not exist" and was dead-lettered — the correlation
-- pipeline had never worked end to end.
--
-- Both shapes are supported additively: the pipeline columns stay, and the
-- telemetry columns are added nullable so existing rows remain valid.
--
-- Durable clock. The telemetry writer supplies its own `timestamp`, but every
-- consumer of this table reads `occurred_at`:
--   * retention deletes WHERE occurred_at < cutoff (server/retention.ts)
--   * the event reader orders by id and reports occurred_at (server/events.ts)
-- A telemetry row therefore arrived with occurred_at NULL: invisible to the
-- event viewer and, critically, never matched by retention. Instead of relying
-- on the writer to always populate both clocks, occurred_at is made to default
-- from timestamp here, so no caller can create an immortal row. A BEFORE
-- trigger is used rather than a generated column because timestamp is nullable
-- (the pipeline shape does not supply it) and a generated column cannot be
-- overridden by a DEFAULT.
--
-- Timestamp agreement. On INSERT, occurred_at is derived from timestamp
-- whenever the caller supplies one, so a telemetry row can never carry a
-- durable clock that contradicts its own telemetry clock. On UPDATE, an
-- explicit correction to either clock is respected and mirrored to the other —
-- the trigger maintains the invariant (neither clock NULL, the two agree) but
-- never reverts a deliberate maintenance change.

ALTER TABLE operational_events
  ADD COLUMN IF NOT EXISTS sequence integer,
  ADD COLUMN IF NOT EXISTS timestamp timestamptz,
  ADD COLUMN IF NOT EXISTS event text,
  ADD COLUMN IF NOT EXISTS tracking_id uuid,
  ADD COLUMN IF NOT EXISTS ingestion_latency_ms double precision,
  ADD COLUMN IF NOT EXISTS extraction_latency_ms double precision,
  ADD COLUMN IF NOT EXISTS total_database_time_ms double precision,
  ADD COLUMN IF NOT EXISTS count integer,
  ADD COLUMN IF NOT EXISTS attempt integer;

-- Backfill the rows written before this migration under the incomplete shape.
-- Without this they remain invisible to retention permanently.
UPDATE operational_events
  SET occurred_at = COALESCE("timestamp", now())
  WHERE occurred_at IS NULL AND "timestamp" IS NOT NULL;

CREATE OR REPLACE FUNCTION operational_events_sync_clock()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  -- occurred_at has a column DEFAULT of now(). A BEFORE trigger cannot tell a
  -- defaulted value from an explicitly supplied one, and trying to guess made
  -- the disagreement check unreachable — so provenance is not guessed at all.
  --
  -- One rule per operation. Guessing provenance from values was wrong twice:
  -- first it made the contradiction check unreachable, then it silently
  -- reverted an operator's deliberate UPDATE of occurred_at (the row appeared
  -- to update but kept its old clock).
  IF TG_OP = 'INSERT' THEN
    -- occurred_at is derived from timestamp whenever the caller supplies one,
    -- so a telemetry row can never be written with a durable clock that
    -- disagrees with its own telemetry clock, and it is never NULL (which would
    -- make the row invisible to retention and immortal).
    IF NEW."timestamp" IS NOT NULL THEN
      NEW.occurred_at := NEW."timestamp";
    ELSE
      NEW.occurred_at := COALESCE(NEW.occurred_at, now());
      NEW."timestamp" := NEW.occurred_at;
    END IF;
    RETURN NEW;
  END IF;

  -- UPDATE: respect what the caller explicitly changed. Only fill a NULL so the
  -- invariant (neither clock is ever NULL) holds after any mutation, and mirror
  -- a change so the two clocks stay in agreement — but never undo a deliberate
  -- correction.
  IF NEW.occurred_at IS NULL THEN
    NEW.occurred_at := COALESCE(NEW."timestamp", now());
  END IF;
  IF NEW."timestamp" IS NULL THEN
    NEW."timestamp" := NEW.occurred_at;
  ELSIF NEW.occurred_at IS DISTINCT FROM OLD.occurred_at THEN
    -- The durable clock was changed on purpose; carry it to the mirror column.
    NEW."timestamp" := NEW.occurred_at;
  ELSIF NEW."timestamp" IS DISTINCT FROM OLD."timestamp" THEN
    NEW.occurred_at := NEW."timestamp";
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS operational_events_sync_clock ON operational_events;
CREATE TRIGGER operational_events_sync_clock
  BEFORE INSERT OR UPDATE OF "timestamp", occurred_at ON operational_events
  FOR EACH ROW EXECUTE FUNCTION operational_events_sync_clock();

-- Exactly one tracking index. An earlier revision of this migration created a
-- second one on the same column and predicate under a different name, which
-- doubles write cost for no benefit.
DROP INDEX IF EXISTS operational_events_tracking_id_idx;

-- Retention and the event viewer both filter on occurred_at; without an index
-- the retention sweep degrades to a full scan of the largest table as it grows.
-- Both indexes are built CONCURRENTLY by applyIndexMigrations() (see
-- migrations/indexes/002_operational_events_indexes.sql): a plain CREATE INDEX
-- here took SHARE on this table for the whole build, blocking every pipeline
-- writer, and tied the build to the migration transaction so a killed build
-- rolled back the schema upgrade too.

INSERT INTO schema_migrations(version) VALUES(22) ON CONFLICT DO NOTHING;
