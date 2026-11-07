-- Typed candidate index for version-range pushdown.
--
-- Correlation used to build the CVE x inventory cross product in the worker.
-- These two tables let PostgreSQL join on structured identity and a typed
-- numeric version ordinal, so the worker only receives plausible pairs. The JS
-- matcher remains authoritative: the index is a conservative superset, and any
-- version it cannot order safely is stored as NULL / unbounded and therefore
-- always reaches the matcher.
CREATE TABLE IF NOT EXISTS match_asset_index (
  asset_id text PRIMARY KEY,
  identities text[] NOT NULL DEFAULT '{}',
  version_ordinal bigint,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS match_asset_identities ON match_asset_index USING GIN(identities);
CREATE INDEX IF NOT EXISTS match_asset_version ON match_asset_index(version_ordinal);

CREATE TABLE IF NOT EXISTS match_cve_index (
  cve_id text NOT NULL,
  criterion_id text NOT NULL,
  identities text[] NOT NULL DEFAULT '{}',
  start_ordinal bigint,
  start_inclusive boolean NOT NULL DEFAULT true,
  end_ordinal bigint,
  end_inclusive boolean NOT NULL DEFAULT true,
  unbounded boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cve_id, criterion_id)
);
CREATE INDEX IF NOT EXISTS match_cve_identities ON match_cve_index USING GIN(identities);
CREATE INDEX IF NOT EXISTS match_cve_cve ON match_cve_index(cve_id);

INSERT INTO schema_migrations(version) VALUES(8) ON CONFLICT DO NOTHING;
