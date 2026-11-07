-- Pre-CVE vulnerability clusters: a canonical identity for a vulnerability
-- described by alternative intelligence (news, vendor advisories, researcher
-- blogs) BEFORE the CVE program assigns an official identifier.
--
-- Without a cluster identity, each article ingests as an independent advisory
-- row and generates its own match set. When NVD later publishes the CVE, the
-- pipeline treats it as a brand-new vulnerability: operators see the same
-- incident twice (duplicate alert loop) and prior review decisions
-- (false-positive markings) are silently bypassed by the new canonical ID.
--
-- Identity is NOT a keyword string: two feeds describing the same zero-day
-- differ in phrasing. Identity is the (vendor, product) pair plus a bounded
-- temporal window — the first report creates the cluster and every
-- corroborating report inside the window joins it.
--
-- Concurrency is enforced by a partial unique index over OPEN clusters only.
-- An earlier design bucketed first_seen into 7-day windows, which wrongly
-- merged two distinct zero-days disclosed the same week; the partial index
-- keeps exactly one open cluster per identity, which is the intended
-- invariant, and lets a new cluster open as soon as the previous one is
-- resolved or its window lapses.

CREATE TABLE IF NOT EXISTS pre_cve_clusters (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Canonical entity, lowercased at insert time by the application layer.
  vendor text NOT NULL,
  product text NOT NULL,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  -- Set once a CVE ID is bound; the cluster stops accepting new members.
  resolved_cve_id text,
  resolved_at timestamptz,
  -- Set when the open window lapses without a CVE. Kept separate from
  -- resolved_cve_id so a lapsed cluster can never be mistaken for one bound
  -- to an identifier.
  closed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- At most one OPEN cluster per identity: concurrent creators are serialized by
-- this index and the loser adopts the winner's row. "Open" means neither
-- resolved to a CVE nor closed by window expiry.
CREATE UNIQUE INDEX IF NOT EXISTS pre_cve_clusters_one_open_per_identity
  ON pre_cve_clusters (vendor, product)
  WHERE resolved_cve_id IS NULL AND closed_at IS NULL;

CREATE INDEX IF NOT EXISTS pre_cve_clusters_open
  ON pre_cve_clusters (vendor, product, last_seen DESC)
  WHERE resolved_cve_id IS NULL AND closed_at IS NULL;
CREATE INDEX IF NOT EXISTS pre_cve_clusters_resolved
  ON pre_cve_clusters (resolved_cve_id) WHERE resolved_cve_id IS NOT NULL;

-- Which advisory fed which cluster: the evidence chain used at CVE-binding
-- time to retroactively attach pre-CVE articles to the canonical identifier.
CREATE TABLE IF NOT EXISTS pre_cve_cluster_members (
  cluster_id uuid NOT NULL REFERENCES pre_cve_clusters(id) ON DELETE CASCADE,
  advisory_id uuid NOT NULL,
  -- Match set at ingest time; kept so a later CVE binding can re-evaluate
  -- matches that were suppressed by the zero-day cap.
  confidence text NOT NULL CHECK (confidence IN ('HIGH','MEDIUM','LOW')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cluster_id, advisory_id)
);

-- Operator-confirmed false-positive marking on a pre-CVE match must survive
-- CVE publication: the resolved CVE inherits the prior review decision.
CREATE TABLE IF NOT EXISTS pre_cve_dispositions (
  cluster_id uuid NOT NULL REFERENCES pre_cve_clusters(id) ON DELETE CASCADE,
  asset_id uuid NOT NULL,
  disposition text NOT NULL CHECK (disposition IN ('CONFIRMED','FALSE_POSITIVE','NOT_AFFECTED')),
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cluster_id, asset_id)
);

INSERT INTO schema_migrations(version) VALUES(18) ON CONFLICT DO NOTHING;
