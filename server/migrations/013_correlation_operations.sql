-- Application-owned projections; protected native tables remain read-only.
CREATE TABLE IF NOT EXISTS correlation_managed_assets (
  record_id text PRIMARY KEY, native_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  vendor text NOT NULL, product text NOT NULL, version text,
  cpes text[] NOT NULL DEFAULT '{}', purls text[] NOT NULL DEFAULT '{}',
  active boolean NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS correlation_managed_names ON correlation_managed_assets(lower(vendor),lower(product)) WHERE active;
CREATE INDEX IF NOT EXISTS correlation_managed_cpes ON correlation_managed_assets USING gin(cpes) WHERE active;
CREATE INDEX IF NOT EXISTS correlation_managed_purls ON correlation_managed_assets USING gin(purls) WHERE active;
CREATE OR REPLACE VIEW correlation_asset_inventory AS
 SELECT id,vendor,product,version,cpe_23,purl,
   encode(sha256(convert_to(jsonb_build_array(vendor,product,version,cpe_23,purl)::text,'UTF8')),'hex') AS revision
 FROM assets
 UNION ALL
 SELECT native_id,vendor,product,version,cpes[1],purls[1],
   encode(sha256(convert_to(jsonb_build_array(vendor,product,version,cpes,purls)::text,'UTF8')),'hex')
 FROM correlation_managed_assets WHERE active;
CREATE TABLE IF NOT EXISTS correlation_match_evidence (
  advisory_id uuid NOT NULL, asset_id uuid NOT NULL, asset_revision char(64) NOT NULL,
  PRIMARY KEY(advisory_id,asset_id)
);
CREATE TABLE IF NOT EXISTS correlation_policy (
  id integer PRIMARY KEY CHECK(id=1), notifications_enabled boolean NOT NULL DEFAULT false,
  notifications_since timestamptz NOT NULL DEFAULT now(), retention_enabled boolean NOT NULL DEFAULT true,
  retention_hours integer NOT NULL DEFAULT 720 CHECK(retention_hours BETWEEN 24 AND 87600),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO correlation_policy(id) VALUES(1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS correlation_review_decisions (
  review_id uuid PRIMARY KEY, decision text NOT NULL CHECK(decision IN ('APPROVED','DISMISSED')),
  asset_id uuid, actor text NOT NULL, note text NOT NULL, decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS correlation_dead_letter_actions (
  letter_id uuid PRIMARY KEY, action text NOT NULL CHECK(action IN ('REPLAYED','DISMISSED')),
  actor text NOT NULL, note text NOT NULL, decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS correlation_notifications (
  advisory_id uuid PRIMARY KEY, evidence_hash char(64) NOT NULL,
  queued_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations(version) VALUES(13) ON CONFLICT DO NOTHING;
