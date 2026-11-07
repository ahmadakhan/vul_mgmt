LOCK TABLE records,audit IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE IF NOT EXISTS state_metrics (
  name text PRIMARY KEY,
  value bigint NOT NULL DEFAULT 0
);

CREATE OR REPLACE FUNCTION record_state_metrics(record_kind text, body jsonb)
RETURNS TABLE(name text,value bigint) LANGUAGE sql IMMUTABLE AS $$
  SELECT metric.name,metric.value FROM (VALUES
    ('collection:' || record_kind,1::bigint),
    ('summary:activeFindings',CASE WHEN record_kind='findings'
      AND COALESCE(body->>'status','') NOT IN ('RESOLVED','FALSE_POSITIVE','PATCH_APPLIED')
      AND COALESCE(body->>'notificationStatus','')<>'NOT_APPLICABLE' THEN 1 ELSE 0 END),
    ('summary:criticalFindings',CASE WHEN record_kind='findings'
      AND COALESCE(body->>'status','') NOT IN ('RESOLVED','FALSE_POSITIVE','PATCH_APPLIED')
      AND COALESCE(body->>'notificationStatus','')<>'NOT_APPLICABLE'
      AND body->'cve'->'cvss'->>'severity'='CRITICAL' THEN 1 ELSE 0 END),
    ('summary:kevFindings',CASE WHEN record_kind='findings'
      AND COALESCE(body->>'status','') NOT IN ('RESOLVED','FALSE_POSITIVE','PATCH_APPLIED')
      AND COALESCE(body->>'notificationStatus','')<>'NOT_APPLICABLE'
      AND COALESCE(body->'cve'->'cisaKev'->>'isKev','false')='true' THEN 1 ELSE 0 END),
    ('summary:deliveredEmails',CASE WHEN record_kind='emailLogs'
      AND body->>'status' IN ('ACCEPTED','DELIVERED') THEN 1 ELSE 0 END)
  ) AS metric(name,value) WHERE metric.value<>0;
$$;

CREATE OR REPLACE FUNCTION maintain_record_state_metrics() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    INSERT INTO state_metrics(name,value)
      SELECT metric.name,sum(metric.value) FROM added_records
      CROSS JOIN LATERAL record_state_metrics(kind,data) metric
      GROUP BY metric.name ORDER BY metric.name
    ON CONFLICT(name) DO UPDATE SET value=state_metrics.value+EXCLUDED.value;
  ELSIF TG_OP='DELETE' THEN
    INSERT INTO state_metrics(name,value)
      SELECT metric.name,-sum(metric.value) FROM removed_records
      CROSS JOIN LATERAL record_state_metrics(kind,data) metric
      GROUP BY metric.name ORDER BY metric.name
    ON CONFLICT(name) DO UPDATE SET value=state_metrics.value+EXCLUDED.value;
  ELSIF TG_OP='UPDATE' THEN
    INSERT INTO state_metrics(name,value)
      SELECT delta.name,sum(delta.value) FROM (
        SELECT metric.name,metric.value FROM added_records
          CROSS JOIN LATERAL record_state_metrics(kind,data) metric
        UNION ALL
        SELECT metric.name,-metric.value FROM removed_records
          CROSS JOIN LATERAL record_state_metrics(kind,data) metric
      ) delta GROUP BY delta.name HAVING sum(delta.value)<>0 ORDER BY delta.name
    ON CONFLICT(name) DO UPDATE SET value=state_metrics.value+EXCLUDED.value;
  ELSE
    UPDATE state_metrics SET value=0
      WHERE (name LIKE 'collection:%' AND name<>'collection:auditLogs') OR name LIKE 'summary:%';
  END IF;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS state_records_insert ON records;
CREATE TRIGGER state_records_insert AFTER INSERT ON records
  REFERENCING NEW TABLE AS added_records FOR EACH STATEMENT EXECUTE FUNCTION maintain_record_state_metrics();
DROP TRIGGER IF EXISTS state_records_update ON records;
CREATE TRIGGER state_records_update AFTER UPDATE ON records
  REFERENCING OLD TABLE AS removed_records NEW TABLE AS added_records
  FOR EACH STATEMENT EXECUTE FUNCTION maintain_record_state_metrics();
DROP TRIGGER IF EXISTS state_records_delete ON records;
CREATE TRIGGER state_records_delete AFTER DELETE ON records
  REFERENCING OLD TABLE AS removed_records FOR EACH STATEMENT EXECUTE FUNCTION maintain_record_state_metrics();
DROP TRIGGER IF EXISTS state_records_truncate ON records;
CREATE TRIGGER state_records_truncate AFTER TRUNCATE ON records
  FOR EACH STATEMENT EXECUTE FUNCTION maintain_record_state_metrics();

CREATE OR REPLACE FUNCTION maintain_audit_state_metrics() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='TRUNCATE' THEN
    UPDATE state_metrics SET value=0 WHERE name='collection:auditLogs';
  ELSE
    INSERT INTO state_metrics(name,value)
      SELECT 'collection:auditLogs',count(*) FROM added_audit
    ON CONFLICT(name) DO UPDATE SET value=state_metrics.value+EXCLUDED.value;
  END IF;
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS state_audit_insert ON audit;
CREATE TRIGGER state_audit_insert AFTER INSERT ON audit
  REFERENCING NEW TABLE AS added_audit FOR EACH STATEMENT EXECUTE FUNCTION maintain_audit_state_metrics();
DROP TRIGGER IF EXISTS state_audit_truncate ON audit;
CREATE TRIGGER state_audit_truncate AFTER TRUNCATE ON audit
  FOR EACH STATEMENT EXECUTE FUNCTION maintain_audit_state_metrics();

UPDATE state_metrics SET value=0;
INSERT INTO state_metrics(name,value)
  SELECT metric.name,sum(metric.value) FROM records
  CROSS JOIN LATERAL record_state_metrics(kind,data) metric
  GROUP BY metric.name ORDER BY metric.name
ON CONFLICT(name) DO UPDATE SET value=EXCLUDED.value;
INSERT INTO state_metrics(name,value) SELECT 'collection:auditLogs',count(*) FROM audit
ON CONFLICT(name) DO UPDATE SET value=EXCLUDED.value;

INSERT INTO schema_migrations(version) VALUES(36) ON CONFLICT DO NOTHING;