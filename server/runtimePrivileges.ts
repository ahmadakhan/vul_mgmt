import type { Db } from './db.ts';
/** Shared by migration bootstrap and restricted-role integration checks. */
export async function grantRuntimePrivileges(db: Db, role = 'vulnstream_app'): Promise<void> {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(role)) throw new Error('INVALID_RUNTIME_ROLE');
  const schema = (await db.query<{ schema: string }>('SELECT current_schema() AS schema')).rows[0].schema;
  const quotedSchema = '"' + schema.replaceAll('"', '""') + '"';
  const target = '"' + role + '"';
  await db.query(`GRANT USAGE ON SCHEMA ${quotedSchema} TO ${target};
    GRANT SELECT,INSERT,UPDATE,DELETE ON users,sessions,login_attempts,records,outbox,scheduler_state,rate_limit_buckets TO ${target};
    GRANT SELECT,INSERT ON audit,operational_events TO ${target};
    GRANT SELECT,INSERT,UPDATE ON state_metrics TO ${target};
    GRANT SELECT ON assets,vendor_product_aliases,correlation_asset_inventory,schema_migrations TO ${target};
    GRANT SELECT,INSERT,UPDATE ON unstructured_advisories TO ${target};
    GRANT SELECT,INSERT,UPDATE,DELETE ON correlation_matches TO ${target};
    GRANT SELECT,INSERT,DELETE ON correlation_dead_letters TO ${target};
    GRANT SELECT,INSERT,UPDATE,DELETE ON low_confidence_review_buffer TO ${target};
    GRANT SELECT,INSERT,UPDATE,DELETE ON correlation_pending,correlation_managed_assets,correlation_match_evidence,
      correlation_review_decisions,correlation_dead_letter_actions,correlation_notifications,password_reset_tokens TO ${target};
    -- Pre-CVE cluster state is written by the ingestion path (membership) and
    -- by the review-decision path (dispositions), and read by the pipeline when
    -- it binds a published CVE. Without these grants every ingest and review
    -- failed with 42501 under the least-privilege runtime role.
    GRANT SELECT,INSERT,UPDATE ON pre_cve_clusters TO ${target};
    GRANT SELECT,INSERT ON pre_cve_cluster_members,pre_cve_dispositions TO ${target};
    GRANT UPDATE ON pre_cve_dispositions TO ${target};
    -- The version-range pushdown index (008) is read and written by the
    -- correlation worker; without these grants the pipeline fails with a
    -- 42501 "permission denied" during product matching, so findings are
    -- never produced and no advisory emails are queued.
    GRANT SELECT,INSERT,UPDATE,DELETE ON match_asset_index,match_cve_index TO ${target};
    GRANT SELECT,UPDATE ON correlation_policy TO ${target};
    GRANT SELECT,INSERT,UPDATE,DELETE ON ml_model_artifacts TO ${target};
    GRANT USAGE,SELECT ON SEQUENCE audit_seq_seq,operational_events_id_seq TO ${target};
    GRANT EXECUTE ON FUNCTION consume_rate_limit_token(text,double precision,double precision) TO ${target};`);
}
