import type { TimedQuery } from './engine.ts';
import type { Db } from '../db.ts';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';

/**
 * Pre-CVE cluster linkage.
 *
 * Before a CVE identifier is published, alternative intelligence (news,
 * vendor advisories, researcher reports) is the only identity a
 * vulnerability has. Left unlinked, each source ingests as an independent
 * advisory and the match engine produces a parallel alert stream per source.
 * When NVD later publishes the CVE, the canonical identifier must inherit
 * the cluster's accumulated evidence and operator dispositions — otherwise
 * the same incident re-alerts under the new ID and prior FALSE_POSITIVE
 * review decisions are bypassed.
 *
 * Clustering key: (vendor, product) of the matched entities, NOT the raw
 * article text. Phrasing differs across sources; the asset-facing identity
 * does not. The temporal window bounds how long a cluster stays open.
 *
 * Window sizing is a policy trade-off, not a constant of nature:
 *   - too short  -> the same zero-day fragments into several clusters when
 *                   follow-up coverage arrives a few weeks later;
 *   - too long   -> two distinct zero-days in one product collapse into one
 *                   cluster and share dispositions.
 * The default below is deliberately generous because the merge failure is
 * visible to an operator (one review row instead of two) while the split
 * failure silently produces an alert storm. Operators can override it via
 * `correlation_policy.pre_cve_cluster_window_days`.
 */
export const DEFAULT_CLUSTER_OPEN_WINDOW_DAYS = 30;
export const MIN_CLUSTER_OPEN_WINDOW_DAYS = 1;
export const MAX_CLUSTER_OPEN_WINDOW_DAYS = 180;
const MAX_CLUSTERS_PER_ADVISORY = 8;

/** Clamp an operator-supplied window to the supported range. */
export function clusterWindowDays(configured?: number | null): number {
  if (typeof configured !== 'number' || !Number.isFinite(configured)) return DEFAULT_CLUSTER_OPEN_WINDOW_DAYS;
  return Math.min(MAX_CLUSTER_OPEN_WINDOW_DAYS, Math.max(MIN_CLUSTER_OPEN_WINDOW_DAYS, Math.floor(configured)));
}

export interface ClusterMatch {
  clusterId: string;
  vendor: string;
  product: string;
  isNew: boolean;
}

/** Deterministic similarity fingerprint for de-duplicating paraphrased
 * coverage inside one cluster: sorted top-n shingles of the normalized text,
 * hashed. Two reports of the same event share the vendor/product/version
 * shingles even when the prose differs. */
export function textFingerprint(normalizedText: string): string {
  const shingles = new Set<string>();
  const tokens = normalizedText.split(/\s+/).filter(Boolean);
  for (let i = 0; i + 3 <= tokens.length && i < 5000; i++)
    shingles.add(tokens.slice(i, i + 3).join(' '));
  return createHash('sha256')
    .update([...shingles].sort().slice(0, 256).join('|'))
    .digest('hex');
}

export type ClusterQuery = {
  query: (sql: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
  /**
   * The underlying pool client, when one exists. `bindClusterToCve` uses it to
   * bound its row-lock wait with a per-statement `lock_timeout` and a savepoint;
   * without it the wait inherits the caller's statement budget and a timeout
   * silently drops the disposition inheritance.
   */
  client?: PoolClient;
  /**
   * True when the caller already opened a transaction on `client`. Savepoints
   * (the only way to survive a lock timeout without aborting the caller's
   * transaction) are illegal outside one, so the guard must be explicit rather
   * than inferred from the client's presence.
   */
  inTransaction?: boolean;
};

/**
 * Join or create a cluster for each (vendor, product) entity this advisory
 * matched, inside the open window. Runs INSIDE the ingest transaction so
 * cluster creation and advisory insertion commit atomically — a crash can
 * never orphan a cluster row with no member evidence.
 */
export async function linkPreCveClusters(
  db: ClusterQuery,
  advisoryId: string,
  entities: { vendor: string; product: string }[],
  matchCount: number,
  cveIds: string[],
  windowDays: number = DEFAULT_CLUSTER_OPEN_WINDOW_DAYS,
  now = new Date(),
): Promise<ClusterMatch[]> {
  if (cveIds.length) return []; // canonical identity exists; no clustering
  const clusters: ClusterMatch[] = [];
  for (const entity of entities.slice(0, MAX_CLUSTERS_PER_ADVISORY)) {
    const vendor = entity.vendor.toLowerCase();
    const product = entity.product.toLowerCase();
    const days = String(clusterWindowDays(windowDays));
    // Join the open cluster for this identity inside the window, or create one.
    //
    // A partial unique index (vendor, product) WHERE resolved_cve_id IS NULL
    // serializes concurrent creators: the loser's INSERT conflicts and is
    // redirected into the DO UPDATE branch, which returns the winner's id.
    // The WHERE NOT EXISTS guard means the common in-window path does not
    // insert at all, so no conflict is generated during normal operation.
    const joined = await db.query(
      `WITH stale AS (
         -- An open cluster whose window lapsed is closed so a fresh
         -- disclosure for the same product starts a new cluster instead of
         -- silently attaching to a months-old incident.
         UPDATE pre_cve_clusters SET closed_at=now()
         WHERE vendor=$1 AND product=$2 AND resolved_cve_id IS NULL AND closed_at IS NULL
           AND last_seen <= now() - ($3 || ' days')::interval
         RETURNING id
       ), open_cluster AS (
         SELECT id FROM pre_cve_clusters
         WHERE vendor=$1 AND product=$2 AND resolved_cve_id IS NULL AND closed_at IS NULL
           AND last_seen > now() - ($3 || ' days')::interval
         ORDER BY last_seen DESC LIMIT 1
       ), touched AS (
         UPDATE pre_cve_clusters SET last_seen=now()
         WHERE id IN (SELECT id FROM open_cluster)
         RETURNING id
       ), created AS (
         INSERT INTO pre_cve_clusters(vendor, product, first_seen, last_seen)
         SELECT $1,$2,now(),now()
         WHERE NOT EXISTS (SELECT 1 FROM touched)
         ON CONFLICT (vendor, product) WHERE resolved_cve_id IS NULL AND closed_at IS NULL
         DO UPDATE SET last_seen=now()
         RETURNING id
       )
       SELECT id FROM touched UNION ALL SELECT id FROM created`,
      [vendor, product, days],
    );
    const clusterId = (joined.rows as { id: string }[])[0]?.id;
    if (!clusterId) continue;
    // `isNew` must reflect whether this advisory was the first to establish
    // the cluster, so it drives notification de-duplication. The membership
    // insert reports its own rowCount instead of a follow-up count, which
    // would race with a concurrent ingest of the same cluster.
    const member = await db.query(
      `INSERT INTO pre_cve_cluster_members(cluster_id, advisory_id, confidence)
      VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
      [clusterId, advisoryId, matchCount > 0 ? 'MEDIUM' : 'LOW'],
    );
    clusters.push({
      clusterId,
      vendor,
      product,
      // A concurrent ingest that lost the race already inserted this member.
      isNew: (member.rowCount ?? 0) > 0,
    });
  }
  return clusters;
}

/**
 * Bind a published CVE to its pre-CVE cluster and propagate the operator
 * dispositions earned before publication. Called by the CVE ingestion path
 * when a new canonical identifier first appears.
 */
export async function bindClusterToCve(
  db: ClusterQuery,
  cveId: string,
  vendor: string,
  product: string,
): Promise<string | null> {
  // The `FOR UPDATE` below must not be skipped: skipping a locked cluster would
  // silently drop the disposition inheritance the cluster exists to provide.
  // It also must not be allowed to fail silently, which is what happened when
  // the statement inherited the caller's 3500ms `statement_timeout`: the wait
  // expired, the error propagated into the pipeline's generic handler, and the
  // inheritance was lost with no retry and no record.
  //
  // Instead, bound the wait to a fraction of the caller's budget with a
  // short-lived savepoint (so a timeout does not poison the enclosing
  // transaction), and retry while budget remains. Only when the budget is
  // genuinely exhausted does this return null — and it reports that so the
  // caller can surface it rather than treating it as "no cluster to bind".
  const started = Date.now();
  const lockBudgetMs = Math.min(2500, Math.max(200, Number(process.env.CORRELATION_BIND_LOCK_BUDGET_MS ?? 2000)));
  // Savepoints are only legal inside a transaction. The pipeline calls this
  // inside one; a read-only or autocommit caller gets the plain wait, and the
  // typed error below still reports contention instead of returning null.
  const inTransaction = Boolean(db.client && db.inTransaction);
  let lastError: unknown;
  for (let attempt = 0; attempt < 3 && Date.now() - started < lockBudgetMs; attempt++) {
    if (inTransaction) {
      await db.query('SAVEPOINT bind_cluster');
      await db.client!.query(`SET LOCAL lock_timeout = '${Math.max(50, Math.floor(lockBudgetMs / 3))}ms'`);
    }
    let releaseFailed = false;
    let rows: { id: string }[];
    try {
      rows = (
        await db.query(
          // Prefer an open cluster. A cluster closed by window expiry is still
          // bindable within a grace period: NVD frequently publishes weeks after
          // the disclosure, and the operator dispositions recorded in the window
          // must still reach the canonical identifier.
          `SELECT id FROM pre_cve_clusters
          WHERE vendor=$1 AND product=$2 AND resolved_cve_id IS NULL
            AND (closed_at IS NULL OR closed_at > now() - interval '180 days')
          ORDER BY closed_at NULLS FIRST, last_seen DESC
          LIMIT 1 FOR UPDATE`,
          [vendor.toLowerCase(), product.toLowerCase()],
        )
      ).rows as { id: string }[];
    } catch (error) {
      const code = String((error as { code?: string }).code ?? '');
      // 55P03 lock_not_available, 40P01 deadlock_detected, 57014 query_canceled
      // (statement timeout). All are transient contention, not an absent cluster.
      if (!['55P03', '40P01', '57014'].includes(code)) throw error;
      lastError = error;
      rows = [];
      releaseFailed = true;
    }
    if (inTransaction) {
      if (releaseFailed) await db.query('ROLLBACK TO SAVEPOINT bind_cluster').catch(() => {});
      else await db.query('RELEASE SAVEPOINT bind_cluster').catch(() => {});
    }
    if (rows.length) {
      const clusterId = rows[0].id;
      const updated = await db.query(
        `UPDATE pre_cve_clusters SET resolved_cve_id=$2, resolved_at=now()
         WHERE id=$1 AND resolved_cve_id IS NULL`,
        [clusterId, cveId],
      );
      return updated.rowCount ? clusterId : null;
    }
    if (!releaseFailed) return null; // genuinely no cluster to bind
    await new Promise((resolve) => setTimeout(resolve, 50 * 2 ** attempt));
  }
  if (lastError)
    throw Object.assign(
      new Error(`BIND_LOCK_CONTENDED: disposition inheritance for ${cveId} was deferred after ${lockBudgetMs}ms`),
      { cause: lastError, code: 'BIND_LOCK_CONTENDED' },
    );
  return null;
}

/**
 * Asset IDs an operator ruled FALSE_POSITIVE or NOT_AFFECTED for a cluster
 * that has since been bound to this CVE. Called inside the same transaction
 * that persists new canonical findings, so a pre-CVE ruling suppresses the
 * canonical finding before it is ever queued for delivery.
 */
export async function clusterSuppressedAssets(
  db: ClusterQuery,
  cveId: string,
): Promise<Set<string>> {
  const rows = (
    await db.query(
      `SELECT d.asset_id FROM pre_cve_dispositions d
      JOIN pre_cve_clusters c ON c.id=d.cluster_id
      WHERE c.resolved_cve_id=$1
        AND d.disposition IN ('FALSE_POSITIVE','NOT_AFFECTED')`,
      [cveId],
    )
  ).rows as { asset_id: string }[];
  return new Set(rows.map((row) => row.asset_id));
}

/** Record an operator ruling against every cluster the asset's advisory
 * belongs to. Written by the review-decision path so the ruling outlives
 * the article it was made on. Takes a `Db` so callers inside a transaction
 * (the decision path) and standalone callers share one implementation. */
export async function recordClusterDisposition(
  db: ClusterQuery,
  advisoryId: string,
  assetId: string,
  disposition: 'CONFIRMED' | 'FALSE_POSITIVE' | 'NOT_AFFECTED',
): Promise<void> {
  await db.query(
    `INSERT INTO pre_cve_dispositions(cluster_id, asset_id, disposition)
    SELECT m.cluster_id, $2, $3 FROM pre_cve_cluster_members m
    WHERE m.advisory_id=$1 ON CONFLICT (cluster_id, asset_id) DO UPDATE
      SET disposition=EXCLUDED.disposition, decided_at=now()`,
    [advisoryId, assetId, disposition],
  );
}
