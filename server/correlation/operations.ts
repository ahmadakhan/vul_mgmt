import { z } from 'zod';
import type { Db } from '../db.ts';
import { appendAudit } from '../db.ts';
import { decrypt, encryptionKeys } from '../secrets.ts';
import { HttpError } from '../validation.ts';
import { AdvisoryInputSchema } from './validation.ts';
import {
  recordClusterDisposition,
  MIN_CLUSTER_OPEN_WINDOW_DAYS,
  MAX_CLUSTER_OPEN_WINDOW_DAYS,
} from './clusters.ts';
import type { CorrelationPolicy, CorrelationWorkflows } from '../../shared/correlation.ts';
const noteSchema = z.string().trim().min(5).max(1000);
export const correlationPolicySchema = z
  .object({
    notificationsEnabled: z.boolean(),
    retentionEnabled: z.boolean(),
    retentionHours: z.number().int().min(24).max(87600),
    // Bounded to match the CHECK constraint in migration 021; omitted values
    // preserve the stored setting so older clients cannot reset the window.
    preCveClusterWindowDays: z
      .number()
      .int()
      .min(MIN_CLUSTER_OPEN_WINDOW_DAYS)
      .max(MAX_CLUSTER_OPEN_WINDOW_DAYS)
      .optional(),
  })
  .strict();
export async function getCorrelationPolicy(db: Db): Promise<CorrelationPolicy> {
  const result = await db.query<CorrelationPolicy>(`SELECT notifications_enabled AS "notificationsEnabled",
    retention_enabled AS "retentionEnabled",retention_hours AS "retentionHours",
    pre_cve_cluster_window_days AS "preCveClusterWindowDays" FROM correlation_policy WHERE id=1`);
  if (!result.rows[0]) throw new Error('CORRELATION_POLICY_MISSING');
  return result.rows[0];
}
export async function updateCorrelationPolicy(
  db: Db,
  raw: unknown,
  actor: string,
): Promise<CorrelationPolicy> {
  const input = correlationPolicySchema.parse(raw);
  // Enabling starts a fresh window. Historical matches never create an alert storm.
  await db.query(
    `UPDATE correlation_policy SET notifications_since=CASE WHEN NOT notifications_enabled AND $1
    THEN now() ELSE notifications_since END,notifications_enabled=$1,retention_enabled=$2,retention_hours=$3,
    pre_cve_cluster_window_days=COALESCE($4,pre_cve_cluster_window_days),updated_at=now() WHERE id=1`,
    [
      input.notificationsEnabled,
      input.retentionEnabled,
      input.retentionHours,
      input.preCveClusterWindowDays ?? null,
    ],
  );
  await appendAudit(db, 'Correlation policy updated', 'Notification and retention policy changed', actor);
  return getCorrelationPolicy(db);
}

/** Read the fleet-wide fault-simulation gate (`correlation_policy.fault_simulation_armed`).
 * This is the per-database half of the gate: the per-replica FAULT_SIMULATION_ENABLED
 * env var alone must never authorize a simulated fault. */
export async function getFaultSimulationArmed(db: Db): Promise<boolean> {
  const result = await db.query<{ armed: boolean }>(
    `SELECT fault_simulation_armed AS armed FROM correlation_policy WHERE id=1`,
  );
  if (!result.rows[0]) throw new Error('CORRELATION_POLICY_MISSING');
  return result.rows[0].armed;
}

/** Arm or disarm the fleet-wide fault-simulation gate (`fault_simulation_armed`).
 * This is the per-database counterpart to the per-replica FAULT_SIMULATION_ENABLED
 * env var: arming the gate on one replica does not arm it fleet-wide on its own. */
export async function setFaultSimulationArmed(db: Db, armed: boolean, actor: string): Promise<boolean> {
  await db.query(`UPDATE correlation_policy SET fault_simulation_armed=$1 WHERE id=1`, [armed]);
  await appendAudit(
    db,
    'Fault simulation arming changed',
    `Fault simulation gate ${armed ? 'armed' : 'disarmed'}`,
    actor,
    'PIPELINE',
  );
  return armed;
}
export async function correlationWorkflows(db: Db): Promise<CorrelationWorkflows> {
  const policy = await getCorrelationPolicy(db);
  const faultSimulationArmed = await getFaultSimulationArmed(db);
  const reviews = await db.query<
    CorrelationWorkflows['reviews'][number]
  >(`SELECT b.id,b.advisory_id AS "advisoryId",
    b.asset_id AS "assetId",b.reason,a.title,left(a.content,2000) AS content,a.url,b.created_at AS "createdAt"
    FROM low_confidence_review_buffer b JOIN unstructured_advisories a ON a.id=b.advisory_id
    LEFT JOIN correlation_review_decisions d ON d.review_id=b.id WHERE d.review_id IS NULL
    ORDER BY b.created_at,b.id LIMIT 50`);
  const deadLetters = await db.query<
    CorrelationWorkflows['deadLetters'][number]
  >(`SELECT l.id,l.tracking_id AS "trackingId",
    l.error_code AS "errorCode",l.created_at AS "createdAt" FROM correlation_dead_letters l
    LEFT JOIN correlation_dead_letter_actions a ON a.letter_id=l.id WHERE a.letter_id IS NULL ORDER BY l.created_at,l.id LIMIT 50`);
  const counts = await db.query<CorrelationWorkflows['counts']>(`SELECT
    (SELECT count(*)::int FROM correlation_pending) AS pending,
    (SELECT count(*)::int FROM low_confidence_review_buffer b WHERE NOT EXISTS(SELECT 1 FROM correlation_review_decisions d WHERE d.review_id=b.id)) AS reviews,
    (SELECT count(*)::int FROM correlation_dead_letters l WHERE NOT EXISTS(SELECT 1 FROM correlation_dead_letter_actions a WHERE a.letter_id=l.id)) AS "deadLetters"`);
  return {
    policy,
    faultSimulationArmed,
    reviews: reviews.rows,
    deadLetters: deadLetters.rows,
    counts: counts.rows[0],
  };
}
export async function decideCorrelationReview(
  db: Db,
  id: string,
  raw: unknown,
  actor: string,
): Promise<void> {
  const input = z
    .object({ decision: z.enum(['APPROVED', 'DISMISSED']), assetId: z.uuid().optional(), note: noteSchema })
    .strict()
    .parse(raw);
  const row = await db.query<{ advisory_id: string; asset_id: string | null }>(
    'SELECT advisory_id,asset_id FROM low_confidence_review_buffer WHERE id=$1 FOR UPDATE',
    [id],
  );
  if (!row.rows[0]) throw new HttpError(404, 'Review not found');
  if ((await db.query('SELECT 1 FROM correlation_review_decisions WHERE review_id=$1', [id])).rowCount)
    throw new HttpError(409, 'Review already decided');
  const assetId = input.assetId || row.rows[0].asset_id;
  if (input.decision === 'APPROVED') {
    if (!assetId) throw new HttpError(400, 'A target asset is required to approve an unmatched article');
    const asset = await db.query<{ vendor: string; product: string; revision: string }>(
      'SELECT vendor,product,revision FROM correlation_asset_inventory WHERE id=$1',
      [assetId],
    );
    if (!asset.rows[0]) throw new HttpError(409, 'Target asset is absent or inactive');
    await db.query(
      `INSERT INTO correlation_matches(advisory_id,asset_id,vendor,product,confidence,reason)
      VALUES($1,$2,$3,$4,'MEDIUM','Operator verified applicability; version scope requires confirmation') ON CONFLICT(advisory_id,asset_id) DO UPDATE SET confidence='MEDIUM',reason=EXCLUDED.reason,created_at=now()`,
      [row.rows[0].advisory_id, assetId, asset.rows[0].vendor, asset.rows[0].product],
    );
    // An operator decision supplies a fresh explicit applicability assertion.
    await db.query(
      `INSERT INTO correlation_match_evidence(advisory_id,asset_id,asset_revision) VALUES($1,$2,$3)
      ON CONFLICT(advisory_id,asset_id) DO UPDATE SET asset_revision=EXCLUDED.asset_revision`,
      [row.rows[0].advisory_id, assetId, asset.rows[0].revision],
    );
  }
  await db.query(
    `INSERT INTO correlation_review_decisions(review_id,decision,asset_id,actor,note) VALUES($1,$2,$3,$4,$5)`,
    [id, input.decision, assetId, actor, input.note],
  );
  // Persist the ruling against the pre-CVE cluster so it survives CVE
  // publication. Without this, the canonical CVE finding re-alerts on an asset
  // the operator already dismissed.
  if (assetId)
    await recordClusterDisposition(
      db,
      row.rows[0].advisory_id,
      assetId,
      input.decision === 'APPROVED' ? 'CONFIRMED' : 'FALSE_POSITIVE',
    );
  await appendAudit(db, 'Correlation review decided', `Review ${id}: ${input.decision}`, actor);
}
export async function decideDeadLetter(
  db: Db,
  id: string,
  raw: unknown,
  actor: string,
  keys: string[],
): Promise<void> {
  const input = z
    .object({
      action: z.enum(['REPLAYED', 'DISMISSED']),
      note: noteSchema,
      payload: AdvisoryInputSchema.optional(),
    })
    .strict()
    .parse(raw);
  const row = await db.query<{ encrypted_payload: string }>(
    'SELECT encrypted_payload FROM correlation_dead_letters WHERE id=$1 FOR UPDATE',
    [id],
  );
  if (!row.rows[0]) throw new HttpError(404, 'Dead letter not found');
  if ((await db.query('SELECT 1 FROM correlation_dead_letter_actions WHERE letter_id=$1', [id])).rowCount)
    throw new HttpError(409, 'Dead letter already decided');
  if (input.action === 'REPLAYED') {
    let payload: unknown = input.payload;
    if (!payload) {
      try {
        payload = JSON.parse(decrypt(row.rows[0].encrypted_payload, keys, 'correlation-dlq'));
      } catch {
        throw new HttpError(409, 'Dead letter cannot be decoded; provide a corrected payload');
      }
    }
    const parsed = AdvisoryInputSchema.safeParse(payload);
    if (!parsed.success)
      throw new HttpError(400, 'Provide a corrected advisory before replaying malformed input');
    await db.query('INSERT INTO correlation_pending(id,payload) VALUES($1,$2) ON CONFLICT DO NOTHING', [
      `replay:${id}`,
      JSON.stringify(parsed.data),
    ]);
  }
  await db.query(
    'INSERT INTO correlation_dead_letter_actions(letter_id,action,actor,note) VALUES($1,$2,$3,$4)',
    [id, input.action, actor, input.note],
  );
  await appendAudit(db, 'Correlation dead letter decided', `Dead letter ${id}: ${input.action}`, actor);
}
export async function cleanupStaleMatches(db: Db): Promise<number> {
  const evidenceDeleted = await db.query(
    `DELETE FROM correlation_match_evidence e
     WHERE NOT EXISTS (
       SELECT 1 FROM correlation_asset_inventory i
       WHERE i.id=e.asset_id AND i.revision=e.asset_revision
     )`,
  );
  const matchesDeleted = await db.query(
    `DELETE FROM correlation_matches m
     WHERE m.asset_id IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM correlation_asset_inventory i
       WHERE i.id=m.asset_id
     )`,
  );
  return (evidenceDeleted.rowCount ?? 0) + (matchesDeleted.rowCount ?? 0);
}
/** Bounded retention; protected inventory, articles and aliases are never deleted. */
export async function retainCorrelationData(db: Db): Promise<number> {
  const policy = await getCorrelationPolicy(db);
  if (!policy.retentionEnabled) return 0;
  const cutoff = new Date(Date.now() - policy.retentionHours * 3600000);
  // Always a transaction-scoped advisory lock, never the session-level form
  // used previously: a session lock taken here is never released, so the pooled
  // connection kept holding it and every later retention run on that connection
  // (and every replica after it) returned 0 without cleaning anything.
  const lock = await db.query<{ locked: boolean }>(
    "SELECT pg_try_advisory_xact_lock(hashtext('correlation-retention'),hashtext(current_schema())) AS locked",
  );
  if (!lock.rows[0]?.locked) return 0;
  const reviews = await db.query(
    `DELETE FROM low_confidence_review_buffer WHERE id IN (
    SELECT b.id FROM low_confidence_review_buffer b JOIN correlation_review_decisions d ON d.review_id=b.id
    WHERE d.decided_at<$1 ORDER BY d.decided_at LIMIT 500)`,
    [cutoff],
  );
  const letters = await db.query(
    `DELETE FROM correlation_dead_letters WHERE id IN (
    SELECT l.id FROM correlation_dead_letters l JOIN correlation_dead_letter_actions a ON a.letter_id=l.id
    WHERE a.decided_at<$1 ORDER BY a.decided_at LIMIT 500)`,
    [cutoff],
  );
  // One sweep per table rather than a DELETE per row: the locked selection is
  // already bounded by LIMIT 500, and two round trips replace up to 1,000.
  // Verified equivalent: the subquery re-derives the exact (advisory_id,
  // asset_id) pairs the FOR UPDATE locked, inside the same transaction and
  // snapshot.
  const evidenceDeleted = await db.query(
    `DELETE FROM correlation_match_evidence e
     WHERE (e.advisory_id,e.asset_id) IN (
       SELECT m.advisory_id,m.asset_id FROM correlation_matches m
       WHERE m.created_at<$1 AND NOT EXISTS(SELECT 1 FROM outbox o WHERE o.advisory_id='NATIVE:'||m.advisory_id::text
         AND o.status IN ('REVIEW','QUEUED','SENDING'))
       LIMIT 500)`,
    [cutoff],
  );
  const matchesDeleted = await db.query(
    // `correlation_matches` is keyed on (advisory_id, asset_id) — commit 91b4381
    // selected a `candidate.id` column this table does not have, so the sweep
    // failed with 42703 on every run. Delete by the real composite key.
    `DELETE FROM correlation_matches m
     WHERE (m.advisory_id,m.asset_id) IN (
       SELECT candidate.advisory_id,candidate.asset_id FROM correlation_matches candidate
       WHERE candidate.created_at<$1
         AND NOT EXISTS(SELECT 1 FROM outbox o WHERE o.advisory_id='NATIVE:'||candidate.advisory_id::text
           AND o.status IN ('REVIEW','QUEUED','SENDING'))
       LIMIT 500)`,
    [cutoff],
  );
  return (reviews.rowCount || 0) + (letters.rowCount || 0) +
    (evidenceDeleted.rowCount || 0) + (matchesDeleted.rowCount || 0);
}
