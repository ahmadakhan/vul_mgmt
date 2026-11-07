import { randomUUID } from 'node:crypto';
import type { Db } from '../db.ts';
import { timedQuery } from './query.ts';
export interface PendingBatch {
  token: string;
  jobs: { id: string; payload: unknown }[];
}
/**
 * How many times one pending row may be claimed before it is presumed
 * unprocessable. A validation failure or a durability failure is deterministic,
 * so retrying it on every tick re-claims the same row forever: claims are
 * ordered `created_at,id` and `SKIP LOCKED` skips only *live* leases, so the
 * poison row occupies the head of the queue and is attempted again each pass.
 * 20 attempts (~20 minutes of leases) leaves ample room for transient outages —
 * a database recovery, a deploy restart — while bounding the loop.
 */
export const MAX_PENDING_ATTEMPTS = 20;
export async function claimPending(db: Db, limit: number): Promise<PendingBatch> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 32) throw new Error('INVALID_CLAIM_LIMIT');
  const token = randomUUID();
  const result = await db.query<{ id: string; payload: unknown }>(timedQuery(`WITH selected AS (
    SELECT id FROM correlation_pending WHERE (lease_until IS NULL OR lease_until<now())
      AND attempts < $3
    ORDER BY created_at,id LIMIT $1 FOR UPDATE SKIP LOCKED)
    UPDATE correlation_pending p SET lease_until=now()+interval '60 seconds',lease_token=$2,
      attempts=attempts+1
    FROM selected s WHERE p.id=s.id RETURNING p.id,p.payload`, [limit, token, MAX_PENDING_ATTEMPTS]));
  return { token, jobs: result.rows };
}
/** A stale worker can neither delete nor extend another worker's claim. */
export async function renewPending(db: Db, batch: PendingBatch): Promise<number> {
  const result = await db.query(timedQuery(`UPDATE correlation_pending SET lease_until=now()+interval '60 seconds'
    WHERE id=ANY($1::text[]) AND lease_token=$2 AND lease_until>now()`, [batch.jobs.map(job => job.id), batch.token]));
  return result.rowCount || 0;
}
export async function acknowledgePending(db: Db, batch: PendingBatch): Promise<number> {
  const result = await db.query(timedQuery(`DELETE FROM correlation_pending
    WHERE id=ANY($1::text[]) AND lease_token=$2 AND lease_until>now()`, [batch.jobs.map(job => job.id), batch.token]));
  return result.rowCount || 0;
}
/**
 * Acknowledge only the jobs that were handled. A batch whose stream threw has
 * at least one record that is *not* durable; acknowledging the batch would
 * delete it, while acknowledging nothing replays the whole batch and re-runs
 * every match for the records that already committed. The caller supplies the
 * ids that were not durable, and every remaining leased job is deleted.
 */
export async function acknowledgePendingExcept(
  db: Db,
  batch: PendingBatch,
  retainedJobIds: readonly string[],
): Promise<number> {
  const retained = new Set(retainedJobIds);
  const done = batch.jobs.map((job) => job.id).filter((id) => !retained.has(id));
  if (!done.length) return 0;
  const result = await db.query(timedQuery(`DELETE FROM correlation_pending
    WHERE id=ANY($1::text[]) AND lease_token=$2 AND lease_until>now()`, [done, batch.token]));
  return result.rowCount || 0;
}
