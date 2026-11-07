import type { Db } from './db.ts';

/**
 * Durable per-recipient delivery claims (AUD-001 / AUD-002).
 *
 * The unit of deduplication is `(recipient, kind, item)` — one finding or one
 * canonical article for one recipient — never a global timestamp on the item and
 * never the content of a batch. That is what makes both properties hold:
 *
 *  - a recipient added after another recipient was already told about a finding
 *    still receives it (the claim is per recipient);
 *  - two concurrent pipeline runs cannot both queue the same item for the same
 *    recipient: the claim is inserted with `ON CONFLICT DO NOTHING` inside the
 *    same transaction that inserts the outbox job, so exactly one run wins.
 *
 * Lifecycle:
 *
 *  - `CLAIMED`  written when the consolidated message is queued. It carries an
 *               expiry so a run that crashes between claiming and enqueueing
 *               cannot suppress the item forever.
 *  - `DELIVERED` written when the transport accepts the message. Permanent; it
 *               is the record that answers "has this recipient been told?".
 *
 * Recovery: a `CLAIMED` row whose `expires_at` has passed is treated as free by
 * `claimItems` (the insert conflicts, so the row is re-taken) and is removed by
 * `releaseExpiredClaims`. A delivery that fails terminally releases its claims
 * immediately (`releaseClaims`), so the next run re-queues the item instead of
 * losing it.
 */

export type ClaimKind = 'finding' | 'article';

export interface ClaimRequest {
  recipientId: string;
  kind: ClaimKind;
  itemId: string;
}

export interface ClaimResult {
  /** Items this caller now owns and must include in its message. */
  granted: ClaimRequest[];
  /** Items another run already claimed or delivered. */
  denied: ClaimRequest[];
}

/**
 * How long a queued-but-unaccepted claim blocks other runs.
 *
 * Long enough to cover the outbox retry budget for a transient transport
 * failure, short enough that a crashed run does not hide a finding for a day.
 */
export const CLAIM_TTL_MS = 6 * 60 * 60 * 1000;

const claimKey = (claim: ClaimRequest) => `${claim.recipientId}\u0000${claim.kind}\u0000${claim.itemId}`;

/**
 * Claims a set of items for a set of recipients.
 *
 * Must run inside the transaction that inserts the outbox job: the claim and the
 * job commit together, so a rollback frees the claim and a commit makes it
 * visible to every other run. `jobId` is recorded for diagnostics and for the
 * delivery worker to mark the claim DELIVERED.
 *
 * A row that is already `DELIVERED` is never re-granted. A `CLAIMED` row is
 * re-granted only once it has expired.
 */
export async function claimItems(
  db: Db,
  requests: readonly ClaimRequest[],
  options: { jobId?: string; ttlMs?: number } = {},
): Promise<ClaimResult> {
  const unique = [...new Map(requests.map((request) => [claimKey(request), request])).values()];
  if (!unique.length) return { granted: [], denied: [] };
  const ttlMs = options.ttlMs ?? CLAIM_TTL_MS;
  const rows = await db.query<{ recipient_id: string; kind: ClaimKind; item_id: string }>(
    // `$3::uuid` is NULL when no job id is supplied yet; the job is attached in
    // the same transaction once the outbox row exists (`attachClaimsToJob`).
    `INSERT INTO delivery_claims(recipient_id,kind,item_id,state,job_id,claimed_at,expires_at)
     SELECT recipient_id,kind,item_id,'CLAIMED',$3::uuid,now(),now()+($4::double precision * interval '1 millisecond')
       FROM unnest($1::text[],$2::text[],$5::text[]) AS t(recipient_id,kind,item_id)
     ON CONFLICT (recipient_id,kind,item_id) DO UPDATE
       SET state='CLAIMED', job_id=EXCLUDED.job_id, claimed_at=now(), expires_at=EXCLUDED.expires_at,
           delivered_at=NULL
       WHERE delivery_claims.state='CLAIMED' AND delivery_claims.expires_at < now()
     RETURNING recipient_id,kind,item_id`,
    [
      unique.map((request) => request.recipientId),
      unique.map((request) => request.kind),
      options.jobId ?? null,
      ttlMs,
      unique.map((request) => request.itemId),
    ],
  );
  const grantedKeys = new Set(
    rows.rows.map((row) =>
      claimKey({ recipientId: row.recipient_id, kind: row.kind, itemId: row.item_id }),
    ),
  );
  return {
    granted: unique.filter((request) => grantedKeys.has(claimKey(request))),
    denied: unique.filter((request) => !grantedKeys.has(claimKey(request))),
  };
}

/**
 * Marks claims DELIVERED after the transport accepted the message.
 *
 * When a job id is supplied, only rows owned by that job are promoted, so a
 * claim that expired and was re-taken by a later run is not overwritten by the
 * stale one. Without a job id every matching CLAIMED row is promoted — the
 * queue pass uses this to promote its own claims immediately.
 */
export async function markClaimsDelivered(
  db: Db,
  requests: readonly ClaimRequest[],
  options: { jobId?: string; deliveredAt?: string } = {},
): Promise<number> {
  const unique = [...new Map(requests.map((request) => [claimKey(request), request])).values()];
  if (!unique.length) return 0;
  const result = await db.query(
    `UPDATE delivery_claims
        SET state='DELIVERED', delivered_at=$4::timestamptz, expires_at=NULL
      WHERE (recipient_id,kind,item_id) IN (
              SELECT * FROM unnest($1::text[],$2::text[],$3::text[])
            )
        AND state='CLAIMED'
        AND ($5::uuid IS NULL OR job_id=$5::uuid)`,
    [
      unique.map((request) => request.recipientId),
      unique.map((request) => request.kind),
      unique.map((request) => request.itemId),
      options.deliveredAt ?? new Date().toISOString(),
      options.jobId ?? null,
    ],
  );
  return result.rowCount ?? 0;
}

/**
 * Releases claims so the items can be queued again.
 *
 * Used when a delivery fails terminally (the recipient never received the
 * message) and when a queue pass claimed items but could not enqueue the job.
 * DELIVERED rows are never released: an accepted message is a fact.
 */
export async function releaseClaims(db: Db, requests: readonly ClaimRequest[]): Promise<number> {
  const unique = [...new Map(requests.map((request) => [claimKey(request), request])).values()];
  if (!unique.length) return 0;
  const result = await db.query(
    `DELETE FROM delivery_claims
      WHERE (recipient_id,kind,item_id) IN (SELECT * FROM unnest($1::text[],$2::text[],$3::text[]))
        AND state='CLAIMED'`,
    [
      unique.map((request) => request.recipientId),
      unique.map((request) => request.kind),
      unique.map((request) => request.itemId),
    ],
  );
  return result.rowCount ?? 0;
}

/** Removes expired CLAIMED rows. DELIVERED rows are permanent. */
export async function releaseExpiredClaims(db: Db): Promise<number> {
  const result = await db.query(
    "DELETE FROM delivery_claims WHERE state='CLAIMED' AND expires_at < now()",
  );
  return result.rowCount ?? 0;
}

/**
 * Reads the claims that currently block delivery for a set of recipients.
 *
 * Returns `recipientId -> Set<itemId>` for every item that is DELIVERED or
 * CLAIMED and not yet expired. This is the read side of the claim; the write
 * side (`claimItems`) is what actually enforces uniqueness.
 */
export async function activeClaims(
  db: Db,
  recipientIds: readonly string[],
  kind: ClaimKind,
  itemIds: readonly string[],
): Promise<Map<string, Set<string>>> {
  const active = new Map<string, Set<string>>(recipientIds.map((id) => [id, new Set<string>()]));
  if (!recipientIds.length || !itemIds.length) return active;
  const rows = await db.query<{ recipient_id: string; item_id: string }>(
    `SELECT recipient_id,item_id FROM delivery_claims
      WHERE kind=$1 AND recipient_id=ANY($2::text[]) AND item_id=ANY($3::text[])
        AND (state='DELIVERED' OR expires_at > now())`,
    [kind, [...recipientIds], [...itemIds]],
  );
  for (const row of rows.rows) active.get(row.recipient_id)?.add(row.item_id);
  return active;
}

/**
 * Records the outbox job that owns a set of claims.
 *
 * Called in the same transaction as the enqueue, so the delivery worker can
 * promote exactly the claims its own message carried and a stale claim that was
 * re-taken by a later run is never overwritten.
 */
export async function attachClaimsToJob(
  db: Db,
  jobId: string,
  requests: readonly ClaimRequest[],
): Promise<number> {
  const unique = [...new Map(requests.map((request) => [claimKey(request), request])).values()];
  if (!unique.length) return 0;
  const result = await db.query(
    `UPDATE delivery_claims SET job_id=$4::uuid
      WHERE (recipient_id,kind,item_id) IN (SELECT * FROM unnest($1::text[],$2::text[],$3::text[]))
        AND state='CLAIMED'`,
    [
      unique.map((request) => request.recipientId),
      unique.map((request) => request.kind),
      unique.map((request) => request.itemId),
      jobId,
    ],
  );
  return result.rowCount ?? 0;
}

/** Claims carried by one outbox job, for the delivery worker's receipt step. */
export function claimsForJob(
  recipientId: string,
  kind: ClaimKind,
  itemIds: readonly string[],
): ClaimRequest[] {
  return itemIds.map((itemId) => ({ recipientId, kind, itemId }));
}
