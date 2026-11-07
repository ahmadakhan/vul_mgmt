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
 *    recipient: the claim is inserted with an `ON CONFLICT` guard inside the
 *    same transaction that inserts the outbox job, so exactly one run wins.
 *
 * Lifecycle:
 *
 *  - `CLAIMED`   written when the consolidated message is queued. The claim is
 *                tied to its owning outbox job: while that job exists in a
 *                QUEUED, SENDING or FAILED-without-confirmation state, the
 *                claim does NOT expire (Finding 4) — a second email must not be
 *                queued while the first may still be delivered. A claim only
 *                becomes reclaimable once its job is terminally gone: terminally
 *                FAILED without confirmed transport acceptance (released
 *                immediately by the finalize path), abandoned (job row deleted
 *                by retention), or expired with no live job.
 *  - `DELIVERED` written when the transport accepts the message. Permanent; it
 *                is the record that answers "has this recipient been told?".
 *
 * Recovery: `releaseClaims(jobId)` deletes only the claims the failing job
 * itself owns (Finding 5) — an expired claim that was re-taken by another job
 * is never deleted by the stale owner. An expired CLAIMED row with no live
 * outbox job is reclaimable through `claimItems` and swept by
 * `releaseExpiredClaims`; rows whose job is still QUEUED or SENDING are never
 * reclaimed.
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
  /** Items another live claim already holds. The caller must release `granted`. */
  denied: ClaimRequest[];
}

/**
 * How long a claim may sit without a live outbox job before another run may
 * reclaim it. This covers only the window between claiming and the outbox row
 * existing — once the job exists, the claim follows the job's lifecycle, not
 * this clock (Finding 4).
 */
export const CLAIM_TTL_MS = 6 * 60 * 60 * 1000;

const claimKey = (claim: ClaimRequest) => `${claim.recipientId}\u0000${claim.kind}\u0000${claim.itemId}`;

/**
 * Claims a set of items for their recipients.
 *
 * Must run inside the transaction that inserts the outbox job: the claim and the
 * job commit together, so a rollback frees the claim and a commit makes it
 * visible to every other run. The returned `jobId` is recorded so the delivery
 * worker can promote exactly the claims its own message carried, and so a
 * terminal failure releases only its own claims.
 *
 * Grant rules:
 *  - a `DELIVERED` claim is never re-granted;
 *  - a `CLAIMED` claim whose job is still QUEUED or SENDING (or FAILED without
 *    a confirmed transport acceptance) is never re-granted, however old it is
 *    (Finding 4): the original email may still be delivered;
 *  - an expired `CLAIMED` claim with no live outbox job is re-granted.
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
    // A claim is retaken only when it is expired AND its owning outbox job no
    // longer legitimately holds the item. QUEUED and SENDING jobs always hold
    // it; a FAILED job holds it until the finalize path releases the claim
    // explicitly (transport acceptance is unconfirmed for anything the finalize
    // path has not released). This is what prevents the expired-claim duplicate
    // email (Finding 4).
    `INSERT INTO delivery_claims(recipient_id,kind,item_id,state,job_id,claimed_at,expires_at)
     SELECT recipient_id,kind,item_id,'CLAIMED',$3::uuid,now(),now()+($4::double precision * interval '1 millisecond')
       FROM unnest($1::text[],$2::text[],$5::text[]) AS t(recipient_id,kind,item_id)
     ON CONFLICT (recipient_id,kind,item_id) DO UPDATE
       SET state='CLAIMED', job_id=EXCLUDED.job_id, claimed_at=now(), expires_at=EXCLUDED.expires_at,
           delivered_at=NULL
      WHERE delivery_claims.state='CLAIMED'
        AND delivery_claims.expires_at < now()
        AND NOT EXISTS (
          SELECT 1 FROM outbox o
           WHERE o.id = delivery_claims.job_id
             AND o.status IN ('QUEUED','SENDING')
        )
        -- A FAILED job holds its claim whenever the finalize path has NOT
        -- released it (the failure may still turn out to be a delivery).
        AND NOT EXISTS (
          SELECT 1 FROM outbox o
           WHERE o.id = delivery_claims.job_id
             AND o.status = 'FAILED'
        )
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
 * Promotion is scoped to the owning job id, so a claim that expired and was
 * re-taken by a later run is not overwritten by the stale one.
 */
export async function markClaimsDelivered(
  db: Db,
  requests: readonly ClaimRequest[],
  options: { jobId: string; deliveredAt?: string },
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
        AND job_id=$5::uuid`,
    [
      unique.map((request) => request.recipientId),
      unique.map((request) => request.kind),
      unique.map((request) => request.itemId),
      options.deliveredAt ?? new Date().toISOString(),
      options.jobId,
    ],
  );
  return result.rowCount ?? 0;
}

/**
 * Releases ONLY the claims owned by the given job.
 *
 * Used when a delivery fails terminally (the recipient provably never received
 * the message) and when a queue pass claimed items but could not enqueue the
 * job. Ownership is enforced (Finding 5): an expired claim that another job has
 * since taken is never deleted by the stale owner. DELIVERED rows are never
 * released: an accepted message is a fact.
 *
 * Administrative recovery of orphaned claims (no owning job, or a job that can
 * no longer be reconstructed) goes through `releaseExpiredClaims`, which never
 * touches a claim whose outbox job is still live.
 */
export async function releaseClaims(
  db: Db,
  requests: readonly ClaimRequest[],
  options: { jobId?: string } = {},
): Promise<number> {
  const unique = [...new Map(requests.map((request) => [claimKey(request), request])).values()];
  if (!unique.length) return 0;
  const result = await db.query(
    `DELETE FROM delivery_claims
      WHERE (recipient_id,kind,item_id) IN (SELECT * FROM unnest($1::text[],$2::text[],$3::text[]))
        AND state='CLAIMED'
        AND ($4::uuid IS NULL OR job_id=$4::uuid)`,
    [
      unique.map((request) => request.recipientId),
      unique.map((request) => request.kind),
      unique.map((request) => request.itemId),
      options.jobId ?? null,
    ],
  );
  return result.rowCount ?? 0;
}

/**
 * Removes expired CLAIMED rows whose owning job no longer legitimately holds
 * the item. DELIVERED rows are permanent; rows whose job is QUEUED or SENDING
 * (or FAILED with an unconfirmed transport outcome) always hold the item.
 */
export async function releaseExpiredClaims(db: Db): Promise<number> {
  const result = await db.query(
    `DELETE FROM delivery_claims
      WHERE state='CLAIMED' AND expires_at < now()
        AND (
          -- No owning job at all (claim written but the enqueue never happened).
          job_id IS NULL
          -- The job row is gone (retention swept it).
          OR NOT EXISTS (SELECT 1 FROM outbox o WHERE o.id = delivery_claims.job_id)
          -- The job failed terminally; only the finalize path can release its
          -- claim while it exists, so an unreleased FAILED claim is stale here.
          OR EXISTS (
            SELECT 1 FROM outbox o
             WHERE o.id = delivery_claims.job_id AND o.status = 'FAILED'
          )
        )`,
  );
  return result.rowCount ?? 0;
}

/**
 * Reads the claims that currently block delivery for a set of recipients.
 *
 * Returns `recipientId -> Set<itemId>` for every item that is DELIVERED, or
 * CLAIMED and not reclaimable (unexpired, or expired while its job is still
 * live). This is the read side of the claim; the write side (`claimItems`) is
 * what actually enforces uniqueness.
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
    `SELECT c.recipient_id, c.item_id FROM delivery_claims c
      WHERE c.kind=$1 AND c.recipient_id=ANY($2::text[]) AND c.item_id=ANY($3::text[])
        AND (c.state='DELIVERED'
          OR c.expires_at > now()
          OR EXISTS (
            SELECT 1 FROM outbox o
             WHERE o.id = c.job_id AND o.status IN ('QUEUED','SENDING')
          )
          -- A FAILED job holds its claim until its finalize path releases it.
          OR EXISTS (
            SELECT 1 FROM outbox o
             WHERE o.id = c.job_id AND o.status = 'FAILED'
          ))`,
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
