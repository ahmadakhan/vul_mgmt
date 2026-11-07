import type { Db } from './db.ts';
import { newsArticleIdentity } from './newsEmail.ts';

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
 * the message). Ownership is mandatory (AUD-009): an expired claim that another
 * job has since taken is never deleted by a stale owner, and the ownership check
 * cannot be bypassed by omitting the job. DELIVERED rows are never released: an
 * accepted message is a fact.
 *
 * A claim written during queue creation but whose outbox job was never inserted
 * (or a rollback that left the claim behind) has no owner — that case has its
 * own narrowly scoped path in `releaseUnattachedClaims`.
 */
export async function releaseClaims(
  db: Db,
  requests: readonly ClaimRequest[],
  options: { jobId: string },
): Promise<number> {
  const unique = [...new Map(requests.map((request) => [claimKey(request), request])).values()];
  if (!unique.length) return 0;
  const result = await db.query(
    `DELETE FROM delivery_claims
      WHERE (recipient_id,kind,item_id) IN (SELECT * FROM unnest($1::text[],$2::text[],$3::text[]))
        AND state='CLAIMED'
        AND job_id=$4::uuid`,
    [
      unique.map((request) => request.recipientId),
      unique.map((request) => request.kind),
      unique.map((request) => request.itemId),
      options.jobId,
    ],
  );
  return result.rowCount ?? 0;
}

/**
 * Releases claims that were taken during queue creation but whose outbox job
 * was never inserted (the enqueue deduped, errored, or the transaction rolled
 * back around the claim).
 *
 * AUD-009: deliberately narrow — only rows with `job_id IS NULL` are touched,
 * so this can never free a claim another (real) job holds. A claim that has
 * since been attached to a job is managed exclusively through that job's
 * lifecycle (`releaseClaims`, `markClaimsDelivered`).
 */
export async function releaseUnattachedClaims(
  db: Db,
  requests: readonly ClaimRequest[],
): Promise<number> {
  const unique = [...new Map(requests.map((request) => [claimKey(request), request])).values()];
  if (!unique.length) return 0;
  const result = await db.query(
    `DELETE FROM delivery_claims
      WHERE (recipient_id,kind,item_id) IN (SELECT * FROM unnest($1::text[],$2::text[],$3::text[]))
        AND state='CLAIMED'
        AND job_id IS NULL`,
    [
      unique.map((request) => request.recipientId),
      unique.map((request) => request.kind),
      unique.map((request) => request.itemId),
    ],
  );
  return result.rowCount ?? 0;
}

/**
 * Removes expired CLAIMED rows that no outbox job owns.
 *
 * These are claims taken by a queue pass whose transaction rolled back after the
 * claim was written (or whose enqueue was abandoned mid-transaction): no job
 * exists to manage them through a delivery lifecycle, so the expiry clock is
 * their only recovery path.
 *
 * AUD-006: a claim WITH an owning job is deliberately left alone here, however
 * old it is. That job's own lifecycle owns the claim — the finalize path either
 * promotes it to DELIVERED on acceptance or releases it on a provable
 * non-delivery — and deleting it from a cleanup sweep could free an item whose
 * email is still queued, in flight, or failed with an unresolved outcome.
 * An expired claim whose job row has vanished (retention) is recoverable through
 * the same sweep the job itself would have followed; explicit administrative
 * recovery is the path for anything else.
 */
export async function releaseExpiredClaims(db: Db): Promise<number> {
  const result = await db.query(
    `DELETE FROM delivery_claims
      WHERE state='CLAIMED' AND expires_at < now() AND job_id IS NULL`,
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
        AND state='CLAIMED'
        AND (job_id IS NULL OR job_id=$4::uuid)`,
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

/**
 * Repair newly acquired claims when the outbox dedupe key already exists.
 * An outbox conflict is not proof of delivery: attach claims to the existing
 * queued/unknown job, promote accepted receipts, and release only when no
 * possible sending job holds them. Must run in the same transaction as claimItems.
 */
export async function reconcileDuplicateOutboxClaims(
  db: Db,
  dedupeKey: string,
  requests: readonly ClaimRequest[],
): Promise<void> {
  if (!requests.length) return;
  const prior = await db.query<{ id: string; status: string; delivery_outcome: string; target_id: string; channel: string; payload: Record<string, unknown> }>(
    'SELECT id,status,delivery_outcome,target_id,channel,payload FROM outbox WHERE dedupe_key=$1 FOR UPDATE',
    [dedupeKey],
  );
  const job = prior.rows[0];
  if (!job) {
    await releaseUnattachedClaims(db, requests);
    return;
  }
  // A matching dedupe key alone is not sufficient evidence that the existing
  // job actually carries every item. Reject inconsistent historical payloads.
  const recorded = new Set<string>();
  if (Array.isArray(job.payload.includedFindingIds)) {
    for (const id of job.payload.includedFindingIds)
      if (typeof id === 'string') recorded.add(`finding:${id}`);
  }
  const evidence = job.payload.newsEvidence as { articles?: unknown; article?: unknown } | undefined;
  const articles = Array.isArray(evidence?.articles) ? evidence.articles : evidence?.article ? [evidence.article] : [];
  for (const value of articles) {
    if (!value || typeof value !== 'object') continue;
    const article = value as { id?: unknown; url?: unknown };
    recorded.add(`article:${newsArticleIdentity({
      id: typeof article.id === 'string' ? article.id : '',
      url: typeof article.url === 'string' ? article.url : '',
    })}`);
  }
  if (job.channel !== 'email' || requests.some((request) =>
    request.recipientId !== job.target_id || !recorded.has(`${request.kind}:${request.itemId}`))) {
    throw new Error('Outbox dedupe collision does not contain the claimed recipient/items');
  }
  if (job.status === 'ACCEPTED' || job.delivery_outcome === 'ACCEPTED') {
    await attachClaimsToJob(db, job.id, requests);
    await markClaimsDelivered(db, requests, { jobId: job.id });
  } else if (
    ['QUEUED', 'SENDING', 'REVIEW'].includes(job.status) ||
    (job.status === 'FAILED' && job.delivery_outcome === 'UNKNOWN')
  ) {
    // Preserve the claim even after its provisional expiry. The job might
    // still send, or may already have sent without a confirmed receipt.
    await attachClaimsToJob(db, job.id, requests);
  } else {
    await releaseUnattachedClaims(db, requests);
  }
}
