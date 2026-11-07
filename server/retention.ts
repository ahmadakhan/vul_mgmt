import type pg from 'pg';
import type { AppSettings, RetentionConfig, RetentionKind, RetentionPreview, RetentionRunResult } from '../src/types/index.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { appendAudit, get, transaction } from './db.ts';

/**
 * Only transient, regenerable records are eligible for retention. Findings,
 * advisories, audit history, checkpoints and configuration are never touched:
 * they are the evidence trail the retention policy exists to preserve.
 */
export const RETENTION_KINDS: readonly RetentionKind[] = [
  'cveData',
  'intelligenceArticles',
  'intelligenceMatches',
  'zeroDayDigests',
  'emailLogs',
  'webhookLogs',
  'executions',
  'events',
];

/**
 * Audit F-3: digests themselves were unbounded — the id is deterministic so a
 * repeat overwrites, but the set of vendor/product pairs grows without limit
 * and nothing aged them. They are therefore retention-eligible by `createdAt`
 * and their cited matches are spared only while the digest survives (see
 * `selectProtectedMatchIds`), so removal loses no evidence: the cap that
 * produced an aged digest would re-derive it identically on the next event.
 */

/** The data timestamp shown in the UI, not the row's insertion time.
 * 'intelligenceMatches' is intentionally absent: its records have no intrinsic
 * timestamp and age by the row's `updated_at`, see `timestampExpression`. */
const TIMESTAMP_FIELDS: Record<Exclude<RetentionKind, 'intelligenceMatches'>, string> = {
  cveData: 'publishedDate',
  intelligenceArticles: 'publishedDate',
  zeroDayDigests: 'createdAt',
  emailLogs: 'sentAt',
  webhookLogs: 'sentAt',
  executions: 'startTime',
  auditLogs: 'timestamp',
  events: 'occurred_at',
};

export interface RetentionRecord {
  kind: RetentionKind;
  id: string;
  timestamp: string | null;
}

export interface RetentionPlan {
  cutoff: string;
  /** Records the policy removes, already filtered and sorted oldest first. */
  delete: { kind: RetentionKind; id: string }[];
  byKind: Record<RetentionKind, number>;
  scanned: number;
  /** Records whose timestamp is missing or unparseable; always retained. */
  unknownAge: number;
}

export type RetentionPolicy = Pick<
  RetentionConfig,
  'enabled' | 'retentionHours' | 'maxArchivedRecords' | 'retentionMode'
>;

const DAY_MS = 86_400_000;

const parseTimestamp = (raw: string | null | undefined): number | null => {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  const value = Date.parse(raw);
  return Number.isFinite(value) ? value : null;
};

const keyOf = (record: { kind: string; id: string }) => `${record.kind}\u0000${record.id}`;
const dayOf = (timestamp: number) => Math.floor(timestamp / DAY_MS);

/**
 * Pure selection step so the destructive part stays small and testable.
 *
 * - strict: delete everything outside the window.
 * - rolling: delete everything outside the window, then trim the oldest
 *   remaining records until the archive ceiling is met.
 * - checkpoints: delete everything outside the window, except keep the newest
 *   record for each UTC day so a daily snapshot of the data survives.
 *
 * A record whose timestamp cannot be parsed is never deleted: silently
 * removing data we cannot age is worse than keeping it.
 */
export function selectRetention(
  records: readonly RetentionRecord[],
  policy: RetentionPolicy,
  nowMs: number,
): RetentionPlan {
  const cutoffMs = nowMs - policy.retentionHours * 3_600_000;
  const byKind = Object.fromEntries(RETENTION_KINDS.map((kind) => [kind, 0])) as Record<
    RetentionKind,
    number
  >;
  const plan: RetentionPlan = {
    cutoff: new Date(cutoffMs).toISOString(),
    delete: [],
    byKind,
    scanned: records.length,
    unknownAge: 0,
  };
  if (!policy.enabled || !Number.isFinite(cutoffMs) || policy.retentionHours <= 0) return plan;

  const aged: { record: RetentionRecord; at: number }[] = [];
  for (const record of records) {
    const at = parseTimestamp(record.timestamp);
    if (at === null) plan.unknownAge++;
    else aged.push({ record, at });
  }

  const doomed = new Set<string>();
  const mark = (record: RetentionRecord) => {
    const key = keyOf(record);
    if (doomed.has(key)) return;
    doomed.add(key);
    byKind[record.kind]++;
  };
  const expired = aged.filter((entry) => entry.at < cutoffMs);

  if (policy.retentionMode === 'checkpoints') {
    // Keep the newest expired record per kind and UTC day; drop the rest.
    const keep = new Map<string, { key: string; at: number; id: string }>();
    for (const entry of expired) {
      const bucket = `${entry.record.kind}\u0000${dayOf(entry.at)}`;
      const current = keep.get(bucket);
      if (
        !current ||
        entry.at > current.at ||
        (entry.at === current.at && entry.record.id > current.id)
      )
        keep.set(bucket, { key: keyOf(entry.record), at: entry.at, id: entry.record.id });
    }
    for (const entry of expired) {
      const bucket = `${entry.record.kind}\u0000${dayOf(entry.at)}`;
      if (keep.get(bucket)?.key !== keyOf(entry.record)) mark(entry.record);
    }
  } else {
    for (const entry of expired) mark(entry.record);
  }

  if (policy.retentionMode === 'rolling' && policy.maxArchivedRecords > 0) {
    const survivors = aged
      .filter((entry) => !doomed.has(keyOf(entry.record)))
      .sort((left, right) => left.at - right.at || left.record.id.localeCompare(right.record.id));
    let total = survivors.length;
    for (const entry of survivors) {
      if (total <= policy.maxArchivedRecords) break;
      mark(entry.record);
      total--;
    }
  }

  plan.delete = aged
    .filter((entry) => doomed.has(keyOf(entry.record)))
    .sort(
      (left, right) =>
        left.at - right.at ||
        left.record.kind.localeCompare(right.record.kind) ||
        left.record.id.localeCompare(right.record.id),
    )
    .map((entry) => ({ kind: entry.record.kind, id: entry.record.id }));
  return plan;
}

const timestampExpression = RETENTION_KINDS.map(
  // Matches carry no intrinsic timestamp (they are re-derived whenever their
  // articles change), so the row's last-write time is the only age signal. Every
  // other kind ages by its own data field.
  (kind) =>
    kind === 'intelligenceMatches'
      ? "WHEN 'intelligenceMatches' THEN to_json(updated_at) #>> '{}'"
      : `WHEN '${kind}' THEN data->>'${(TIMESTAMP_FIELDS as Record<string, string>)[kind]}'`,
).join('\n        ');

async function loadRetentionRecords(
  db: pg.Pool | pg.PoolClient,
): Promise<{ records: RetentionRecord[]; auditCount: number }> {
  const recordsRows = await db.query<RetentionRecord>(
    `SELECT kind, id,
      CASE kind
      ${timestampExpression}
      END AS timestamp
     FROM records
     WHERE kind = ANY($1::text[])`,
    [RETENTION_KINDS.filter((k) => k !== 'auditLogs' && k !== 'events')],
  );

  // Audit rows live in the append-only `audit(seq, data)` table, not `records`.
  // Commit 74e42c0 selected `id, timestamp`, columns that table does not have —
  // every retention run 500'd from then on. The audit chain is intentionally
  // EXCLUDED from deletion (deleting would invalidate hash links), so audit
  // rows are reported through the run summary count instead of being loaded as
  // deletion candidates: a placeholder row per audit entry would inflate both
  // `scanned` (a shared-schema test asserts exactly 3) and `unknownAge`.
  const auditCountRows = await db.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM audit`,
  );
  const auditCount = Number(auditCountRows.rows[0]?.count ?? 0);

  // Load operational events (stored in the separate operational_events table)
  const eventRows = await db.query<{ id: number; occurred_at: string }>(
    `SELECT id, occurred_at FROM operational_events`,
  );

  const records: RetentionRecord[] = [...recordsRows.rows];
  for (const row of eventRows.rows) {
    records.push({ kind: 'events', id: String(row.id), timestamp: row.occurred_at });
  }
  return { records, auditCount };
}

/**
 * Matches that must survive this sweep because something the policy protects
 * still points at them.
 *
 * A zero-day digest names the matches it consolidated, and an open finding
 * names the match it was raised from; deleting cited evidence would leave
 * those records pointing at nothing.
 *
 * Audit F-2: the finding guard originally read `findingId` from the match rows
 * themselves and protected every match that ever had one — a self-referential
 * query that made the sweep a near no-op. References now resolve in the working
 * direction through JOINs, so a citation only pins a match that still exists on
 * the referenced side:
 *  - a SURVIVING digest (not itself doomed) citing the match;
 *  - an OPEN finding naming the match — a resolved, dismissed or deleted
 *    finding releases its match evidence.
 *
 * `doomedDigestIds` excludes digests already selected for deletion, so a fully
 * expired digest does not pin its matches for another cycle.
 */
const OPEN_FINDING_STATUSES = ['MONITORED', 'REMEDIATION_AVAILABLE'] as const;
/**
 * Renders ids as a PostgreSQL text-array literal.
 *
 * Digest ids come from `formatAdvisoryId`/vendor-product slugs, so they are
 * `[A-Za-z0-9_.-]` only: no quoting, no escaping, and no element can introduce
 * a comma or brace. A bare `{}` fails to type-infer when the parameter is used
 * only through casts (audit F-3 probe), so ids are inlined as a literal rather
 * than bound as an untyped parameter.
 */
const asTextArray = (ids: readonly string[]): string =>
  ids.length ? `{${ids.map((id) => id.replace(/[^A-Za-z0-9_.-]/g, '_')).join(',')}}` : '{}';
async function selectProtectedMatchIds(
  db: pg.Pool | pg.PoolClient,
  doomedDigestIds: ReadonlySet<string>,
): Promise<Set<string>> {
  const protectedIds = new Set<string>();
  // Digest citations. Rows already doomed are skipped so their pins lapse with
  // them; every other digest pins only matches that still exist.
  const digestPinned = await db.query<{ matchId: string }>(
    `SELECT DISTINCT m.id AS "matchId"
       FROM records m
       JOIN records d ON d.kind = 'zeroDayDigests'
         AND m.id = ANY(ARRAY(SELECT jsonb_array_elements_text(COALESCE(d.data->'matchIds','[]'::jsonb))))
     WHERE m.kind = 'intelligenceMatches'
       AND NOT (coalesce(array_length($1::text[], 1), 0) > 0 AND d.id = ANY($1::text[]))`,
     // Postgres cannot infer the type of a bare parameter used only inside
     // `$1::text[]`/`cardinality($1::text)` casts on an empty value, so the
     // doomed ids are inlined as a server-side text-array literal.
     [asTextArray([...doomedDigestIds])],
  );
  for (const row of digestPinned.rows) protectedIds.add(row.matchId);
  // Open-finding citations.
  const referenced = await db.query<{ matchId: string }>(
    `SELECT DISTINCT m.data->>'findingId' AS "matchId"
       FROM records m
       JOIN records f ON f.kind = 'findings' AND f.id = m.data->>'findingId'
      WHERE m.kind = 'intelligenceMatches'
        AND m.data->>'findingId' IS NOT NULL
        AND f.data->>'status' = ANY($1::text[])`,
    [OPEN_FINDING_STATUSES],
  );
  for (const row of referenced.rows) protectedIds.add(row.matchId);
  return protectedIds;
}

/**
 * Read-only footprint for the archive screen. Mirrors the selection logic used by
 * a real run so the operator sees both "past the window" and "would be removed"
 * without loading every record into the browser.
 */
export async function previewRetention(
  pool: pg.Pool,
  policy: RetentionPolicy,
): Promise<RetentionPreview> {
  const { records, auditCount } = await loadRetentionRecords(pool);
  const now = Date.now();
  const rawPlan = selectRetention(records, { ...policy, enabled: true }, now);
  // Audit F-4: the preview must apply the same protected-reference filter as
  // the run, or the archive screen overstates deletable matches and an operator
  // approves a destructive policy on numbers the run will not honour. Digests
  // are aged too (audit F-3), so the doomed set feeds the guard exactly as the
  // run computes it.
  const doomedDigestIds = new Set(
    rawPlan.delete.filter((record) => record.kind === 'zeroDayDigests').map((record) => record.id),
  );
  const protectedMatchIds = await selectProtectedMatchIds(pool, doomedDigestIds);
  const deletable = new Map(rawPlan.delete.map((record) => [`${record.kind}\u0000${record.id}`, record]));
  for (const id of protectedMatchIds) deletable.delete(`intelligenceMatches\u0000${id}`);
  const plan: RetentionPlan = {
    ...rawPlan,
    delete: [...deletable.values()],
    byKind: { ...rawPlan.byKind },
  };
  plan.byKind.intelligenceMatches = plan.delete.filter((r) => r.kind === 'intelligenceMatches').length;
  plan.byKind.zeroDayDigests = plan.delete.filter((r) => r.kind === 'zeroDayDigests').length;
  const cutoffMs = now - policy.retentionHours * 3_600_000;
  const buckets = Object.fromEntries(
    RETENTION_KINDS.map((kind) => [kind, { total: 0, past: 0, deletable: plan.byKind[kind] }]),
  ) as RetentionPreview['records'];
  for (const record of records) {
    const bucket = buckets[record.kind];
    bucket.total++;
    const at = parseTimestamp(record.timestamp);
    if (at !== null && at < cutoffMs) bucket.past++;
  }
  // Audit rows live outside `records` and are never deletion candidates, but
  // the archive screen still reports their footprint. auditLogs is not in
  // RETENTION_KINDS (never deletable), so its bucket must be created here.
  buckets.auditLogs = { total: auditCount, past: 0, deletable: 0 };
  const protectedRows = (
    await pool.query<{ kind: string; count: number }>(
      "SELECT kind, count(*)::int AS count FROM records WHERE kind IN ('findings','advisories') GROUP BY kind",
    )
  ).rows;
  const protectedCount = (kind: string) =>
    Number(protectedRows.find((row) => row.kind === kind)?.count ?? 0);
  return {
    cutoff: plan.cutoff,
    records: buckets,
    protected: {
      findings: protectedCount('findings'),
      advisories: protectedCount('advisories'),
    },
    scanned: records.length,
  };
}

/**
 * Apply the saved retention policy once. Returns null when the policy is
 * disabled so callers can distinguish "nothing to do" from "cleanup ran".
 *
 * Runs inside the shared state transaction (advisory lock 800002) so a
 * concurrent pipeline write cannot observe a half-applied cleanup, and writes
 * one audit entry only when records were actually removed.
 */
export async function runRetention(
  pool: pg.Pool,
  actor: string,
  ipAddress = '',
  /** Cancels the sweep inside PostgreSQL instead of only abandoning it. */
  signal?: AbortSignal,
): Promise<RetentionRunResult | null> {
  return transaction(
    pool,
    async (db) => {
      const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
      const policy = settings.retentionConfig;
      if (!policy?.enabled) return null;

    const { records, auditCount } = await loadRetentionRecords(db);
    const plan = selectRetention(records, policy, Date.now());
    // Protected in this sweep: any match a SURVIVING digest still cites, or an
    // OPEN finding names. Digests themselves are aged (audit F-3), so digests
    // selected for deletion pass through as doomed and their pins lapse with
    // them instead of preserving matches for another cycle.
    const doomedDigestIds = new Set(
      plan.delete.filter((record) => record.kind === 'zeroDayDigests').map((record) => record.id),
    );
    const referencedMatchIds = await selectProtectedMatchIds(db, doomedDigestIds);
    plan.delete = plan.delete.filter(
      (record) => record.kind !== 'intelligenceMatches' || !referencedMatchIds.has(record.id),
    );
    for (const kind of RETENTION_KINDS) {
      const ids = plan.delete
        .filter((record) => record.kind === kind)
        // A retained digest or a still-open finding owns this match.
        .filter((record) => !(kind === 'intelligenceMatches' && referencedMatchIds.has(record.id)))
        .map((record) => record.id);
      if (kind === 'intelligenceMatches') plan.byKind[kind] = ids.length;
      // The audit trail is append-only and hash-chained: deleting any row would
      // invalidate the tamper-evidence links, so auditLogs is never a deletion
      // source here regardless of what a policy selection might claim.
      if (kind === 'auditLogs') continue;
      if (kind === 'events') {
        // Delete from the separate operational_events table (id is bigint)
        for (let offset = 0; offset < ids.length; offset += 1000)
          await db.query('DELETE FROM operational_events WHERE id=ANY($1::bigint[])', [
            ids.slice(offset, offset + 1000).map(Number),
          ]);
      } else {
        // Keep each statement's row count bounded so one large backlog cannot hold
        // the state lock for an unbounded amount of time.
        for (let offset = 0; offset < ids.length; offset += 1000)
          await db.query('DELETE FROM records WHERE kind=$1 AND id=ANY($2::text[])', [
            kind,
            ids.slice(offset, offset + 1000),
          ]);
      }
    }

    // Terminal queue rows are transient too. Applying the same policy window
    // keeps an operator's configured retention period authoritative instead of
    // silently trimming them on a fixed schedule.
    // Deletions are batched in 10,000-row chunks using subquery-scoped
    // primary-key lookups to avoid table-level lock contention.
    let outboxDeleted = 0;
    for (;;) {
      const outbox = await db.query(
        "DELETE FROM outbox WHERE id IN (SELECT id FROM outbox WHERE status IN ('ACCEPTED','FAILED','REJECTED') AND updated_at < $1 LIMIT 10000)",
        [new Date(plan.cutoff)],
      );
      outboxDeleted += outbox.rowCount ?? 0;
      if ((outbox.rowCount ?? 0) < 10000) break;
    }

    const eventsDeleted = plan.byKind['events'] ?? 0;
    const actualDeleted = RETENTION_KINDS.reduce((sum, kind) => sum + plan.byKind[kind], 0);
    if (actualDeleted || outboxDeleted || eventsDeleted) {
      const summary = RETENTION_KINDS.filter((kind) => plan.byKind[kind] > 0)
        .map((kind) => `${kind}: ${plan.byKind[kind]}`)
        .join(', ');
      const system = [
        outboxDeleted ? `outbox: ${outboxDeleted}` : '',
      ]
        .filter(Boolean)
        .join(', ');
      await appendAudit(
        db,
        'Retention cleanup',
        `${actualDeleted} record(s) removed${summary ? ` (${summary})` : ''}${system ? `; transient system rows removed (${system})` : ''} using ${policy.retentionMode} mode and a ${policy.retentionHours}h window`,
        actor,
        'SECURITY',
        'INFO',
        ipAddress,
      );
    }

    return {
      ranAt: new Date().toISOString(),
      mode: policy.retentionMode,
      retentionHours: policy.retentionHours,
      cutoff: plan.cutoff,
      scanned: plan.scanned,
      deleted: RETENTION_KINDS.reduce((sum, kind) => sum + plan.byKind[kind], 0),
      unknownAge: plan.unknownAge,
      byKind: plan.byKind,
      system: { outbox: outboxDeleted, events: eventsDeleted },
    };
    },
    undefined,
    // Serialize destructive cleanup across replicas; ordinary mutations are no
    // longer blocked behind a multi-second retention sweep.
    { locks: ['retention-run'], signal },
  );
}
