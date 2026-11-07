import { describeError, writeEvent } from './events';
import { mergeArticles, matchIntelligence } from '../src/utils/intelligenceMatcher';
import { formatExecutionName, formatAdvisoryId } from '../src/utils/executionName';
import type pg from 'pg';
import { randomUUID, createHash } from 'node:crypto';
import {
  get,
  getForUpdate,
  getMany,
  list,
  put,
  putMany,
  removeMany,
  transaction,
  appendAudit,
  pipelineState,
  schemaLockKey,
} from './db';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type {
  AppSettings,
  PipelineExecution,
  ThreatFeed,
  Advisory,
  Finding,
  NormalizedCVE,
  WatchListItem,
  AliasEntry,
  EmailDeliveryLog,
  WebhookDeliveryLog,
  EmailRecipient,
  IntelligenceMatch,
  IntelligenceArticle,
} from '../src/types/index.ts';
import { buildAliasMap, parseCPE23 } from '../src/utils/cpeMatcher';
import {
  deriveCorrelationAliases,
  deriveInventoryAliases,
  reconcileAutoAliases,
} from '../src/utils/aliasLifecycle';
import { mergeCveRecords, normalizeCveId, stableJson } from '../src/utils/deduplicator';
import { countNewFindings, findingIdentity, reconcileFindings } from '../src/engine/reconcileFindings';
import {
  applyVexSuppression,
  determineExploitRisk,
  MAX_ZERO_DAYS_PER_RUN,
  rankAndRateLimitZeroDays,
  runVulnerabilityPipeline,
} from '../src/engine/pipelineEngine';
import { ingestFeed, type IngestContext, FeedDeferred } from './ingestion';
import { assessFindings } from './ml/assessment.ts';
import {
  predictCredibilityWeights,
  computeFeedRecoveryDelay,
  shouldAutoDispatch,
  rankReviewFindings,
  predictMatchConfidence,
  predictSeverityTier,
  predictAliasConfidence,
  classifyDeliveryError,
  mlOrderFindingsByImportance,
  predictExploitRisk,
  calibrateCredibilityScore,
  getZeroDayCap,
} from './ml/integration.ts';
import { bindClusterToCve, clusterSuppressedAssets } from './correlation/clusters.ts';
import { refreshCandidatePairs } from './versionIndex';
import { recoveryDue, recoveryAt, isPermanentFeedFailure, shouldStartAutomaticRun } from './feedRecovery';
import { ingestionWindow, type FeedCursor, OPENCVE_MAX_WINDOW_HOURS } from './ingestionState';
import type { Requester } from './network';
import { withAbortSignal } from './network';
import { feedEgressHosts, type Config } from './config';
import {
  enqueue,
  deliveryRevisionEvidence,
  findingRevision,
  queueAdvisory,
  queueConsolidatedFindingNotifications,
  recipientAllows,
  revision,
  type Job,
} from './delivery';
import { bufferFindingsForDigest } from './digest';
import { loadNewsRecipients, queueConsolidatedNews, newsArticleIdentity } from './newsQueue';
import { renderAdvisory } from './advisoryRender';
import { HttpError } from './validation';
import { advisoryEmail } from './advisoryEmail';
import { currentAdvisoryView, currentAdvisoryBody } from './advisoryRebuild';
export { renderAdvisory } from './advisoryRender';
/**
 * Rebuilds a queued job's stored payload from current intelligence.
 *
 * Jobs queued before content-revision evidence existed (or whose payload was
 * queued under an older revision scheme) carry no `cveRevisions`, so the
 * delivery worker cannot prove the advisory text still describes the current
 * CVE corpus. Rather than failing such a job permanently, the payload is
 * regenerated from the advisory and the findings it currently references, with
 * fresh `cveRevisions` / `findingRevisions` computed from the current cache. A
 * job whose findings no longer match the stored CVE revisions keeps its stale
 * evidence, so the worker's normal applicability check still rejects it and
 * rebuilds the bundle instead of delivering outdated content.
 *
 * Returns true when the payload was rewritten; false when the job no longer
 * exists, belongs to a native correlation (which has its own evidence hash), or
 * already carries revision evidence.
 */
export async function rebuildLegacyDeliveryPayload(db: pg.Pool | pg.PoolClient, job: Job): Promise<boolean> {
  if (job.payload.nativeCorrelation) return false;
  const advisory = await get<Advisory>(db, 'advisories', job.advisory_id);
  if (!advisory) return false;
  const declaredCves = job.payload.cveIds ?? advisory.cveIds;
  const evidence = job.payload.cveRevisions ?? {};
  if (declaredCves.every(cveId => evidence[cveId])) return false;
  const findingIds = job.payload.includedFindingIds ?? advisory.findingIds;
  const findingMap = await getMany<Finding>(db, 'findings', findingIds);
  if (!findingIds.length || findingMap.size !== new Set(findingIds).size) return false;
  const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
  const aliases = await list<AliasEntry>(db, 'aliases');
  const current: Finding[] = [];
  for (const finding of findingMap.values()) {
    // Serial: `db` is a single client inside this transaction, and issuing
    // queries concurrently on one pg connection races the protocol queue.
    const asset = await get<WatchListItem>(db, 'watchlist', finding.matchedAssetId);
    const cve = await get<NormalizedCVE>(db, 'cveData', finding.cveId);
    const withdrawal = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', finding.cveId);
    if (!asset?.active || !cve || ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) ||
        (withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate))) return false;
    const match = runVulnerabilityPipeline([], [cve], [asset], [], [], { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
      'Server worker', false, buildAliasMap(aliases, 'VENDOR'), buildAliasMap(aliases, 'PRODUCT'), undefined, aliases).newFindings[0];
    if (match?.notificationStatus !== 'QUEUED_FOR_DISPATCH') return false;
    current.push({ ...finding, ...match, id: finding.id });
  }
  const view = currentAdvisoryView(advisory, current);
  if (view.cveIds.length !== new Set(declaredCves).size || declaredCves.some(id => !view.cveIds.includes(id))) return false;
  const payload = {
    ...job.payload,
    ...await currentAdvisoryBody(db, view, current),
    cveIds: view.cveIds,
    includedFindingIds: view.findingIds,
    // Single canonical evidence-builder (audit L-6): the same revision maps are
    // produced by `deliveryRevisionEvidence` (delivery.ts) everywhere else.
    ...deliveryRevisionEvidence(current),
  };
  const updated = await db.query(
    "UPDATE outbox SET payload=$2::jsonb, review_approved=false, updated_at=now() WHERE id=$1 AND (status='QUEUED' OR (status='SENDING' AND lock_token=$3))",
    [job.id, JSON.stringify(payload), job.lock_token],
  );
  if (!updated.rowCount) return false;
  job.payload = payload;
  job.review_approved = false;
  return true;
}

type KevSnapshot = {
  fingerprint: string;
  etag?: string;
  kev: NonNullable<Awaited<ReturnType<typeof ingestFeed>>['kev']>;
};
const sourceFingerprint = (feed: ThreatFeed) =>
  createHash('sha256')
    .update(JSON.stringify([feed.type, feed.url, feed.authType, feed.authSecretKey || '']))
    .digest('hex');
/**
 * Shallow content view of a stored CVE, used to decide whether this run changed
 * it.
 *
 * Audit H-3: change detection compared `stableJson(wholeRecord)` for every CVE
 * in the corpus on every run, which required keeping a second full copy of the
 * corpus in memory and serialising several hundred thousand objects per run.
 * Only applicability-affecting fields can change correlation output; the
 * remaining fields (EPSS, KEV, exploit status) are updated in place below and do
 * not need to invalidate the candidate index.
 */
function cveContentView(cve: NormalizedCVE): string {
  return stableJson({
    cveId: cve.cveId,
    title: cve.title,
    description: cve.description,
    publishedDate: cve.publishedDate,
    modifiedDate: cve.modifiedDate,
    cvss: cve.cvss,
    cpeMatches: cve.cpeMatches,
    cpeMatchDetails: cve.cpeMatchDetails,
    versionRange: cve.versionRange,
    purls: cve.purls,
    sourceApplicability: cve.sourceApplicability,
    applicabilityRequiresReview: cve.applicabilityRequiresReview,
    applicabilityPolicy: cve.applicabilityPolicy,
    // Risk metadata is written by the enrichment pass below, so it must be part
    // of the change comparison or a KEV/EPSS update is never persisted.
    cisaKev: cve.cisaKev,
    epss: cve.epss,
    exploitStatus: cve.exploitStatus,
    exploitationSources: cve.exploitationSources,
  });
}

/**
 * (vendor, product) identities a CVE asserts, used to join pre-CVE clusters.
 * Derived only from non-wildcard CPE criteria; a CVE with no parseable
 * structured identity cannot bind a cluster (binding on prose would let a
 * poisoned CVE claim another vulnerability's rulings).
 */
function cveClusterIdentities(cve: NormalizedCVE): { vendor: string; product: string }[] {
  const criteria = cve.cpeMatchDetails?.length
    ? cve.cpeMatchDetails.map((detail) => detail.criteria)
    : cve.cpeMatches;
  const identities = new Map<string, { vendor: string; product: string }>();
  for (const criterion of criteria) {
    const parsed = parseCPE23(criterion);
    if (!parsed.isValid || /[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) continue;
    const vendor = parsed.vendor.toLowerCase();
    const product = parsed.product.toLowerCase();
    identities.set(`${vendor}\u0000${product}`, { vendor, product });
  }
  return [...identities.values()];
}

/** Bounded retries for a pre-CVE disposition bind that lost its lock race. */
const DEFERRED_BIND_MAX_ATTEMPTS = 5;

 export async function queueRun(
  pool: pg.Pool,
  scope: number | undefined,
  actor: string,
  incrementalFeeds = true,
  client?: pg.PoolClient,
): Promise<PipelineExecution> {
  return transaction(
    pool,
    async (db) => {
      // Only the active execution matters here. `list('executions')` loaded
      // every run ever recorded and de-serialised it in JavaScript, which on a
      // long-lived installation grew past the 15 s pool statement timeout and
      // turned "queue a run" into a 500. The JSONB status is indexed.
      const active = await db.query<{ data: PipelineExecution }>(
        "SELECT data FROM records WHERE kind='executions' AND data->>'status' IN ('QUEUED','RUNNING') ORDER BY updated_at DESC LIMIT 1",
      );
      const existing = active.rows[0]?.data;
      if (existing) return existing;
      const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
      const id = randomUUID();
      const execution: PipelineExecution = {
        id,
        name: formatExecutionName(id),
        startTime: new Date().toISOString(),
        endTime: null,
        status: 'QUEUED',
        scopeHours: scope ?? settings.scopeHours,
        incrementalFeeds,
        phases: [],
        stats: {
          rawIngested: 0,
          normalized: 0,
          deduplicated: 0,
          inRunDuplicatesDropped: 0,
          matchedWatchlist: 0,
          autoDispatchedNotifications: 0,
          advisoriesDispatched: 0,
          webhooksFired: 0,
          vexSuppressedCount: 0,
        },
        logs: [],
      };
      await put(db, 'executions', id, execution);
      await writeEvent(db, {
        category: 'PIPELINE',
        code: 'pipeline.queued',
        message: 'Pipeline queued',
        runId: id,
      });
      await appendAudit(db, 'Pipeline queued', `Execution ${id}`, actor, 'PIPELINE');
      return execution;
    },
    client,
    client
      ? { locks: [], lockAcquired: ['pipeline-queue'] }
      : { locks: ['pipeline-queue'] },
  );
}
/** Recover an unsent stale advisory after its failed attempt is committed.
 * Rebuild applicable subsets, invalidate remaining queued siblings, and leave
 * every in-flight delivery lease untouched. Policy holds do not start ingestion
 * loops; a wholly inapplicable bundle schedules one reconciliation run.
 */
export async function rebuildFromCurrentInventory(
  pool: pg.Pool,
  advisoryId: string,
  reason: string,
  options: { payloadRebuilt?: boolean } = {},
): Promise<void> {
  if (!options.payloadRebuilt) {
    const legacy = await pool.query<Job>(
      "SELECT * FROM outbox WHERE advisory_id=$1 AND status='QUEUED' AND payload->'cveRevisions' IS NULL",
      [advisoryId],
    );
    for (const job of legacy.rows) await rebuildLegacyDeliveryPayload(pool, job).catch(() => false);
  }
  // Regroup the still-deliverable jobs of this bundle before failing the rest,
  // so a single held finding cannot silently drop the deliverable findings.
  const { regrouped, holdGated } = await regroupStaleAdvisory(pool, advisoryId).catch(() => ({
    regrouped: false,
    holdGated: false,
  }));
  await transaction(pool, async db => {
    const invalidated = await db.query<{ id: string; channel: string; attempts: number }>(
      `UPDATE outbox
         SET status='FAILED', error=$1, next_attempt=now(),
             locked_at=NULL, lock_token=NULL, updated_at=now()
       WHERE advisory_id=$2 AND status='QUEUED' RETURNING id,channel,attempts`,
      [reason, advisoryId],
    );
    for (const row of invalidated.rows) {
      if (row.channel === 'email') {
        const log = await getForUpdate<EmailDeliveryLog>(db, 'emailLogs', row.id);
        if (log) await put(db, 'emailLogs', row.id, { ...log, status: 'FAILED', attemptCount: row.attempts, nextRetryTime: null, errorMessage: reason });
      } else {
        const log = await getForUpdate<WebhookDeliveryLog>(db, 'webhookLogs', row.id);
        if (log) await put(db, 'webhookLogs', row.id, { ...log, status: 'FAILED', errorMessage: reason });
      }
    }
  });
  // Fresh replacement jobs are already queued. Only a wholly inapplicable
  // bundle needs correlation to reconcile inventory; policy holds await review.
  if (!regrouped && !holdGated) await queueRun(pool, 24, 'delivery-rebuild');
}
/** Regenerate unsent delivery subsets from current inventory and policy.
 * Queued jobs move to a fresh advisory; failed pre-transport attempts retain
 * their history and receive an idempotent replacement. Accepted and sending
 * jobs are excluded. Only the retained findings bind to the new advisory.
 */
export async function regroupStaleAdvisory(
  pool: pg.Pool,
  advisoryId: string,
): Promise<{ regrouped: boolean; holdGated: boolean }> {
  return transaction(pool, async (db) => {
    const advisory = await get<Advisory>(db, 'advisories', advisoryId);
    if (!advisory) return { regrouped: false, holdGated: false };
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    const jobs = (
      await db.query<Job>(
        "SELECT * FROM outbox WHERE advisory_id=$1 AND (status='QUEUED' OR (status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%')) AND payload->'nativeCorrelation' IS NULL FOR UPDATE",
        [advisoryId],
      )
    ).rows;
    if (!jobs.length) return { regrouped: false, holdGated: false };
    const aliasEntries = await list<AliasEntry>(db, 'aliases');
    const vendorAliases = buildAliasMap(aliasEntries, 'VENDOR');
    const productAliases = buildAliasMap(aliasEntries, 'PRODUCT');
    const deliverability = new Map<string, boolean>();
    const evidence = new Map<
      string,
      { cveRevisions: Record<string, string>; findingRevisions: Record<string, string>; findings: Finding[] }
    >();
    let holdGated = false;
    for (const job of jobs) {
      const findingIds = job.payload.includedFindingIds ?? advisory.findingIds;
      const findings = [...(await getMany<Finding>(db, 'findings', findingIds)).values()];
      const cves = await getMany<NormalizedCVE>(db, 'cveData', [...new Set(findings.map((f) => f.cveId))]);
      const assets = await getMany<WatchListItem>(db, 'watchlist', [...new Set(findings.map((f) => f.matchedAssetId))]);
      const cveRevisions: Record<string, string> = {};
      const findingRevisions: Record<string, string> = {};
      const current: Finding[] = [];
      for (const finding of findings) {
        const cve = cves.get(finding.cveId) || finding.cve;
        const asset = assets.get(finding.matchedAssetId);
        if (cve) cveRevisions[cve.cveId] = revision(cve);
        // Only findings the current policy and inventory still admit may move to
        // the new bundle; a review-held or unverifiable finding stays in place and
        // is finalized by the caller's FAILED update.
        const withdrawal = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', finding.cveId);
        if (!asset?.active || !cve || ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) ||
            (withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate))) {
          continue;
        }
        const match = runVulnerabilityPipeline(
          [],
          [cve],
          [asset],
          [],
          [],
          { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
          'Server worker',
          false,
          vendorAliases,
          productAliases,
          undefined,
          aliasEntries,
        ).newFindings[0];
        // Limited-confidence matches are dispatched too (the email states the
        // limitation), so they are admitted exactly like QUEUED_FOR_DISPATCH.
        if (match?.notificationStatus !== 'QUEUED_FOR_DISPATCH' && match?.notificationStatus !== 'REVIEW_REQUIRED') {
          continue;
        }
        const fresh = { ...finding, ...match, id: finding.id };
        findingRevisions[finding.id] = findingRevision(fresh);
        current.push(fresh);
      }
      deliverability.set(job.id, current.length > 0);
      evidence.set(job.id, { cveRevisions, findingRevisions, findings: current });
    }
    const regroup = jobs.filter((job) => deliverability.get(job.id));
    if (!regroup.length) return { regrouped: false, holdGated };
    const isDigest = Boolean(jobs[0].payload.digestKey) && jobs.every((job) => job.payload.digestKey === jobs[0].payload.digestKey);
    const replacement: Advisory = {
      ...currentAdvisoryView(advisory, [...new Map(regroup.flatMap(job => evidence.get(job.id)!.findings.map(f => [f.id, f] as const))).values()]),
      id: formatAdvisoryId(settings.advisoryPrefix),
      createdDate: new Date().toISOString(),
      deliveryStatus: 'PENDING',
    };
    let regroupedJobs = 0;
    let emailJobs = 0;
    for (const job of regroup) {
      const { cveRevisions, findingRevisions, findings: groupedFindings } = evidence.get(job.id)!;
      const included = groupedFindings.map(f => f.id);
      const body = await currentAdvisoryBody(db, currentAdvisoryView(replacement, groupedFindings), groupedFindings);
      const payload = {
        ...job.payload,
        ...body,
        cveIds: Array.from(new Set(groupedFindings.map(f => f.cveId))).sort(),
        includedFindingIds: included,
        // Canonical evidence-builder (audit L-6); `findingRevisions` from the
        // scan loop is keyed identically, so it is replaced wholesale.
        ...deliveryRevisionEvidence(groupedFindings),
        digestKey: isDigest ? `${job.payload.digestKey}:regrouped` : undefined,
      };
      // Preserve the failed attempt and its log. A deterministic rebuild key
      // coalesces equivalent failed jobs for the same recipient. Keying by the
      // source job id lets repeated stale-bundle recovery create one replacement
      // per retrying row and send the same content repeatedly.
      if ((job as Job & { status?: string }).status === 'FAILED') {
        const fingerprint = createHash('sha256')
          .update(stableJson({
            cveRevisions: payload.cveRevisions,
            findingRevisions,
            included,
          }))
          .digest('hex');
        const inserted = await enqueue(db, job.channel, job.target_id, replacement.id, payload,
          `rebuild:${job.channel}:${job.target_id}:${fingerprint}`, 'QUEUED', job.priority || 0);
        if (!inserted) continue;
      } else {
      await db.query(
        `UPDATE outbox
            SET advisory_id=$2, payload=$3::jsonb, review_approved=false, status='QUEUED', attempts=0,
                locked_at=NULL, lock_token=NULL, next_attempt=now(), error=NULL, updated_at=now()
          WHERE id=$1 AND (status='QUEUED' OR (status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%'))`,
        [
          job.id,
          replacement.id,
          JSON.stringify(payload),
        ],
      );
      }
      regroupedJobs++;
      if (job.channel === 'email') emailJobs++;
      for (const finding of groupedFindings) {
        await put(db, 'findings', finding.id, { ...finding, advisoryId: replacement.id, notificationStatus: 'QUEUED_FOR_DISPATCH' });
      }
    }
    if (!regroupedJobs) return { regrouped: true, holdGated };
    await put(db, 'advisories', replacement.id, { ...replacement, recipientCount: emailJobs });
    await writeEvent(db, {
      category: 'EMAIL',
      code: 'delivery.bundle_regrouped',
      message: `Regrouped ${regroupedJobs} deliverable job(s) from a stale advisory bundle`,
      context: { staleAdvisoryId: advisoryId, advisoryId: replacement.id, jobs: regroupedJobs },
    });
    return { regrouped: true, holdGated };
  });
}
class PipelineStopped extends Error {
  constructor() {
    super('Pipeline stopped by operator; uncommitted results discarded');
  }
}
/**
 * A source that cannot finish within its configured window.
 *
 * Audit R-2: this used to be a plain `Error` that fell through the generic
 * failure branch, so a slow-but-healthy source was recorded as DOWN, consumed
 * one of its `consecutiveFailures`, and could open its circuit breaker. A
 * deadline is a capacity signal about *this run*, not evidence that the source
 * is unreachable, so it is classified separately and never fed to recoveryAt.
 */
class FeedDeadlineExceeded extends Error {
  constructor() {
    super('Feed ingestion exceeded its configured duration limit');
    this.name = 'FeedDeadlineExceeded';
  }
}

/** Bounds the in-memory execution log.
 *
 * Audit P-3: every feed worker appended to the execution's log array, and the
 * whole object was persisted on every source. With N feeds that is O(N^2)
 * JSON written per run, and the record grows without limit across a long
 * bootstrap. Recent entries are what an operator reads; older ones are already
 * in `operational_events`.
 *
 * Audit F-1: the cap must never touch the crash-recovery counter. Counting
 * restarts by scanning log lines meant one eviction of the marker silently
 * reset the poison-pill budget and a crashing worker restarted forever. The
 * count now lives in `stats.recoveryAttempts`, which the cap cannot reach;
 * `countRecoveries` still reads the historical marker so executions persisted
 * by older builds keep their budget across a deploy.
 */
const EXECUTION_LOG_LIMIT = 200;
/** Log fragment older builds used as the recovery counter. Read-only. */
const LEGACY_RECOVERY_MARKER = 'Recovered interrupted worker';
/**
 * Lines that are operational state, not narration. Audit F-1: the recovery
 * counter used to live in a log line, and audit P-1's regression test asserts
 * the stop marker survives a long feed run — eviction of either silently broke
 * the crash-recovery budget or erased the operator's stop decision. Both are
 * pinned to the tail on every bound.
 */
const PINNED_LOG_MARKERS = [LEGACY_RECOVERY_MARKER, 'Operator requested stop'] as const;
const isPinnedLogLine = (line: string) => PINNED_LOG_MARKERS.some((marker) => line.includes(marker));
function countRecoveries(execution: PipelineExecution): number {
  return Math.max(Number.isFinite(Number(execution.stats.recoveryAttempts)) ? Number(execution.stats.recoveryAttempts) : 0, 0);
}
function pushExecutionLog(execution: PipelineExecution, line: string) {
  execution.logs.push(line);
  boundExecutionLogs(execution.logs);
}
/** Applies the log bound in place, keeping pinned state lines, and returns it. */
function boundExecutionLogs(logs: string[]): string[] {
  if (logs.length <= EXECUTION_LOG_LIMIT) return logs;
  const pinned = logs.filter(isPinnedLogLine);
  const evictionPool = logs.filter((line) => !isPinnedLogLine(line));
  const evictCount = logs.length - EXECUTION_LOG_LIMIT;
  const evicted = new Set(evictionPool.slice(0, evictCount));
  const kept = logs.filter((line) => !evicted.has(line));
  logs.length = 0;
  logs.push(...kept);
  return logs;
}
/** Atomically reject a stale worker write after an operator has stopped a run.
 * A checkpoint read alone leaves a race before the following JSON upsert. */
async function saveActiveExecution(db: pg.PoolClient, execution: PipelineExecution) {
  const saved = await db.query(
    `UPDATE records SET data=$2::jsonb,updated_at=now()
     WHERE kind='executions' AND id=$1 AND data->>'status' IN ('QUEUED','RUNNING')
       AND COALESCE(data->>'stopRequestedAt','')='' RETURNING id`,
    [execution.id, JSON.stringify(execution)],
  );
  if (saved.rowCount) return;
  if (!(await get(db, 'executions', execution.id))) throw new Error('Pipeline execution no longer exists');
  throw new PipelineStopped();
}
export async function stopRun(pool: pg.Pool, id: string, actor: string): Promise<PipelineExecution> {
  return stopRunWithClient(pool, id, actor);
}

/**
 * Record a stop in a queue-serialized transaction, optionally reusing the
 * worker's connection. Network ingestion never holds the queue-admission lock.
 */
export async function stopRunWithClient(
  pool: pg.Pool,
  id: string,
  actor: string,
  lockClient?: pg.PoolClient,
): Promise<PipelineExecution> {
    return transaction(
      pool,
      async (db) => {
        const run = await getForUpdate<PipelineExecution>(db, 'executions', id);
        if (!run) throw new HttpError(404, 'Execution not found');
        if (!['QUEUED', 'RUNNING'].includes(run.status) || run.stopRequestedAt) return run;
        run.stopRequestedAt = new Date().toISOString();
        if (run.status === 'QUEUED') {
          run.status = 'CANCELLED';
          run.endTime = run.stopRequestedAt;
        }
        run.logs.push('Operator requested stop');
        await put(db, 'executions', id, run);
        await writeEvent(db, {
          category: 'PIPELINE',
          code: 'pipeline.stop_requested',
          message: 'Operator requested pipeline stop',
          runId: id,
          context: {
            actor,
            stopRequestedAt: run.stopRequestedAt,
          },
        });
        await appendAudit(db, 'Pipeline stop requested', `Execution ${id}`, actor, 'PIPELINE');
        return run;
      },
      lockClient,
      { locks: ['pipeline-queue'] },
    );
}
export async function processPipeline(pool: pg.Pool, config: Config, request: Requester, signal?: AbortSignal, onProgress?: () => void): Promise<boolean> {
  signal?.throwIfAborted();
  const lock = await pool.connect();
  let connectionLost = false;
  const onError = () => {
    connectionLost = true;
  };
  lock.on('error', onError);
  const lockedTransaction = <T>(fn: (db: pg.PoolClient) => Promise<T>) => transaction(pool, fn, lock, {
    locks: ['pipeline-queue'],
    signal,
  });
  let locked = false,
    execution: PipelineExecution | undefined;
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  let released = false;
  const onAbort = () => {
    connectionLost = true;
    if (heartbeat) clearInterval(heartbeat);
    if (!released) {
      released = true;
      lock.release(true);
    }
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    if (signal?.aborted) {
      onAbort();
      signal.throwIfAborted();
    }
    locked = (await lock.query(`SELECT pg_try_advisory_lock(800003, ${schemaLockKey}) AS locked`)).rows[0]
      .locked;
    if (!locked) return false;
    // Only RUNNING executions can be recovered; the bounded query replaces a
    // load of every historical run on each tick.
    const running = await pool.query<{ data: PipelineExecution }>(
      "SELECT data FROM records WHERE kind='executions' AND data->>'status'='RUNNING' ORDER BY updated_at DESC",
    );
    const runs = running.rows.map((row) => row.data);
    // Owning the advisory lock proves no other live worker owns a run. Recovery
    // is safe because records, advisories and outbox are committed atomically.
    await lockedTransaction(async (db) => {
      for (const scanned of runs.filter((e) => e.status === 'RUNNING')) {
        const stale = await getForUpdate<PipelineExecution>(db, 'executions', scanned.id);
        if (!stale || stale.status !== 'RUNNING') continue;
        if (stale.stopRequestedAt) {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'CANCELLED',
            endTime: new Date().toISOString(),
            phases: stale.phases.map((phase) =>
              ['RUNNING', 'PENDING'].includes(phase.status) ? { ...phase, status: 'CANCELLED' } : phase,
            ),
            logs: [...stale.logs, 'Recovered interrupted worker with an outstanding stop request; cancelled'],
          });
          await writeEvent(db, {
            category: 'PIPELINE',
            code: 'pipeline.cancelled',
            message: 'Recovered pipeline stop request',
            runId: stale.id,
          });
          continue;
        }
        const recoveryCount = countRecoveries(stale) + 1;
        if (recoveryCount > 3) {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'FAILED',
            endTime: new Date().toISOString(),
            logs: [
              ...stale.logs,
              `Worker exceeded maximum recovery attempts (${recoveryCount - 1}); marked FAILED to prevent poison-pill crash loop`,
            ],
            phases: stale.phases.map((phase) =>
              phase.status === 'RUNNING' || phase.status === 'PENDING'
                ? { ...phase, status: 'FAILED' }
                : phase,
            ),
          });
          await writeEvent(db, {
            category: 'ISSUE',
            level: 'ERROR',
            code: 'pipeline.recovery_limit_exceeded',
            message: 'Pipeline execution repeatedly failed; marked FAILED',
            runId: stale.id,
          });
          await appendAudit(
            db,
            'Pipeline recovery limit exceeded',
            `Execution ${stale.id} marked FAILED after ${recoveryCount - 1} crashes`,
            'worker',
            'PIPELINE',
            'ERROR',
          );
        } else {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'QUEUED',
            stats: { ...stale.stats, recoveryAttempts: recoveryCount },
            logs: [
              ...stale.logs,
              `Recovered interrupted worker (attempt ${recoveryCount}/3); restarting idempotently`,
            ],
          });
          await writeEvent(db, {
            category: 'PIPELINE',
            code: 'pipeline.recovered',
            message: 'Recovered interrupted worker',
            runId: stale.id,
          });
          await appendAudit(
            db,
            'Pipeline recovered',
            `Execution ${stale.id} recovered (attempt ${recoveryCount}/3)`,
            'worker',
            'PIPELINE',
          );
        }
      }
    });
    // Same bounded query as queueRun: only active executions matter. Loading
    // the whole executions table on every worker tick was both an unbounded
    // read and a statement-timeout risk.
    const queued = await pool.query<{ data: PipelineExecution }>(
      "SELECT data FROM records WHERE kind='executions' AND data->>'status'='QUEUED' ORDER BY updated_at DESC LIMIT 1",
    );
    execution = queued.rows[0]?.data;
    if (!execution) {
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const last = (await pool.query('SELECT last_run FROM scheduler_state WHERE id=1')).rows[0];
      const schedulerNow = Date.now();
      const catchUpDue = settings.schedulerEnabled && (await list<FeedCursor>(pool, 'feedCursors')).some((cursor) => {
        if (!cursor.hasMore) return false;
        if (!cursor.next_catchup_at) return false;
        const nextCatchupAt = Date.parse(cursor.next_catchup_at);
        return !Number.isFinite(nextCatchupAt) || nextCatchupAt <= schedulerNow;
      });
      const recoveryProbeDue = !settings.schedulerEnabled &&
        (await list<ThreatFeed>(pool, 'feeds')).some((feed) => recoveryDue(feed, schedulerNow));
      if (
        shouldStartAutomaticRun({
          schedulerEnabled: settings.schedulerEnabled,
          recoveryProbeDue,
          catchUpDue,
          lastRun: last?.last_run ? new Date(last.last_run).toISOString() : null,
          intervalMinutes: settings.schedulerIntervalMinutes,
        }, schedulerNow)
      )
        execution = await queueRun(pool, undefined, 'scheduler', undefined, lock);
    }
    await pool.query('UPDATE scheduler_state SET heartbeat=now() WHERE id=1');
    if (!execution) return false;
    const checkpoint = async (db: pg.Pool | pg.PoolClient = pool) => {
      signal?.throwIfAborted();
      if (connectionLost) throw new Error('Pipeline worker lost its database lock connection');
      const current = await get<PipelineExecution>(db, 'executions', execution!.id);
      if (!current) throw new Error('Pipeline execution no longer exists');
      if (current?.stopRequestedAt || current?.status === 'CANCELLED') throw new PipelineStopped();
      signal?.throwIfAborted();
      onProgress?.();
    };
    await checkpoint();
    execution.status = 'RUNNING';
    execution.phases = [
      'Feed ingestion',
      'Normalize & deduplicate',
      'Product matching',
      'Delivery queue',
    ].map((name, index) => ({
      name,
      status: index === 0 ? 'RUNNING' : 'PENDING',
      durationMs: 0,
      details: index === 0 ? 'Retrieving and enriching enabled sources' : 'Waiting for dependencies',
    }));
    execution.startTime = new Date().toISOString();
    let heartbeatPending = false;
    heartbeat = setInterval(() => {
      if (heartbeatPending) return;
      heartbeatPending = true;
      void pool
        .query('UPDATE scheduler_state SET heartbeat=now() WHERE id=1')
        .catch(() => console.error(JSON.stringify({ level: 'error', event: 'pipeline-heartbeat' })))
        .finally(() => {
          heartbeatPending = false;
        });
    }, 15000);
    heartbeat.unref();
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      await saveActiveExecution(db, execution!);
      await db.query('UPDATE scheduler_state SET last_run=now() WHERE id=1');
      await writeEvent(db, {
        category: 'PIPELINE',
        code: 'pipeline.started',
        message: 'Pipeline started',
        runId: execution!.id,
      });
    });
    const allFeeds = await list<ThreatFeed>(pool, 'feeds');
    const feeds = allFeeds.filter((feed) => feed.enabled);
    const feedTypesById = new Map(allFeeds.map((feed) => [feed.id, feed.type]));
    const [cachedCves, cachedWithdrawals, inventory, aliasEntries] = await Promise.all([
      list<NormalizedCVE>(pool, 'cveData'),
      list<{ cveId: string; modifiedDate: string }>(pool, 'cveWithdrawals'),
      list<WatchListItem>(pool, 'watchlist'),
      list<AliasEntry>(pool, 'aliases'),
    ]);
    // Operator-managed additions to the built-in alias thesaurus (see cpeMatcher.ts
    // DEFAULT_VENDOR_ALIASES/DEFAULT_PRODUCT_ALIASES) plus the automatic rows
    // that were derived on previous runs. Inventory-derived aliases are merged
    // immediately so a newly added/renamed asset benefits from the current run;
    // the full add/remove reconciliation happens once correlation evidence for
    // this run is known.
    const inventoryAliases = deriveInventoryAliases(inventory, aliasEntries);
    const startedAliasEntries: AliasEntry[] = [...aliasEntries, ...inventoryAliases];
    const vendorAliases = buildAliasMap(startedAliasEntries, 'VENDOR');
    const productAliases = buildAliasMap(startedAliasEntries, 'PRODUCT');
    const canonicalCache = mergeCveRecords(cachedCves);
    const knownCveModifiedAt = new Map([...canonicalCache].map(([id, cve]) => [id, cve.modifiedDate]));
    const knownWithdrawalAt = new Map(cachedWithdrawals.map((entry) => [entry.cveId, entry.modifiedDate]));
    let succeeded = 0,
      rawCount = 0;
    const results: Awaited<ReturnType<typeof ingestFeed>>[] = [];
    const feedUpdates: ThreatFeed[] = [];
    // Bound cross-feed concurrency; each adapter also paces its own pages.
    const ingestSources = async (sources: ThreatFeed[], targets: string[] = []) => {
      const concurrency = Math.min(sources.length, 6);
      let nextIndex = 0;
      const worker = async () => {
        while (nextIndex < sources.length) {
          const i = nextIndex++;
          const feed = sources[i];
          // Audit R-1: this checkpoint is the only stop signal in the loop, and
          // the circuit-open branch below used to `continue` straight past it on
          // the next iteration. Every iteration now re-checks the operator's
          // stop request before the skip is evaluated.
          await checkpoint();
          if (feed.circuitOpenUntil && Date.parse(feed.circuitOpenUntil) > Date.now()) {
            pushExecutionLog(
              execution!,
              `Feed ${feed.id}: skipped (circuit open, ${feed.consecutiveFailures} consecutive failures)`,
            );
            continue;
          }
          const start = Date.now();
          // MITRE can return up to 5,000 delta records; at its documented feed
          // pacing that bootstrap needs over 40 minutes for detail retrieval.
          // Give that source enough time to finish atomically while preserving
          // the configured limit for all other feeds.
          const maxDurationSeconds =
            feed.type === 'MITRE_CVE'
              ? Math.max(config.FEED_MAX_DURATION_SECONDS, 3600)
              : config.FEED_MAX_DURATION_SECONDS;
          const deadline = start + maxDurationSeconds * 1000;
          const configuredFeedHosts = config.EGRESS_ALLOWED_HOSTS.split(',').map((host) => host.trim()).filter(Boolean);
          const additionalAllowedHosts = feedEgressHosts(feed.type, feed.url, configuredFeedHosts)
            .filter((host) => !configuredFeedHosts.includes(host));
          const sourceCheckpoint = async () => {
            await checkpoint();
            if (Date.now() >= deadline) throw new FeedDeadlineExceeded();
          };
          try {
            const checkedRequest: Requester = async (url, options) => {
              await sourceCheckpoint();
              const remaining = Math.max(1, deadline - Date.now());
              const requestSignal = signal && options?.signal
                ? AbortSignal.any([signal, options.signal]) : signal ?? options?.signal;
              const response = await withAbortSignal(request(url, {
                ...options,
                additionalAllowedHosts,
                signal: requestSignal,
                timeoutMs: Math.min(options?.timeoutMs ?? 20000, remaining),
                socketTimeoutMs: Math.min(options?.socketTimeoutMs ?? 15000, remaining),
              }), requestSignal);
              await sourceCheckpoint();
              return response;
            };
            const checkedSleep = async (ms: number) => {
              const until = Date.now() + ms;
              while (Date.now() < until) {
                // `sourceCheckpoint` awaits a database read and a clock check, so
                // the remaining time can cross zero between the loop test and the
                // timer. A negative delay is clamped by Node only after warning,
                // which flooded the worker log with TimeoutNegativeWarning.
                const delay = until - Date.now();
                await sourceCheckpoint();
                if (delay <= 0) return;
                await new Promise((resolve) => setTimeout(resolve, Math.min(500, delay)));
              }
            };
            const savedCursor = await get<FeedCursor>(pool, 'feedCursors', feed.id);
            const cursor = savedCursor?.fingerprint === sourceFingerprint(feed) ? savedCursor : undefined;
            if (['NVD_API', 'OPENCVE_API', 'MITRE_CVE', 'VULNCHECK_KEV'].includes(feed.type)) {
              const maxWindow = feed.type === 'OPENCVE_API' ? OPENCVE_MAX_WINDOW_HOURS : 24;
              const window = ingestionWindow(execution!.scopeHours, cursor, undefined, maxWindow);
              execution!.logs.push(
                `Feed ${feed.id}: ${window.incremental ? 'incremental' : 'initial bounded'} sync ${window.start.toISOString()} to ${window.end.toISOString()}`,
              );
            }
            const savedKev =
              feed.type === 'CISA_KEV' ? await get<KevSnapshot>(pool, 'feedSnapshots', feed.id) : undefined;
            const cachedKev = savedKev?.fingerprint === sourceFingerprint(feed) ? savedKev : undefined;
            const context: IngestContext = {
              ...(execution!.incrementalFeeds !== false && cursor ? cursor : {}),
              knownCveModifiedAt,
              knownWithdrawalAt,
              knownCveContent: canonicalCache,
              ...(feed.type === 'OSV_API'
                ? {
                    targetPurls: inventory
                      .filter((item) => item.active)
                      .flatMap((item) => item.purls || []),
                  }
                : {}),
            };
            // A validator is usable only together with its complete source snapshot.
            let result = await ingestFeed(
              feed.type === 'CISA_KEV' ? { ...feed, etag: cachedKev?.etag } : feed,
              execution!.scopeHours,
              checkedRequest,
              config,
              checkedSleep,
              targets,
              feed.type === 'NVD_API'
                ? async ({ offset, total, records }) => {
                    await transaction(pool, async (db) => {
                      await checkpoint(db);
                      execution!.phases[0].durationMs = Date.now() - Date.parse(execution!.startTime);
                      execution!.phases[0].details = `NVD: ${offset.toLocaleString()} of ${total.toLocaleString()} records in incremental sync; ${records.toLocaleString()} retrieved`;
                      execution!.stats.rawIngested = rawCount + records;
                      await saveActiveExecution(db, execution!);
                    }, undefined, { signal });
                  }
                : undefined,
              context,
            );
            if (feed.type === 'CISA_KEV' && result.notModified) {
              if (!cachedKev) throw new Error('KEV conditional response has no source snapshot');
              result = { ...result, kev: cachedKev.kev };
            }
            results.push({ ...result, sourceId: feed.id });
            rawCount += result.notModified ? 0 : result.count;
            succeeded++;
            if (feed.type === 'EPSS_API' && targets.length === 0) {
              execution!.logs.push(`Feed ${feed.id}: no applicable CVEs; EPSS network retrieval skipped`);
              // No request was needed: clear expired recovery state without claiming
              // a successful connectivity check or changing lastSync.
              feedUpdates.push({
                ...feed,
                healthStatus: 'UNTESTED',
                errorLog: null,
                consecutiveFailures: 0,
                circuitOpenUntil: null,
              });
              continue;
            }
            feedUpdates.push({
              ...feed,
              healthStatus: result.warnings?.length ? 'DEGRADED' : 'HEALTHY',
              lastSync: new Date().toISOString(),
              latencyMs: Date.now() - start,
              itemCountLastRun: result.notModified ? feed.itemCountLastRun : result.count,
              errorLog: result.warnings?.join('; ') || null,
              ssrfValidated: true,
              etag: result.etag,
              consecutiveFailures: 0,
              circuitOpenUntil: null,
            });
          } catch (e) {
            signal?.throwIfAborted();
            if (e instanceof PipelineStopped || connectionLost) throw e;
            const message = e instanceof Error ? e.message : 'Ingestion failed';
            // Audit H-5: a configuration fault (SSRF-rejected destination,
            // malformed or unsupported URL, unusable checkpoint) cannot be fixed
            // by retrying. Record it as DOWN with no circuit and no failure
            // budget so it stays visible as an operator action item instead of
            // cycling the breaker and suppressing catch-up for that source.
            if (isPermanentFeedFailure(e)) {
              feedUpdates.push({
                ...feed,
                healthStatus: 'DOWN',
                latencyMs: Date.now() - start,
                errorLog: `Configuration error (not retryable): ${message}`,
                consecutiveFailures: feed.consecutiveFailures || 0,
                circuitOpenUntil: null,
              });
              pushExecutionLog(execution!, `Feed ${feed.id}: configuration error, retry disabled — ${message}`);
              await writeEvent(pool, {
                category: 'FEED',
                level: 'ERROR',
                code: 'feed.configuration_invalid',
                message: `${feed.name}: configuration error (not retryable)`,
                runId: execution!.id,
                context: { feedId: feed.id, error: message },
              }).catch(() => undefined);
            } else if (e instanceof FeedDeadlineExceeded) {
              // Audit R-2: a duration overrun is a capacity signal for this run,
              // not proof the source is unreachable. Recording it as a failure
              // opened the breaker after three long-but-successful bootstraps and
              // suppressed the catch-up the source still owed.
              feedUpdates.push({
                ...feed,
                healthStatus: 'DEGRADED',
                latencyMs: Date.now() - start,
                errorLog: message,
                consecutiveFailures: feed.consecutiveFailures || 0,
                circuitOpenUntil: feed.circuitOpenUntil ?? null,
              });
              pushExecutionLog(execution!, `Feed ${feed.id}: ${message} (not counted as a failure)`);
            } else if (e instanceof FeedDeferred) {
              // Audit R-3: the provider asked us to wait (Retry-After). Deferring
              // to the next run is correct behavior, not evidence the source is
              // unreachable. Record as DEGRADED with no circuit breaker opened
              // and no failure budget consumed, so catch-up still runs on schedule.
              feedUpdates.push({
                ...feed,
                healthStatus: 'DEGRADED',
                latencyMs: Date.now() - start,
                errorLog: message,
                consecutiveFailures: feed.consecutiveFailures || 0,
                circuitOpenUntil: feed.circuitOpenUntil ?? null,
              });
              pushExecutionLog(execution!, `Feed ${feed.id}: ${message} (not counted as a failure)`);
            } else {
              const consecutiveFailures = (feed.consecutiveFailures || 0) + 1;
              feedUpdates.push({
                ...feed,
                healthStatus: 'DOWN',
                latencyMs: Date.now() - start,
                errorLog: message,
                consecutiveFailures,
                circuitOpenUntil: recoveryAt(feed, consecutiveFailures, Date.now(), computeFeedRecoveryDelay(consecutiveFailures)),
                lastRecoveryAttemptAt: new Date().toISOString(),
              });
              pushExecutionLog(execution!, `Feed ${feed.id}: ${message}`);
            }
          }
          await transaction(pool, async (db) => {
            // A dead lock connection means the write cannot land; the checkpoint
            // throws at once (fails the feed) instead of waiting out the
            // statement timeout on a backend that is already gone.
            await checkpoint(db);
            // Audit L-3: `rawCount`/`results`/`feedUpdates` are mutated by every
            // concurrent worker, so the intermediate progress line raced and
            // could report a count that went backwards. Publish from the
            // execution object's own monotonic counter, and only ever raise it.
            const seen = Number(execution!.stats.rawIngested) || 0;
            execution!.phases[0].durationMs = Date.now() - Date.parse(execution!.startTime);
            execution!.phases[0].details = `${feeds.length} sources processed; ${Math.max(seen, rawCount)} records read`;
            execution!.stats.rawIngested = Math.max(seen, rawCount);
            await saveActiveExecution(db, execution!);
          });
        }
      };
      const workers = await Promise.allSettled(Array.from({ length: concurrency }, worker));
      const failure = workers.find((result) => result.status === 'rejected');
      if (failure?.status === 'rejected') throw failure.reason;
    };
    const primaryIngestionStartedAt = Date.now();
    await ingestSources(feeds.filter((feed) => feed.type !== 'EPSS_API'));
    const primaryIngestionDuration = Date.now() - primaryIngestionStartedAt;
    const preliminaryCorpus = mergeCveRecords([...cachedCves, ...results.flatMap((result) => result.cves)]);
    const preliminaryCves = [...preliminaryCorpus.values()];
    // Push structured identity + typed version-range filtering into PostgreSQL.
    // The JS matcher still decides every candidate; this only avoids the full
    // corpus x inventory cross product.
    const preliminaryPairs = await transaction(
      pool,
      (db) =>
        refreshCandidatePairs(db, preliminaryCves, inventory, {
          vendorAliases,
          productAliases,
        }),
      undefined,
      { locks: ['match-index'] }, // Use match-index advisory lock for exclusive coordination
    );
    // Audit M-2/M-3: the preliminary pass used to run the *entire* matcher over
    // the whole corpus solely to decide which CVEs need EPSS scores. That is the
    // most expensive call in the system, and the result was almost always
    // discarded because `preliminarySourceIds` includes every source that
    // returned records (i.e. every normal incremental run), making the reuse
    // check vacuous.
    //
    // EPSS changes risk, not applicability, so a CVE that names no inventory
    // identity never needs a score. Deriving the target list from the candidate
    // index is cheap and errs wide: any CVE the index could not narrow (wildcard
    // or unstructured criteria) is fetched in full, exactly as before.
    const epssTargets = new Set<string>();
    for (const [cveId, assets] of preliminaryPairs) if (assets.size) epssTargets.add(cveId);
    // Conservative widening: a CVE the index dropped entirely (wildcard/aliases)
    // or one whose assets the index could not version-bound is still a plausible
    // correlation, so it must not lose its risk score.
    for (const cve of preliminaryCves) {
      const canonical = normalizeCveId(cve.cveId);
      if (!canonical) continue;
      const unbounded =
        !cve.cpeMatchDetails?.length &&
        (!cve.cpeMatches.length || cve.cpeMatches.some((criteria) => {
          const parsed = parseCPE23(criteria);
          return !parsed.isValid || /[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product);
        }));
      if (unbounded) epssTargets.add(canonical);
    }
    const epssFeeds = feeds.filter((feed) => feed.type === 'EPSS_API');
    const epssIngestionStartedAt = Date.now();
    if (epssFeeds.length) {
      // EPSS changes risk, not product applicability. Query only CVEs that can
      // currently affect inventory, including uncertain matches awaiting review.
      await ingestSources(epssFeeds, [...epssTargets].sort());
    }
    const epssIngestionDuration = Date.now() - epssIngestionStartedAt;
    results.sort((a, b) => (a.sourceId || '').localeCompare(b.sourceId || ''));
    const ingestionDuration = primaryIngestionDuration + epssIngestionDuration;
    execution.phases[0] = {
      name: 'Feed ingestion',
      status:
        succeeded < feeds.length || results.some((result) => result.warnings?.length) ? 'WARNING' : 'SUCCESS',
      durationMs: ingestionDuration,
      details: `${succeeded}/${feeds.length} feeds succeeded; ${rawCount} records read`,
    };
    execution.phases[1].status = 'RUNNING';
    execution.phases[1].details = 'Canonicalizing records and resolving source revisions';
    execution.phases[2].details = 'Waiting for normalized CVEs';
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      await saveActiveExecution(db, execution!);
    });
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      const currentFeeds = new Map((await list<ThreatFeed>(db, 'feeds')).map((feed) => [feed.id, feed]));
      const validSources = new Set(
        feeds
          .filter((feed) => {
            const current = currentFeeds.get(feed.id);
            return (
              current?.enabled &&
              current.url === feed.url &&
              current.type === feed.type &&
              current.authType === feed.authType &&
              (current.authSecretKey || '') === (feed.authSecretKey || '')
            );
          })
          .map((feed) => feed.id),
      );
      const acceptedResults = results.filter((result) => validSources.has(result.sourceId!));
      succeeded = acceptedResults.length;
      rawCount = acceptedResults.reduce((sum, result) => sum + (result.notModified ? 0 : result.count), 0);
      for (const feed of feeds)
        if (!validSources.has(feed.id))
          execution!.logs.push(
            `Feed ${feed.id}: configuration changed during ingestion; obsolete response ignored`,
          );
      for (const feed of feedUpdates) {
        const current = currentFeeds.get(feed.id);
        // A feed the operator disabled while ingestion was running, or whose
        // source changed, is no longer ours to describe: writing the run's
        // health/etag back would resurrect a stale `enabled=true` or overwrite
        // the newly configured source's state.
        if (!current || !validSources.has(feed.id)) continue;
        await put(db, 'feeds', feed.id, {
          ...current,
          healthStatus: feed.healthStatus,
          lastSync: feed.lastSync,
          latencyMs: feed.latencyMs,
          itemCountLastRun: feed.itemCountLastRun,
          errorLog: feed.errorLog,
          ssrfValidated: feed.ssrfValidated,
          etag: feed.etag,
          consecutiveFailures: feed.consecutiveFailures,
          circuitOpenUntil: feed.circuitOpenUntil,
          // This update previously dropped these fields silently (only the
          // listed keys were merged onto `current`, so they survived) but the
          // explicit carry-forward documents the invariant and keeps a future
          // refactor from resetting the recovery clock.
          lastRecoveryAttemptAt: feed.lastRecoveryAttemptAt ?? current.lastRecoveryAttemptAt,
          enabled: current.enabled,
        });
      }
      if (feeds.length && !succeeded) {
        await appendAudit(
          db,
          'Pipeline warning',
          'All enabled feeds failed; running correlation against cache',
          'worker',
          'PIPELINE',
          'WARNING',
        );
        execution!.logs.push('All feeds failed; proceeding with cached CVE correlation');
      }
      for (const result of acceptedResults) {
        if (result.syncState) {
          const source = currentFeeds.get(result.sourceId!)!;
          // Clear catch_up flag when hasMore is false (catch-up complete).
          const cursorState = result.syncState.hasMore
            ? result.syncState
            : { ...result.syncState, catch_up: false, next_catchup_at: undefined };
          // Dead worker: the data connection is gone, so this write cannot land.
          // Let the checkpoint throw instead of waiting out statement_timeout.
          if (connectionLost) throw new Error('Pipeline worker lost its database lock connection');
          await put(db, 'feedCursors', source.id, {
            ...cursorState,
            fingerprint: sourceFingerprint(source),
          } satisfies FeedCursor);
        }
        if (result.kev && !result.notModified) {
          const source = currentFeeds.get(result.sourceId!)!;
          await put(db, 'feedSnapshots', source.id, {
            fingerprint: sourceFingerprint(source),
            etag: result.etag,
            kev: result.kev,
          } satisfies KevSnapshot);
        }
      }
      for (const update of feedUpdates.filter((feed) => validSources.has(feed.id)))
        await writeEvent(db, {
          category: 'FEED',
          level:
            update.healthStatus === 'DOWN'
              ? 'ERROR'
              : update.healthStatus === 'DEGRADED'
                ? 'WARNING'
                : 'INFO',
          code: 'feed.ingestion',
          message: `${update.name}: ${update.healthStatus}`,
          runId: execution!.id,
          context: {
            feedId: update.id,
            feedType: update.type,
            provider: update.name,
            healthStatus: update.healthStatus,
            consecutiveFailures: update.consecutiveFailures || 0,
            count: update.itemCountLastRun,
            latencyMs: update.latencyMs,
          },
        });
      // Commit a durable native-correlation handoff with the source checkpoint.
      // Existing inventory remains authoritative; no record-store assets are copied.
      for (const result of acceptedResults)
        for (const article of result.articles || [])
          await db.query(
            `INSERT INTO correlation_pending(id,payload) VALUES($1,$2)
          ON CONFLICT(id) DO NOTHING`,
            [
              article.id,
              JSON.stringify({
                title: article.title,
                content: article.summary,
                url: article.url,
              }),
            ],
          );
      // Re-read the durable CVE corpus at commit. Operator revisions made while
      // network ingestion was running must remain authoritative and stale feed
      // revisions must not overwrite them.
      //
      // Audit C-1: the previous version loaded the snapshot here but then diffed
      // `byId` against the SAME snapshot it had just merged into, so every record
      // that did not change during ingestion was absent from `changedCves` and
      // was never written. The in-run corpus is now diffed against the state
      // that was current when the run started, and a record current at commit
      // time is only replaced when the run's own revision is genuinely newer.
      const snapshot = await pipelineState(db);
      const commitState = new Map(snapshot.cveData.map((cve) => [normalizeCveId(cve.cveId) || cve.cveId, cve]));
      const runStartedAt = Date.parse(execution!.startTime);
      // Re-read alias entries inside the commit transaction: operator alias
      // changes during ingestion (save/promote/revoke) must not be silently
      // overwritten by a stale snapshot loaded before network I/O.
      const aliasEntries = await list<AliasEntry>(db, 'aliases');
      const articles = mergeArticles([
        ...snapshot.intelligenceArticles,
        ...acceptedResults.flatMap((result) => result.articles || []),
      ]);
      await putMany(
        db,
        'intelligenceArticles',
        articles.map((data) => ({ id: data.id, data })),
      );
      const byId = mergeCveRecords([
        ...snapshot.cveData,
        ...acceptedResults.filter((result) => !result.notModified).flatMap((result) => result.cves),
      ]);
      // Operator-import records are explicit authoritative revisions. Feed
      // refreshes may add enrichment, but they must never replace an operator
      // correction made while ingestion was in progress.
      for (const operatorRevision of snapshot.cveData) {
        if (operatorRevision.sourceFeeds?.includes('operator-import')) {
          byId.set(normalizeCveId(operatorRevision.cveId) || operatorRevision.cveId, operatorRevision);
        }
      }
      // Audit C-1 / C-2: a record that a different writer committed after this
      // run started but before the commit transaction opened is authoritative.
      // Without this pass the merge above would resurrect the run's pre-ingestion
      // copy of that CVE and feed `reconcileFindings` stale applicability.
      const protectedFromRunCves = new Set<string>();
      for (const [id, stored] of commitState) {
        if (!byId.has(id)) continue;
        const storedAt = Date.parse(stored.modifiedDate);
        const startedBeforeRevision = Number.isFinite(storedAt) && storedAt > runStartedAt;
        const operatorCorrection = stored.sourceFeeds?.includes('operator-import');
        if (operatorCorrection || startedBeforeRevision) {
          byId.set(id, stored);
          protectedFromRunCves.add(id);
        }
      }
      type Withdrawal = { cveId: string; modifiedDate: string };
      const oldWithdrawals = new Map(
        (await list<Withdrawal>(db, 'cveWithdrawals')).map((entry) => [entry.cveId, entry]),
      );
      const withdrawals = new Map(oldWithdrawals);
      for (const entry of acceptedResults.flatMap((result) => result.withdrawals || [])) {
        const old = withdrawals.get(entry.cveId);
        if (!old || Date.parse(entry.modifiedDate) > Date.parse(old.modifiedDate))
          withdrawals.set(entry.cveId, entry);
      }
      const changedWithdrawals = [...withdrawals.values()].filter((entry) => {
        const old = oldWithdrawals.get(entry.cveId);
        return !old || old.modifiedDate !== entry.modifiedDate;
      });
      await putMany(
        db,
        'cveWithdrawals',
        changedWithdrawals.map((entry) => ({ id: entry.cveId, data: entry })),
      );
      for (const entry of withdrawals.values()) {
        // Audit C-2: a withdrawal supersedes a feed revision, but never an
        // operator correction that was imported after the withdrawal. Applying
        // the tombstone blindly deleted the operator's repair.
        const operatorCorrection = byId.get(entry.cveId)?.sourceFeeds?.includes('operator-import');
        if (operatorCorrection) continue;
        const cve = byId.get(entry.cveId);
        if (cve && Date.parse(cve.modifiedDate) <= Date.parse(entry.modifiedDate)) byId.delete(entry.cveId);
      }
      const oldCveMap = mergeCveRecords(snapshot.cveData);
      // Audit H-3: build the change-detection projection once, keyed by
      // canonical id. `oldCveMap` itself is released as soon as the EPSS/KEV
      // carry-forward below finishes, so the run never holds two complete
      // corpora plus a third map of dense strings.
      // Audit H-3: compare only the content view of each stored CVE, built once
      // before the EPSS/KEV enrichment below. The comparison itself must still run
      // AFTER enrichment, because a KEV or EPSS update is a real, persistable
      // change: the previous implementation compared whole records post-merge for
      // exactly that reason, and comparing the pre-enrichment view made KEV
      // enrichment silently unpersisted.
      const oldCveViews = new Map<string, string>();
      for (const old of oldCveMap.values()) oldCveViews.set(old.cveId, cveContentView(old));
      // Records written by another worker during this run are compared against
      // the commit-time value they actually replaced, so their update is not
      // re-applied as an unchanged no-op and the diff stays correct.
      for (const [id, stored] of commitState)
        if (protectedFromRunCves.has(id)) oldCveViews.set(id, cveContentView(stored));
      for (const old of oldCveMap.values()) {
        const current = byId.get(normalizeCveId(old.cveId) || '');
        if (current) {
          current.epss = old.epss;
          current.cisaKev = old.cisaKev;
        }
      }
      // The full previous corpus is no longer needed: change detection reads
      // `oldCveViews`, superseded-alias detection reads `oldCveIds`. Dropping the
      // map here halves peak resident memory on a large corpus (audit H-3).
      const oldCveIds = new Set(oldCveMap.keys());
      oldCveMap.clear();
      const kevReports = acceptedResults.filter((result) => result.kev);
      const cisaKevEnabled = [...currentFeeds.values()].some(
        (feed) => feed.type === 'CISA_KEV' && feed.enabled,
      );
      if (
        cisaKevEnabled &&
        !acceptedResults.some((result) => currentFeeds.get(result.sourceId || '')?.type === 'CISA_KEV')
      )
        execution!.logs.push('CISA KEV was not refreshed; cached KEV flags are retained and may be stale');
      const exploitedReports = acceptedResults.filter((result) => result.exploited && !result.notModified);
      const epssReports = acceptedResults.filter((result) => result.epss && !result.notModified);
      const epssScopes = new Map(epssReports.map((result) => [result, new Set(result.epssScope)]));
      for (const cve of byId.values()) {
        const exploitationSources = exploitedReports
          .filter((result) => result.exploited?.[cve.cveId])
          .map((result) => result.sourceId!)
          .sort();
        if (exploitationSources.length) {
          cve.exploitationSources = [
            ...new Set([...(cve.exploitationSources || []), ...exploitationSources]),
          ];
          if (cve.exploitStatus === 'None') cve.exploitStatus = 'Reported In Wild';
        }
        if (kevReports.length) {
          const hasFullCisaKev = kevReports.some((r) => {
            const feed = currentFeeds.get(r.sourceId || '');
            return feed?.type === 'CISA_KEV';
          });
          const kevMatch = kevReports.map((result) => result.kev![cve.cveId]).find((entry) => entry?.isKev);
          if (kevMatch) {
            cve.cisaKev = kevMatch;
          } else if (hasFullCisaKev) {
            cve.cisaKev = { isKev: false };
          }
        }
        const scopedReports = epssReports.filter((result) => epssScopes.get(result)!.has(cve.cveId));
        if (scopedReports.length) {
          cve.epss = scopedReports.map((result) => result.epss![cve.cveId]).find(Boolean) || {
            score: 0,
            percentile: 0,
          };
        }
      }
      // Audit H-3: compare only the applicability-affecting view computed before
      // the EPSS/KEV enrichment above, so a refreshed score does not force a full
      // re-serialisation of the corpus (and a spurious rewrite of every row).
      const changedCves = [...byId.values()].filter((cve) => {
        const previousView = oldCveViews.get(cve.cveId);
        return previousView === undefined || previousView !== cveContentView(cve);
      });
      // Bind published CVEs to their pre-CVE clusters so early-intelligence
      // evidence and operator rulings travel with the canonical identifier.
      // Only CVEs that are new to the corpus (not merely re-versioned) can
      // establish the publication event; a re-publication never re-binds.
      //
      // A bind that loses its bounded lock race throws BIND_LOCK_CONTENDED. That
      // is not "no cluster to bind": swallowing it would record the CVE as
      // already-published, so no later run would retry and the operator's
      // FALSE_POSITIVE/NOT_AFFECTED ruling would never reach the canonical
      // finding. Deferred identities are merged into the pending pin, which the
      // next citation run retries before re-deriving new publications.
      type DeferredBind = { cveId: string; vendor: string; product: string; attempts?: number };
      const deferredBinds: DeferredBind[] = [];
      const previous = await get<{ pending: DeferredBind[] }>(
        db,
        'systemState',
        'correlation-deferred-binds',
      ).catch(() => undefined);
      // At most 500 entries fit in the durable pin, and CVEs beyond the cap are
      // never revisited (a CVE that is already in the corpus is skipped by
      // `oldCveMap.has` on every later run). Defer only what the pin can hold:
      // the rest still inherits its cluster, because bindClusterToCve's own
      // bounded retries already ran and a cluster that genuinely exists is
      // bindable. Losing a bound identity silently is the outcome this list
      // exists to prevent.
      const DEFERRED_BIND_LIMIT = 500;
      const defer = (bind: DeferredBind, attempts = 1) => {
        if (deferredBinds.length >= DEFERRED_BIND_LIMIT) return;
        deferredBinds.push({ ...bind, attempts });
      };
      for (const identity of previous?.pending ?? []) {
        try {
          await bindClusterToCve(db, identity.cveId, identity.vendor, identity.product);
        } catch (error) {
          if ((error as { code?: string }).code !== 'BIND_LOCK_CONTENDED') throw error;
          const attempts = (identity.attempts ?? 0) + 1;
          if (attempts < DEFERRED_BIND_MAX_ATTEMPTS) defer(identity, attempts);
          else
            execution!.logs.push(
              `Pre-CVE disposition inheritance for ${identity.cveId} was deferred ${attempts} times and is now abandoned`,
            );
        }
      }
      for (const cve of changedCves) {
        if (oldCveIds.has(cve.cveId)) continue;
        for (const identity of cveClusterIdentities(cve)) {
          try {
            await bindClusterToCve(db, cve.cveId, identity.vendor, identity.product);
          } catch (error) {
            if ((error as { code?: string }).code !== 'BIND_LOCK_CONTENDED') throw error;
            defer({ cveId: cve.cveId, ...identity }, 1);
          }
        }
      }
      // Retried binds whose CVE has left the changed set are carried forward
      // too; dropping them here is the same loss as never recording them.
      if (deferredBinds.length)
        await put(db, 'systemState', 'correlation-deferred-binds', {
          pending: deferredBinds.slice(0, DEFERRED_BIND_LIMIT),
          updatedAt: new Date().toISOString(),
        });
      else if (previous)
        await put(db, 'systemState', 'correlation-deferred-binds', {
          pending: [],
          updatedAt: new Date().toISOString(),
        });
      await putMany(
        db,
        'cveData',
        changedCves.map((cve) => ({ id: cve.cveId, data: cve })),
      );
      if (protectedFromRunCves.size)
        await writeEvent(db, {
          category: 'PIPELINE',
          level: 'INFO',
          code: 'pipeline.cve_revision_preserved',
          message: 'Concurrent CVE revisions were preserved over stale run data',
          runId: execution!.id,
          context: { cveIds: [...protectedFromRunCves].slice(0, 50), count: protectedFromRunCves.size },
        });
      const keys = await db.query("SELECT id FROM records WHERE kind='cveData'");
      // Batch deletion of superseded/withdrawn CVE aliases into a single query
      // instead of one DELETE per row, reducing O(N) round-trips to O(1).
      const staleIds = keys.rows
        .map((row) => {
          const canonical = normalizeCveId(row.id);
          return canonical &&
            ((canonical !== row.id && byId.has(canonical)) ||
              (withdrawals.has(canonical) && !byId.has(canonical)))
            ? row.id
            : null;
        })
        .filter((id): id is string => id !== null);
      if (staleIds.length)
        await db.query("DELETE FROM records WHERE kind='cveData' AND id = ANY($1::text[])", [staleIds]);
      // Applicability matching is time-bounded to the run window so only CVEs
      // published or modified within scopeHours are matched.
      const settings = { ...snapshot.settings, scopeHours: execution!.scopeHours };
      execution!.logs.push(
        `Applicability matching is time-bounded to the run window (scopeHours=${execution!.scopeHours})`,
      );
      const finalCves = [...byId.values()];
      // Inventory may have changed while this run was ingesting. Re-derive its
      // automatic aliases for the final snapshot so both the PostgreSQL
      // candidate index and the JavaScript matcher use the same expanded keys.
      const finalInventoryAliases = deriveInventoryAliases(snapshot.watchlist, aliasEntries);
      const finalAliasEntries: AliasEntry[] = [...aliasEntries, ...finalInventoryAliases];
      const finalVendorAliases = buildAliasMap(finalAliasEntries, 'VENDOR');
      const finalProductAliases = buildAliasMap(finalAliasEntries, 'PRODUCT');
      // AUDIT FIX: Apply pipeline-news integration correction
      // Derive and calculate final alias maps immediately for both CVE and news matching
      const finalPairs = await transaction(
        pool,
        (db) =>
          refreshCandidatePairs(db, finalCves, snapshot.watchlist, {
            vendorAliases: finalVendorAliases,
            productAliases: finalProductAliases,
          }),
        undefined,
        { locks: ['match-index'] },
      );
      const correlated = runVulnerabilityPipeline(
        feeds,
        finalCves,
        snapshot.watchlist,
        snapshot.alertedCves,
        snapshot.findings,
        settings,
        'Server worker',
        true,
        finalVendorAliases,
        finalProductAliases,
        finalPairs.size ? finalPairs : undefined,
        aliasEntries,
      );
      const previousInventory = await get<Record<string, string>>(db, 'systemState', 'matched-inventory-v1');
      const inventoryFingerprints: Record<string, string> = Object.create(null);
      const changedInventory = snapshot.watchlist.filter((asset) => {
        const fingerprint = createHash('sha256').update(JSON.stringify({
          vendor: asset.vendor, product: asset.product, version: asset.version,
          cpes: [...asset.cpes].sort(), purls: [...(asset.purls ?? [])].sort(),
          active: asset.active, assetTag: asset.assetTag,
        })).digest('hex');
        inventoryFingerprints[asset.id] = fingerprint;
        return asset.active && previousInventory?.[asset.id] !== fingerprint;
      });
      if (changedInventory.length) {
        const historical = runVulnerabilityPipeline(
          feeds, finalCves, changedInventory, snapshot.alertedCves, snapshot.findings,
          { ...settings, scopeHours: 0 }, 'Inventory registration', true,
          finalVendorAliases, finalProductAliases, finalPairs.size ? finalPairs : undefined, aliasEntries,
        );
        const known = new Set(correlated.newFindings.map(findingIdentity));
        correlated.newFindings.push(...historical.newFindings.filter((finding) => !known.has(findingIdentity(finding))));
      }
      correlated.newFindings = assessFindings(correlated.newFindings, feedTypesById);
      await put(db, 'systemState', 'matched-inventory-v1', inventoryFingerprints);
      // `correlated.newFindings` is every current match because the server asks
      // for existing candidates so it can refresh applicability. The execution
      // metric must only count identities that did not exist before this run;
      // otherwise every run reports the whole corpus as a new detection.
      const newDetectionCount = countNewFindings(snapshot.findings, correlated.newFindings);
      // A wholly rejected stale bundle may be rebuilt from current matches. Never
      // automatically resend a bundle with any acceptance or an in-flight delivery.
      const staleBundles = new Set<string>(
        (
          await db.query(
            `SELECT advisory_id FROM outbox GROUP BY advisory_id HAVING bool_and(status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%')`,
          )
        ).rows.map((row) => row.advisory_id),
      );
      // Pre-CVE operator rulings suppress their canonical CVE's new findings
      // before reconciliation or any delivery queue sees them. A finding whose
      // asset an operator ruled FALSE_POSITIVE/NOT_AFFECTED during the pre-CVE
      // window is created MONITORED with the ruling recorded, never queued.
      const existingFindingIdentities = new Set(snapshot.findings.map(findingIdentity));
      const newFindingIds = new Set(
        [...new Map(correlated.newFindings
          .filter((finding) => !existingFindingIdentities.has(findingIdentity(finding)))
          .map((finding) => [findingIdentity(finding), finding.id])).values()],
      );
      const suppressedNewFindings: Finding[] = [];
      const survivingNewFindings: Finding[] = [];
      {
        const suppressionCache = new Map<string, Set<string>>();
        for (const finding of correlated.newFindings) {
          let suppressed = suppressionCache.get(finding.cveId);
          if (!suppressed) {
            suppressed = await clusterSuppressedAssets(db, finding.cveId);
            suppressionCache.set(finding.cveId, suppressed);
          }
          if (suppressed.has(finding.matchedAssetId))
            suppressedNewFindings.push({
              ...finding,
              ...(newFindingIds.has(finding.id) && { executionId: execution!.id }),
              status: 'FALSE_POSITIVE',
              notificationStatus: 'NOT_APPLICABLE',
              matchingEvidence:
                'Suppressed by operator ruling on the pre-CVE cluster; canonical CVE inherits the earlier decision',
            });
          else
            survivingNewFindings.push(
              newFindingIds.has(finding.id) ? { ...finding, executionId: execution!.id } : finding,
            );
        }
      }
      const reconciled = reconcileFindings(
        snapshot.findings.map((f) =>
          f.advisoryId && staleBundles.has(f.advisoryId) && !f.autoDispatchedAt
            ? { ...f, advisoryId: null }
            : f,
        ),
        survivingNewFindings,
      );
      const vexEnforced = applyVexSuppression(reconciled);
      // Suppressed findings are persisted alongside the surviving set: dropping
      // them would let the next run re-create and queue the same finding.
      const persistedFindings = [...vexEnforced, ...suppressedNewFindings];
      await putMany(
        db,
        'findings',
        persistedFindings.map((f) => ({ id: f.id, data: f })),
      );
      // Rebuild the automatic alias layer from current inventory and from the
      // correlations that survived this run. Rows that are no longer supported
      // by either source are removed, while operator-managed rows are never
      // touched. The effective maps include this run's changes so news evidence
      // matching also sees the freshly learned names.
      // A stop requested during the commit window must surface before the
      // alias reconciliation writes back: once upserts/removals hit the table,
      // a cancellation can no longer prevent a lossy overwrite of concurrent
      // operator alias edits.
      await checkpoint(db);
      const desiredAutoAliases = [
        ...deriveInventoryAliases(snapshot.watchlist, aliasEntries),
        ...deriveCorrelationAliases(persistedFindings, snapshot.watchlist, byId, aliasEntries),
      ];
      const autoAliases = reconcileAutoAliases(aliasEntries, desiredAutoAliases, undefined, {
        ttlDays: settings.securityPolicy.autoAliasTtlDays,
      });
      // Batched, not per-row (audit finding #10): alias reconciliation can
      // touch hundreds of entries per run; putMany/removeMany issue one
      // parameterised statement each instead of one round trip per row.
      await putMany(db, 'aliases', autoAliases.upserts.map((entry) => ({ id: entry.id, data: entry })));
      await removeMany(db, 'aliases', autoAliases.removals);
      const effectiveAliasEntries = autoAliases.aliases;
      const effectiveVendorAliases = buildAliasMap(effectiveAliasEntries, 'VENDOR');
      const effectiveProductAliases = buildAliasMap(effectiveAliasEntries, 'PRODUCT');
      // Audit ML-3: the weights that actually scored this run's news evidence
      // were never recorded, so a bad split could not be attributed to a model
      // version after the fact. Capture them once and persist with the run.
      const credibilityWeights = predictCredibilityWeights();
      const intelligenceMatches: IntelligenceMatch[] = matchIntelligence(
        articles,
        snapshot.watchlist,
        vexEnforced,
        [...byId.values()],
        effectiveVendorAliases,
        effectiveProductAliases,
        // Cached CVEs stay applicable regardless of age, but news vendor +
        // product evidence is limited to the run's published/modified window.
        execution!.scopeHours,
        new Date(),
        credibilityWeights,
      ).map((match) => ({
        ...match,
        calibratedCredibilityScore: calibrateCredibilityScore(match.credibilityScore ?? 0).score,
      }));
      await putMany(
        db,
        'intelligenceMatches',
        intelligenceMatches.map((data) => ({ id: data.id, data })),
      );
      // Apply zero-day rate limiting and digest consolidation before the sweep
      // below, so the rows a digest replaces are deleted in the same pass instead
      // of being written and then immediately removed.
      //
      // Audit C-3: the cap also removes the suppressed matches' counterpart
      // findings. They were persisted but never queued, so exceeding the cap
      // silently lost the notification — the exact storm-to-silence failure the
      // cap was meant to convert into a digest. The digests are now recorded
      // durably so the operator and the UI can see what was withheld.
      const zeroDayCap = Math.max(1, Math.min(MAX_ZERO_DAYS_PER_RUN, Math.floor(getZeroDayCap())));
      const { matches: rateLimitedMatches, digests: zeroDayDigests } =
        rankAndRateLimitZeroDays(vexEnforced, intelligenceMatches, zeroDayCap);
      // Declared with the other queue counters below; hoisted here because the
      // digest delivery happens before the ordinary dispatch block runs.
      let zeroDayDigestNotificationsQueued = 0;
      // Materialise each digest once: the persisted record and the queued email
      // must describe exactly the same withheld evidence.
      const allByMatchId = new Map(intelligenceMatches.map((match) => [match.id, match]));
      const articleById = new Map(articles.map((article) => [article.id, article]));
      const digestPayloads = zeroDayDigests.map((digest) => {
        const withheld = digest.matchIds
          .map((id) => allByMatchId.get(id))
          .filter((match): match is IntelligenceMatch => Boolean(match));
        const articleIds = [...new Set(withheld.flatMap((match) => match.articleIds))];
        return {
          retained: {
            ...digest,
            executionId: execution!.id,
            createdAt: new Date().toISOString(),
            // The withheld evidence must remain reviewable: a digest removes it
            // from the notification path, not from the operator's view.
            articles: articleIds,
          },
          payload: {
            digestId: digest.advisoryId,
            vendor: digest.vendor,
            product: digest.product,
            matchIds: digest.matchIds,
            matchCount: digest.matchCount,
            findings: withheld.map((match) => ({
              findingId: match.findingId,
              cveId: match.cveId ?? undefined,
              assetName: match.assetName,
              evidence: match.evidence,
              credibilityScore: match.credibilityScore,
            })),
            articles: articleIds
              .map((id) => articleById.get(id))
              .filter((article): article is IntelligenceArticle => Boolean(article))
              .map((article) => ({
                id: article.id,
                title: article.title,
                url: article.url,
                sourceFeeds: [...article.sourceFeeds],
              })),
          },
        };
      });
      if (digestPayloads.length)
        await putMany(
          db,
          'zeroDayDigests',
          digestPayloads.map(({ retained }) => ({ id: retained.advisoryId, data: retained })),
        );
      await putMany(
        db,
        'intelligenceMatches',
        rateLimitedMatches.map((data) => ({ id: data.id, data })),
      );
      // Audit M-6: the previous `NOT (id = ANY($1))` form bound every match id as
      // a single array parameter and scanned the whole kind on every run — a
      // multi-megabyte parameter for a large corpus. Batching keeps each
      // statement well under the 65,535 bind-parameter limit and lets the
      // primary key drive the delete.
      const liveMatchIds = rateLimitedMatches.map((item) => item.id);
      const liveIdSet = new Set(liveMatchIds);
      const existingMatchIds = (
        await db.query("SELECT id FROM records WHERE kind='intelligenceMatches'")
      ).rows.map((row: { id: string }) => row.id);
      const staleMatchIds = existingMatchIds.filter((id) => !liveIdSet.has(id));
      await removeMany(db, 'intelligenceMatches', staleMatchIds);
      await writeEvent(db, {
        category: 'MATCHING',
        code: 'matching.completed',
        message: 'Structured applicability and news evidence correlation completed',
        runId: execution!.id,
        context: {
          findings: correlated.newFindings.length,
          newDetections: newDetectionCount,
          articles: articles.length,
          credibilityWeights,
          evidenceMatches: rateLimitedMatches.length,
          reviewRequired: rateLimitedMatches.filter((item) => item.status === 'REVIEW_REQUIRED').length,
          zeroDayDigests: zeroDayDigests.length,
          zeroDaysRateLimited: intelligenceMatches.length - rateLimitedMatches.length,
          // Audit M-1/M-9: the cap now also suppresses the counterpart findings,
          // so record exactly what was withheld and under which digest.
          withheldFindings: zeroDayDigests.reduce((sum, digest) => sum + digest.findingIds.length, 0),
          digestGroups: zeroDayDigests.map((digest) => ({
            advisoryId: digest.advisoryId,
            product: `${digest.vendor}/${digest.product}`,
            matches: digest.matchCount,
          })),
        },
      });
      if (zeroDayDigests.length) {
        execution!.logs.push(
          `Zero-day cap (${zeroDayCap}) reached: ${zeroDayDigests.length} digest(s) consolidated ${intelligenceMatches.length - rateLimitedMatches.length} match(es)`,
        );
      }
      // Audit C-3: exceeding the cap must not silence the operator. Each digest
      // is delivered as one consolidated email per Security-team recipient, so
      // the cost bound the cap protects still holds. The findings themselves stay
      // out of the normal dispatch path.
      if (digestPayloads.length) {
        // Keep zero-day evidence available in the UI without sending a third
        // email repeating the same findings or source articles.
        await writeEvent(db, {
          category: 'MATCHING',
          code: 'matching.zero_day_digests_recorded',
          message: 'Zero-day evidence recorded for consolidated findings and news',
          runId: execution!.id,
          context: { digests: digestPayloads.length },
        });
      }
      const queueStarted = Date.now();
      let notificationsQueued = 0,
        advisoriesQueued = 0,
        digestBuffered = 0,
        newsNotificationsQueued = 0,
        newsArticlesQueued = 0,
        manualReviewFindingsQueued = 0;
      // Security news is consolidated into ONE email per recipient per run, and an
      // article already delivered to a recipient is never delivered again. The
      // per-match queue could not guarantee that: the matcher re-keys a match on
      // `hash(cveId || articleId)`, so the same story produced new rows (and new
      // emails) whenever it was re-correlated or syndicated through another feed.
      if (intelligenceMatches.length) {
        const securityRecipients = await loadNewsRecipients(db);
        if (securityRecipients.length) {
          const articleMap = new Map(
            articles.map((article) => [article.id, article] as [string, IntelligenceArticle]),
          );
          const news = await queueConsolidatedNews(db, intelligenceMatches, articleMap, securityRecipients, {
            enqueue: async (input) =>
              enqueue(
                input.db,
                'email',
                input.recipient.id,
                input.advisoryId,
                {
                  subject: input.subject,
                  text: input.text,
                  html: input.html,
                  cveIds: input.cveIds,
                  newsEvidence: {
                    matchId: input.articles.flatMap((item) => item.matchIds).sort()[0] || input.advisoryId,
                    article: {
                      id: input.articles[0].article.id,
                      title: input.articles[0].article.title,
                      url: input.articles[0].article.url,
                      sourceFeeds: [...input.articles[0].article.sourceFeeds],
                      publishedDate: input.articles[0].article.publishedDate,
                    },
                    articles: input.articles.map((item) => ({
                      id: item.article.id,
                      title: item.article.title,
                      url: item.article.url,
                      sourceFeeds: [...item.article.sourceFeeds],
                      publishedDate: item.article.publishedDate,
                    })),
                    assets: [...new Set(input.articles.flatMap((item) => item.assets))].sort(),
                    asset: { name: input.articles.flatMap((item) => item.assets).sort()[0] || 'unknown asset' },
                    cveIds: input.cveIds,
                    evidence: input.articles.flatMap((item) => item.evidence).join(' | '),
                    zeroDay: input.articles.some((item) => item.zeroDay),
                    credibilityScore: input.articles.reduce<number | undefined>(
                      (best, item) =>
                        typeof item.credibilityScore === 'number'
                          ? Math.max(best ?? 0, item.credibilityScore)
                          : best,
                      undefined,
                    ),
                  },
                  contentRevision: input.contentRevision,
                  recipientEmail: input.recipient.email,
                },
                `${input.identity}:email:${input.recipient.id}`,
                'QUEUED',
              ),
          });
          newsNotificationsQueued += news.emailsQueued;
          newsArticlesQueued += news.articlesIncluded;
          await writeEvent(db, {
            category: 'MATCHING',
            code: 'matching.news_dispatched',
            message: 'Consolidated security-news email dispatched to the security team',
            runId: execution!.id,
            context: {
              matches: intelligenceMatches.length,
              recipientsNotified: news.emailsQueued,
              articlesIncluded: news.articlesIncluded,
              articlesAlreadySent: news.articlesSuppressed,
            },
          });
        }
      }
      // Include limited-confidence findings in the SAME recipient email as
      // confirmed findings. The renderer explains the confidence and its reason.
      //
      // `reviewNotifiedAt` is deliberately NOT a filter here (audit follow-up,
      // Finding 1): it is a GLOBAL stamp set when any recipient's email was
      // accepted, so filtering on it dropped findings for every recipient who
      // had not been told yet — including recipients added later. The
      // per-recipient `delivery_claims` record inside the consolidated queue is
      // what decides whether THIS recipient still needs THIS finding.
      const pending = vexEnforced.filter(
        (f) =>
          // Status and advisoryId are global bookkeeping. A DELIVERED finding
          // can still be new to a recipient added later. Only a recipient's
          // durable delivery claim determines whether that mailbox is notified.
          !['NOT_APPLICABLE', 'SUPPRESSED_VEX_NOT_AFFECTED', 'SECURITY_REJECTED'].includes(f.notificationStatus) &&
          !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status),
      );
      // ML-guided finding order: use the trained importance ranker when
      // available, falling back to the natural (severity) order.
      const mlOrdered = mlOrderFindingsByImportance(pending);
      pending.length = 0;
      pending.push(...mlOrdered);
      // Never gate findings on operator review or split the recipient's batch
      // by confidence, severity tier, or an arbitrary page size.
      // Subscription filtering happens inside the consolidated queue.
      if (pending.length) {
        notificationsQueued += await queueConsolidatedFindingNotifications(db, pending);
        advisoriesQueued = notificationsQueued ? 1 : 0;
      }
      const zeroDayLog = zeroDayDigestNotificationsQueued
        ? `; ${zeroDayDigestNotificationsQueued} zero-day digest notifications queued`
        : '';
      let deliveryLog = `${notificationsQueued} jobs queued${digestBuffered ? `; ${digestBuffered} findings buffered for the digest window` : ''}${newsNotificationsQueued ? `; ${newsNotificationsQueued} consolidated news emails queued` : ''}${manualReviewFindingsQueued ? `; ${manualReviewFindingsQueued} limited-confidence emails queued` : ''}${zeroDayLog}`;
      if (pending.length && !settings.autoDispatchEnabled) {
        deliveryLog += `; ${pending.length} findings pending but autoDispatchEnabled is false`;
      }
      // Audit L-2: an ingestion outage and a correlation failure are different
      // incidents. Keep the FAILED status (it drives alerting and the audit
      // level) but state explicitly in the log that correlation completed over
      // the cache, so the run is not misread as having produced nothing.
      const allFeedsFailed = feeds.length > 0 && succeeded === 0;
      execution = {
        ...correlated.execution,
        id: execution!.id,
        startTime: execution!.startTime,
        endTime: new Date().toISOString(),
        status: allFeedsFailed ? 'FAILED' : correlated.execution.status,
        scopeHours: execution!.scopeHours,
        // Audit P-1: bound the merged tail so a completed run's persisted log
        // also stays within the cap (the running array was bounded, but this
        // spread was not). Pinned state lines survive via boundExecutionLogs.
        logs: boundExecutionLogs([
          ...execution!.logs,
          ...(allFeedsFailed
            ? [
                'All enabled feeds failed; correlation completed against the cached corpus and queued findings remain valid',
              ]
            : []),
          `Product matching: ${newDetectionCount} new detections; ${correlated.newFindings.length} current matches; ${reconciled.length} retained findings`,
          `Delivery queue: ${deliveryLog}`,
        ]),
        phases: [
          {
            name: 'Feed ingestion',
            status:
              succeeded < feeds.length || acceptedResults.some((result) => result.warnings?.length)
                ? 'WARNING'
                : 'SUCCESS',
            durationMs: ingestionDuration,
            details: `${succeeded}/${feeds.length} feeds succeeded; ${rawCount} records read; cached intelligence retained`,
          },
          {
            ...correlated.execution.phases[0],
            details: `${byId.size} canonical CVEs; ${correlated.execution.stats.inRunDuplicatesDropped} duplicate records removed`,
          },
          {
            ...correlated.execution.phases[1],
            details: `${byId.size} CVEs evaluated against ${snapshot.watchlist.filter((asset) => asset.active).length} active products; ${correlated.newFindings.length} current matches; ${newDetectionCount} new`,
          },
          {
            name: 'Delivery queue',
            status: 'SUCCESS',
            durationMs: Date.now() - queueStarted,
            details: `${notificationsQueued} jobs queued${digestBuffered ? `; ${digestBuffered} findings buffered for the digest window` : ''}${pending.length && !settings.autoDispatchEnabled ? `; ${pending.length} findings pending but autoDispatchEnabled is false` : ''}${newsNotificationsQueued ? `; ${newsNotificationsQueued} consolidated news emails queued (${newsArticlesQueued} articles)` : ''}${manualReviewFindingsQueued ? `; ${manualReviewFindingsQueued} limited-confidence emails queued` : ''}${zeroDayLog}; transport acceptance is tracked separately`,
          },
        ],
      };
      execution.stats = {
        ...execution.stats,
        rawIngested: rawCount,
        matchedWatchlist: newDetectionCount,
        notificationsQueued,
        advisoriesQueued,
        digestBuffered,
        newsNotificationsQueued,
        unverifiableNotificationsQueued: manualReviewFindingsQueued,
        zeroDayDigestNotificationsQueued,
      };
      await saveActiveExecution(db, execution);
      // Clear next_catchup_run if all feeds have completed their catch-up.
      const pendingCatchup = acceptedResults.some((r) => r.syncState?.catch_up && r.syncState.hasMore);
      if (pendingCatchup) {
        // Back off to the latest per-feed next_catchup_at so the scheduler does
        // not retrigger catch-up before the per-feed cooldown has elapsed.
        const allCatchup = acceptedResults.flatMap((r) =>
          r.syncState?.catch_up && r.syncState?.next_catchup_at
            ? [Date.parse(r.syncState.next_catchup_at)]
            : [],
        );
        const nextCatchupRun = allCatchup.length ? Math.max(...allCatchup) : Date.now() + 60000;
        await db.query('UPDATE scheduler_state SET last_run=now(), next_catchup_run=$1 WHERE id=1', [
          new Date(Math.max(nextCatchupRun, Date.now())).toISOString(),
        ]);
      } else {
        await db.query('UPDATE scheduler_state SET last_run=now(), next_catchup_run=NULL WHERE id=1');
      }
      await writeEvent(db, {
        category: 'PIPELINE',
        level: execution!.status === 'FAILED' ? 'ERROR' : 'INFO',
        code: 'pipeline.finished',
        message: `Pipeline ${execution!.status.toLowerCase()}`,
        runId: execution!.id,
        context: { stats: execution!.stats },
      });
      await appendAudit(
        db,
        execution.status === 'FAILED' ? 'Pipeline failed' : 'Pipeline completed',
        `${execution.id}; ${newDetectionCount} new findings; ${succeeded}/${feeds.length} feeds succeeded`,
        'worker',
        'PIPELINE',
        execution.status === 'FAILED' ? 'ERROR' : undefined,
      );
    });
    return true;
  } catch (e) {
    signal?.throwIfAborted();
    // Audit H-4: losing the advisory-lock connection does not mean the run can
    // be abandoned silently. Previously this threw before recording anything,
    // leaving the execution wedged in RUNNING until another worker's recovery
    // pass collected it — during which queueRun() keeps returning the stale
    // execution and no new work is enqueued. Record the failure through the
    // pool (a fresh connection, since the lock client is dead) instead.
    if (connectionLost) {
      if (!execution) throw e;
      // Share the crash-recovery budget: the sweep counts stats.recoveryAttempts
      // (falling back to the historical log marker), so a worker that keeps
      // losing its lock exhausts 3 attempts total rather than 3 crashes plus
      // 3 lock losses.
      const lostLockExecution =
        (await get<PipelineExecution>(pool, 'executions', execution.id).catch(() => undefined)) ?? undefined;
      const lostLockRecoveries = lostLockExecution ? countRecoveries(lostLockExecution) : 0;
      await transaction(pool, async (db) => {
        const current = await getForUpdate<PipelineExecution>(db, 'executions', execution!.id);
        if (!current || !['QUEUED', 'RUNNING'].includes(current.status)) return;
      const nextAttempt = lostLockRecoveries + 1;
      if (current.stopRequestedAt) {
        const cancelled = {
          ...current,
          status: 'CANCELLED' as const,
          endTime: new Date().toISOString(),
          phases: current.phases.map((phase) =>
            phase.status === 'RUNNING' || phase.status === 'PENDING' ? { ...phase, status: 'CANCELLED' as const } : phase,
          ),
          logs: boundExecutionLogs([...new Set([...current.logs, 'Operator stop retained; worker did not restart after lock loss'])]),
        };
        await put(db, 'executions', execution!.id, cancelled);
        await writeEvent(db, {
          category: 'PIPELINE', level: 'INFO', code: 'pipeline.cancelled_after_lock_loss',
          message: 'Pipeline cancelled during lock-loss recovery because stop was requested', runId: execution!.id,
        });
        return;
      }
      if (nextAttempt >= 3) {
        const failed = {
          ...current,
          status: 'FAILED' as const,
          endTime: new Date().toISOString(),
          phases: current.phases.map((phase) =>
            phase.status === 'RUNNING' || phase.status === 'PENDING' ? { ...phase, status: 'FAILED' as const } : phase,
          ),
          stats: { ...current.stats, recoveryAttempts: nextAttempt },
          logs: boundExecutionLogs([
            ...new Set([...current.logs, `Recovery limit exceeded (attempt ${nextAttempt}/3); pipeline failed after repeated lock loss`]),
          ]),
        };
        await put(db, 'executions', execution!.id, failed);
        await writeEvent(db, {
          category: 'ISSUE', level: 'ERROR', code: 'pipeline.recovery_limit_exceeded',
          message: 'Pipeline recovery limit exceeded after repeated lock loss', runId: execution!.id,
          context: { recoveryAttempts: nextAttempt },
        });
        await appendAudit(db, 'Pipeline recovery exhausted', `Execution ${execution!.id}; repeated lock loss exhausted 3 recovery attempts`, 'worker', 'PIPELINE', 'ERROR');
        return;
      }
      await put(db, 'executions', execution!.id, {
        ...current,
        // Audit H-4: requeue instead of failing. The worker never reached the
          // commit transaction, so no result was persisted and nothing is
          // half-applied — the run is exactly as resumable as an interrupted
          // one. Marking it FAILED made it unrecoverable, because the recovery
          // sweep only rescues RUNNING/QUEUED records. Hand the run back as
          // QUEUED and count the restart against the same bounded recovery
          // budget the crash path uses, so a genuinely broken worker still
          // parks the run instead of looping forever.
          status: 'QUEUED',
          stats: { ...current.stats, recoveryAttempts: nextAttempt },
          phases: current.phases.map((phase) =>
            phase.status === 'RUNNING' ? { ...phase, status: 'PENDING' } : phase,
          ),
          logs: [
            ...current.logs,
            `Recovered interrupted worker (attempt ${nextAttempt}/3); restarting idempotently after lock-connection loss`,
          ],
        });
        await writeEvent(db, {
          category: 'ISSUE',
          level: 'WARNING',
          code: 'pipeline.worker_connection_lost',
          message: 'Pipeline worker lost its database lock connection; run requeued',
          runId: execution!.id,
          context: describeError(e),
        });
        await appendAudit(
          db,
          'Pipeline requeued',
          `Execution ${execution!.id}; worker lost its database lock connection after ${nextAttempt} restart(s)`,
          'worker',
          'PIPELINE',
          'WARNING',
        );
      }).catch(() => undefined);
      // Preserve the worker contract that a lost lock surfaces as a rejected run
      // (the scheduler treats the throw as a failed tick and backing off is
      // correct). The execution row is requeued or terminally failed; the next
      // worker therefore never sees a silently wedged RUNNING record.
      throw e;
    }
    if (execution) {
      // Cancellation is an intentional operator action; only a real failure
      // carries an error payload into the event and the audit trail.
      const failure: Record<string, unknown> = e instanceof PipelineStopped ? {} : describeError(e);
      await lockedTransaction(async (db) => {
        const current = await getForUpdate<PipelineExecution>(db, 'executions', execution!.id);
        await put(db, 'executions', execution!.id, {
          ...execution,
          status: e instanceof PipelineStopped ? 'CANCELLED' : 'FAILED',
          stopRequestedAt: current?.stopRequestedAt,
          phases: execution!.phases.map((phase) =>
            phase.status === 'RUNNING' || phase.status === 'PENDING'
              ? { ...phase, status: e instanceof PipelineStopped ? 'CANCELLED' : 'FAILED' }
              : phase,
          ),
          endTime: new Date().toISOString(),
          // Audit F-1 (merge side): the running array is capped but `current`
          // holds the previously persisted (also capped) record, so the union
          // here could still exceed EXECUTION_LOG_LIMIT on a long run. Route
          // through the same bound so a persisted execution record stays
          // bounded on every write path. Recovery state is unaffected either
          // way: it lives in stats.recoveryAttempts, not in these lines.
          // NOTE: assign `logs:` (not a bare spread) — spreading an array into
          // the object literal produced indexed keys and wiped the field, which
          // erased the operator's stop marker on every cancellation.
          logs: boundExecutionLogs([
            ...new Set([...(current?.logs || []), ...execution!.logs]),
            e instanceof Error ? e.message : 'Worker failed',
          ]),
        });
        await writeEvent(db, {
          category: e instanceof PipelineStopped ? 'PIPELINE' : 'ISSUE',
          level: e instanceof PipelineStopped ? 'INFO' : 'ERROR',
          code: e instanceof PipelineStopped ? 'pipeline.cancelled' : 'pipeline.failed',
          message:
            e instanceof PipelineStopped
              ? 'Pipeline stopped by operator'
              : 'Pipeline failed; inspect execution details',
          runId: execution!.id,
          context: failure,
        });
        await appendAudit(
          db,
          e instanceof PipelineStopped ? 'Pipeline stopped' : 'Pipeline failed',
          `Execution ${execution!.id}${
            typeof failure.error === 'string' ? `; ${failure.error.slice(0, 500)}` : ''
          }`,
          'worker',
          'PIPELINE',
          e instanceof PipelineStopped ? undefined : 'ERROR',
        );
      });
    } else throw e;
    return true;
  } finally {
    signal?.removeEventListener('abort', onAbort);
    if (heartbeat) clearInterval(heartbeat);
    if (locked && !released) {
      try {
        await lock.query(`SELECT pg_advisory_unlock(800003, ${schemaLockKey})`);
        await writeEvent(lock, {
          category: 'PIPELINE',
          level: 'INFO',
          code: 'pipeline.lock_released',
          message: 'Pipeline advisory lock released successfully',
        });
      } catch (unlockError) {
        // A failed unlock means this session may still own the lock. It must never
        // return to the pool: `lock.release(connectionLost)` below destroys the
        // client, and a destroy on an idle client queues the socket close. Mark
        // the connection as lost so the release path takes the "destroy" branch
        // even though the original error listener never fired.
        connectionLost = true;
        await writeEvent(lock, {
          category: 'PIPELINE',
          level: 'ERROR',
          code: 'pipeline.lock_release_failed',
          message: 'Failed to release pipeline advisory lock',
          context: {
            connectionLost,
            error: (unlockError as Error).message,
          },
        }).catch(() => undefined);
        console.error(JSON.stringify({
          level: 'error',
          event: 'pipeline_lock_cleanup_failed',
          message: 'Failed to release advisory lock',
          context: {
            connectionLost,
            error: (unlockError as Error).message,
          },
        }));
      }
    }
    lock.removeListener('error', onError);
    if (!released) lock.release(connectionLost);
  }
}
