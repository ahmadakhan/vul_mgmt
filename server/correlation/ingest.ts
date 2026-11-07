import { timedQuery } from './query.ts';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import type { Pool, PoolClient, QueryResultRow } from 'pg';
import { AdvisoryInputSchema } from './validation.ts';
import { extractText } from './extraction.ts';
import { TextCorrelationEngine, type TimedQuery } from './engine.ts';
import { linkPreCveClusters, clusterWindowDays, DEFAULT_CLUSTER_OPEN_WINDOW_DAYS } from './clusters.ts';
import type { CorrelationTelemetry } from './telemetry.ts';
import type { DeadLetterQueue } from './deadLetter.ts';
export type IngestionResult = 'PROCESSED' | 'DUPLICATE' | 'DEAD_LETTER' | 'UNDURABLE';
export const databaseCode = (error: unknown): string => {
  const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
  return /^[A-Z0-9]{5,20}$/.test(code) ? code : 'DATABASE_FAILURE';
};
/**
 * Wall-clock budget for the whole four-attempt ladder. Four attempts at
 * 3.5 s of database work plus their backoff must fit this, and it must fit
 * inside the stream's processing deadline (stream.ts).
 */
export const ATTEMPT_BUDGET_MS = 20_000;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const transientDatabaseError = (error: unknown) =>
  /^(40001|40P01|08[A-Z0-9]{3}|57P0[123]|ECONNRESET|ECONNREFUSED|EPIPE|ETIMEDOUT|ENETUNREACH)$/.test(
    databaseCode(error),
  ) ||
  (error instanceof Error &&
    /connection terminated|connection timeout|timeout exceeded when trying to connect/i.test(error.message));
export class AdvisoryIngestor {
  /**
   * Cached logging detail level, refreshed at the start of each advisory.
   *
   * It cannot be resolved inside the ingest transaction: the first telemetry
   * entries (`ingestion.started`, `extraction.completed`) are emitted before a
   * connection is even acquired, so reading the setting later meant those lines
   * were filtered under the previous level and the advisory committed with an
   * empty telemetry buffer. Refreshing per advisory keeps a settings change
   * effective without a restart while ensuring the level is known up front.
   */
  private verbosityLevel: 'standard' | 'verbose' = 'standard';
  private verbosityCheckedAt = 0;
  constructor(
    readonly telemetry: CorrelationTelemetry,
    readonly deadLetterQueue: DeadLetterQueue,
    private readonly engine = new TextCorrelationEngine(),
  ) {}
  async flushDeadLetters(pool: Pool): Promise<number> {
    let totalFlushed = 0;
    for (let batch = 0; batch < 26; batch++) {
      const flushed = await this.deadLetterQueue.flush(pool);
      totalFlushed += flushed;
      if (flushed < 10) break;
    }
    return totalFlushed;
  }
  /** Refresh from the settings record at most once per second. */
  private async refreshVerbosity(pool: Pool): Promise<void> {
    const now = Date.now();
    if (now - this.verbosityCheckedAt < 1000) return;
    try {
      const row = (
        await pool.query<{ value: string | null }>(
          "SELECT data->>'logVerbosity' AS value FROM records WHERE kind='settings' AND id='main'",
        )
      ).rows[0];
      this.verbosityLevel = row?.value === 'verbose' ? 'verbose' : 'standard';
      // Only a successful read resets the interval. A transient failure must be
      // retried on the next advisory, not latched for a second.
      this.verbosityCheckedAt = now;
    } catch {
      // Keep the last known level: it is a display preference, never a gate.
      this.verbosityLevel = this.telemetry.verbosity;
    }
    this.telemetry.verbosity = this.verbosityLevel;
  }
  /** Resolve the operator-configured cluster window; falls back to the
   * default when the policy row is absent (pre-021 database mid-migration). */
  private async clusterWindowDays(query: TimedQuery): Promise<number> {
    try {
      const row = (
        await query<{ days: number | null }>(
          'SELECT pre_cve_cluster_window_days AS days FROM correlation_policy WHERE id=1',
        )
      ).rows[0];
      return clusterWindowDays(row?.days);
    } catch (error) {
      if (databaseCode(error) !== '42703' && databaseCode(error) !== '42P01') throw error;
      return DEFAULT_CLUSTER_OPEN_WINDOW_DAYS;
    }
  }
  /**
   * Maximum review rows one advisory may write. A REVIEW verdict applies to
   * every asset of the product, so the unbounded shape is O(estate size) rows
   * and round trips inside a single 3.5 s transaction. The cap is a *review
   * queue* budget, not a correctness limit: the reason string and the cluster
   * membership still record the finding, and the overflow is reported.
   */
  static readonly DEFAULT_REVIEW_ROW_CAP = 200;
  private async reviewRowCap(query: TimedQuery): Promise<number> {
    try {
      const row = (
        await query<{ cap: number | null }>('SELECT review_row_cap AS cap FROM correlation_policy WHERE id=1')
      ).rows[0];
      const cap = Number(row?.cap);
      if (Number.isInteger(cap) && cap >= 1 && cap <= 10_000) return cap;
    } catch (error) {
      // Only a *missing* setting (a database that predates the column)
      // justifies the built-in default. SQLSTATE 42703 is undefined_column;
      // 42P01 is undefined_table. Any other failure is a real fault and must
      // surface, not be masked as "the operator did not configure a cap".
      if (databaseCode(error) !== '42703' && databaseCode(error) !== '42P01') throw error;
    }
    return AdvisoryIngestor.DEFAULT_REVIEW_ROW_CAP;
  }
  async processIncomingAdvisory(
    rawInput: unknown,
    dbPool: Pool,
    trackingId: string = randomUUID(),
    signal?: AbortSignal,
  ): Promise<IngestionResult> {
    // `trackingId` is interpolated into a uuid[] parameter and used as a
    // telemetry correlation key. It is caller-supplied, so anything that is not
    // a UUID is replaced rather than allowed to fail the telemetry insert and
    // abort the advisory it describes.
    trackingId = UUID_PATTERN.test(trackingId) ? trackingId : randomUUID();
    const started = performance.now();
    let databaseTime = 0;
    // Resolve the logging level before the first entry so the whole advisory is
    // recorded under one consistent level.
    await this.refreshVerbosity(dbPool);
    this.telemetry.log('INFO', 'ingestion.started', { trackingId });
    const parsed = AdvisoryInputSchema.safeParse(rawInput);
    if (!parsed.success) {
      this.telemetry.log('WARN', 'validation.failed', { trackingId, count: parsed.error.issues.length });
      const durable = await this.persistFailure(rawInput, 'VALIDATION_FAILED', trackingId, dbPool);
      this.telemetry.completed++;
      this.telemetry.latencyTotal += performance.now() - started;
      return durable ? 'DEAD_LETTER' : 'UNDURABLE';
    }
    const input = parsed.data;
    const fingerprint = createHash('sha256')
      .update(JSON.stringify([input.url, input.title]))
      .digest('hex');
    try {
      const extracted = await extractText(
        `${input.title} ${input.content}`,
        this.telemetry,
        trackingId,
        signal,
      );
      // Four attempts at the per-attempt budget above is ~14 s of database
      // time; the delays between them must fit inside ATTEMPT_BUDGET_MS or the
      // ladder ends exactly when the stream's processing deadline aborts it,
      // and the last attempt is killed instead of dead-lettering cleanly.
      const attemptStarted = performance.now();
      for (let attempt = 0; attempt <= 3; attempt++) {
        let client: PoolClient | undefined;
        let released = false;
        let failed = false;
        let connectionError: Error | undefined;
        const onClientError = (error: Error) => {
          connectionError = error;
          failed = true;
        };
        const abort = () => {
          if (client && !released) {
            released = true;
            client.release(true);
          }
        };
        try {
          signal?.throwIfAborted();
          const connectStart = performance.now();
          client = await dbPool.connect();
          client.on('error', onClientError);
          databaseTime += performance.now() - connectStart;
          signal?.addEventListener('abort', abort, { once: true });
          signal?.throwIfAborted();
          const query: TimedQuery = async <T extends QueryResultRow>(sql: string, values?: unknown[]) => {
            signal?.throwIfAborted();
            if (connectionError) throw connectionError;
            const queryStart = performance.now();
            try {
              return await client!.query<T>(timedQuery(sql, values));
            } finally {
              databaseTime += performance.now() - queryStart;
            }
          };
          await query('BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED');
          // Per-attempt budgets. `lock_timeout` is below `statement_timeout` so a
          // blocked lock fails as contention (retryable) rather than burning the
          // whole statement budget, and all four attempts fit inside the
          // stream's processing deadline (stream.ts PROCESSING_DEADLINE_MS).
          await query("SET LOCAL statement_timeout='3500ms'");
          await query("SET LOCAL lock_timeout='1500ms'");
          await query("SET LOCAL idle_in_transaction_session_timeout='5000ms'");
          // Preliminary duplicate check: a fingerprint that is visible and
          // already processed is a duplicate and nothing else happens. The
          // authoritative check is the URL-conflict path below, which also
          // distinguishes an unprocessed (crashed) row that must be resumed.
          const duplicate = await query<{ processed: boolean }>(
            'SELECT processed_at IS NOT NULL AS processed FROM unstructured_advisories WHERE fingerprint=$1',
            [fingerprint],
          );
          if (duplicate.rows[0]?.processed) {
            await query('COMMIT');
            this.telemetry.log('INFO', 'ingestion.duplicate', { trackingId });
            return 'DUPLICATE';
          }
          let mergedAdvisory = false;
          let unfinishedAdvisoryId: string | null = null;
          // Resolve (or create) the advisory row and report which case applied.
          // The URL is the natural key: the row is inserted, or an existing row
          // at this URL is updated in place when its content changed.
          // A fingerprint already stored under a different URL is a duplicate;
          // it is detected by probing for an existing row rather than by
          // attempting a write that could raise a unique violation.
          const advisoryId = await (async (): Promise<string | null> => {
            const inserted = await query<{ id: string }>(
              `INSERT INTO unstructured_advisories(id,title,content,url,fingerprint)
               VALUES($1,$2,$3,$4,$5) ON CONFLICT (url) DO NOTHING RETURNING id`,
              [randomUUID(), input.title, extracted.cleanContent, input.url, fingerprint],
            );
            if (inserted.rowCount) return inserted.rows[0].id;
            // The URL is known to exist (the INSERT above found a conflict), so a
            // matching fingerprint means duplicate content already stored. FOR
            // UPDATE locks any matching row so the merge below is race-free.
            const duplicateFingerprint =
              ((await query('SELECT 1 FROM unstructured_advisories WHERE fingerprint=$1 FOR UPDATE', [fingerprint]))
                .rowCount ?? 0) > 0;
            const current = await query<{ id: string; processed: boolean }>(
              `SELECT id, processed_at IS NOT NULL AS processed FROM unstructured_advisories WHERE url=$1`,
              [input.url],
            );
            const row = current.rows[0];
            if (!row) return null;
            if (duplicateFingerprint) {
              // Same content already stored (possibly under this URL): nothing
              // to merge. An unprocessed row is resumed so a crash between
              // INSERT and the match writes cannot strand an advisory.
              if (!row.processed) {
                unfinishedAdvisoryId = row.id;
                return row.id;
              }
              return null;
            }
            const merged = await query<{ id: string }>(
              `UPDATE unstructured_advisories SET
                 title=$1, content=$2, fingerprint=$3, processed_at=NULL
               WHERE url=$4 RETURNING id`,
              [input.title, extracted.cleanContent, fingerprint, input.url],
            );
            if (!merged.rowCount) return null;
            mergedAdvisory = true;
            this.telemetry.log('INFO', 'ingestion.url_merged', { trackingId });
            return merged.rows[0].id;
          })();
          if (!advisoryId) {
            await query('COMMIT');
            this.telemetry.log('INFO', 'ingestion.duplicate', { trackingId });
            return 'DUPLICATE';
          }
          // A crash between inserting the advisory and committing its matches
          // leaves `processed_at` NULL on a row whose content is already stored
          // (see the fingerprint branch above). The advisory is then
          // re-correlated here rather than being declared complete.
          const pending = await query<{ processed_at: Date | null }>(
            'SELECT processed_at FROM unstructured_advisories WHERE id=$1',
            [advisoryId],
          );
          if (pending.rows[0]?.processed_at && advisoryId !== unfinishedAdvisoryId) {
            await query('COMMIT');
            this.telemetry.log('INFO', 'ingestion.duplicate', { trackingId });
            return 'DUPLICATE';
          }
          // Correlation runs on the advisory's own transaction and snapshot, so
          // the matches that are written and the assets they were derived from
          // are consistent even if inventory changes concurrently. It runs
          // once per attempt: a retried transaction must re-read the inventory,
          // because the attempt that failed may have observed a stale page.
          const matches = await this.engine.correlate(input, extracted, query);
          // Pre-CVE cluster linkage runs inside the same transaction: the
          // advisory, its matches, and its cluster membership commit atomically.
          // The window is read here rather than cached so an operator policy
          // change takes effect on the next advisory without a restart.
          const entities = matches
            .filter((match) => match.vendor && match.product)
            .map((match) => ({ vendor: match.vendor, product: match.product }));
          const windowDays = await this.clusterWindowDays(query);
          // Adapt the transaction-bound TimedQuery to the structural query
          // interface used by the cluster module (both are the same client).
          const clusterDb = {
            query: (sql: string, values?: unknown[]) => query<Record<string, unknown>>(sql, values),
            client,
            inTransaction: true,
          };
          await linkPreCveClusters(clusterDb, advisoryId, entities, matches.length, extracted.cveIds, windowDays);
          // Bound the review queue. A REVIEW verdict is applied to every asset of
          // the named product, so a 40,000-seat product produces 40,000 review
          // rows for one article — an operator-facing flood that also costs one
          // round trip per row inside the advisory transaction. The remainder is
          // reported instead of being silently dropped.
          const reviewMatches = matches.filter((match) => match.confidence === 'LOW');
          const reviewCap = await this.reviewRowCap(query);
          const reviewBudget = Math.min(reviewMatches.length, reviewCap);
          const deferredReviews = reviewMatches.length - reviewBudget;
          let written = 0;
          for (const match of matches) {
            if (match.confidence === 'LOW') {
              const withinBudget = written < reviewBudget;
              written++;
              if (!withinBudget) continue;
              await query(
                `INSERT INTO low_confidence_review_buffer(advisory_id,asset_id,reason)
                VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
                [advisoryId, match.assetId || null, match.reason],
              );
            } else
              await query(
                `INSERT INTO correlation_matches(advisory_id,asset_id,vendor,product,confidence,reason)
                VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
                [advisoryId, match.assetId, match.vendor, match.product, match.confidence, match.reason],
              );
          }
          if (deferredReviews > 0)
            this.telemetry.log('WARN', 'ingestion.review_capped', { trackingId, count: deferredReviews });
          for (const match of matches)
            if (match.assetId && match.assetRevision)
              await query(
                `INSERT INTO correlation_match_evidence(advisory_id,asset_id,asset_revision) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
                [advisoryId, match.assetId, match.assetRevision],
              );
          await query('UPDATE unstructured_advisories SET processed_at=now() WHERE id=$1', [advisoryId]);
          // A merge replaced the advisory's *content*, so it must replace the
          // conclusions derived from the content too. Before this, a title or
          // body edit that removed the CVE reference left the previous HIGH
          // match in place forever: correlation_matches is insert-only and its
          // primary key is (advisory_id, asset_id), so nothing could retire a
          // match the new text no longer supports. Operator decisions are
          // evidence, not derived state, and are preserved.
          if (mergedAdvisory) {
            const keep = matches.filter((match) => match.assetId).map((match) => match.assetId);
            const retained = await query<{ asset_id: string | null }>(
              'DELETE FROM correlation_matches m WHERE m.advisory_id=$1 AND NOT (m.asset_id = ANY($2::uuid[])) RETURNING m.asset_id',
              [advisoryId, keep],
            );
            // Evidence describes the *asset revision* that was matched at the
            // time; it is retired only with the matches it belonged to.
            if (retained.rowCount)
              await query(
                'DELETE FROM correlation_match_evidence WHERE advisory_id=$1 AND asset_id=ANY($2::uuid[])',
                [advisoryId, retained.rows.map((row) => row.asset_id)],
              );
            const retainedReviews = await query<{ asset_id: string | null }>(
              `DELETE FROM low_confidence_review_buffer b
               WHERE b.advisory_id=$1 AND NOT (b.asset_id = ANY($2::uuid[]))
                 AND NOT EXISTS (SELECT 1 FROM correlation_review_decisions d WHERE d.review_id=b.id)
               RETURNING b.asset_id`,
              [advisoryId, matches.filter((match) => match.confidence === 'LOW' && match.assetId).map((match) => match.assetId)],
            );
            if (retained.rowCount || retainedReviews.rowCount)
              this.telemetry.log('INFO', 'ingestion.merged_matches_retired', {
                trackingId,
                count: (retained.rowCount ?? 0) + (retainedReviews.rowCount ?? 0),
              });
          }
          // Persist telemetry to operational_events BEFORE commit for crash durability
          await this.telemetry.persistBeforeCommit(client, trackingId);
          await query('COMMIT');
          this.telemetry.log('INFO', 'ingestion.committed', {
            trackingId,
            count: matches.length,
            ingestionLatencyMs: performance.now() - started,
            totalDatabaseTimeMs: databaseTime,
          });
          return 'PROCESSED';
        } catch (error) {
          failed = true;
          // A merge that reached the database changes the fingerprint first; a
          // retry of the same payload must therefore be a duplicate, not a
          // second merge that silently re-correlates and re-inserts matches.
          if (client && !released) await client.query(timedQuery('ROLLBACK', [], 1000)).catch(() => {});
          if (signal?.aborted || !transientDatabaseError(error) || attempt === 3) throw error;
          this.telemetry.log('WARN', 'database.transaction_retry', { trackingId, attempt: attempt + 1 });
        } finally {
          signal?.removeEventListener('abort', abort);
          client?.removeListener('error', onClientError);
          if (client && !released) {
            released = true;
            client.release(failed);
          }
        }
        // Full jitter rather than base + small noise: every worker that failed
        // on the same failover event otherwise retries within ~50 ms of its
        // peers. The cap keeps the ladder inside the attempt budget.
        const backoff = Math.random() * Math.min(100 * 2 ** attempt, 2_000);
        if (performance.now() - attemptStarted + backoff > ATTEMPT_BUDGET_MS)
          throw new Error('RETRY_BUDGET_EXHAUSTED');
        await delay(backoff, undefined, { signal });
      }
      throw new Error('RETRIES_EXHAUSTED');
    } catch (error) {
      this.telemetry.log('ERROR', 'ingestion.failed', { trackingId, totalDatabaseTimeMs: databaseTime });
      const durable = await this.persistFailure(rawInput, databaseCode(error), trackingId, dbPool);
      // The transaction rolled back, so its buffered telemetry can never be
      // persisted with it. Discard *after* the failure has been made durable:
      // discarding first removed the very line describing the failure before
      // the spool path could report it.
      this.telemetry.discard(trackingId);
      return durable ? 'DEAD_LETTER' : 'UNDURABLE';
    } finally {
      this.telemetry.completed++;
      this.telemetry.latencyTotal += performance.now() - started;
    }
  }



  /**
   * Durable fallback chain: encrypted spool first, then the database.
   *
   * A failed advisory must never be dropped. The previous implementation let a
   * full spool throw out of the caller, which both lost the record and aborted
   * the surrounding stream — turning a disk-pressure event into a pipeline-wide
   * outage precisely when load was highest. Every failure here is contained and
   * reported, never propagated.
   */
  private async persistFailure(
    raw: unknown,
    errorCode: string,
    trackingId: string,
    dbPool: Pool,
  ): Promise<boolean> {
    let outcome: 'SPOOLED' | 'DATABASE' | 'capacity' | 'unavailable' = 'capacity';
    try {
      outcome = await this.deadLetterQueue.capture(raw, errorCode, trackingId, dbPool);
      if (outcome === 'SPOOLED' || outcome === 'DATABASE') return true;
    } catch (error) {
      this.telemetry.log('CRITICAL', 'dead_letter.spool_failed', { trackingId });
    }
    if (outcome !== 'unavailable' &&
      await this.deadLetterQueue.captureToDatabase(raw, errorCode, trackingId, dbPool)) return true;
    // The durable store is unavailable. This is the only remaining loss window, so
    // the caller must NOT treat the record as durably handled. It is logged at
    // CRITICAL with enough identifiers to reconstruct the record from the
    // source feed, and the ingest outcome is UNDURABLE so a pending row is not
    // acknowledged and deleted.
    this.telemetry.log('CRITICAL', 'dead_letter.undurable', { trackingId });
    return false;
  }
}
