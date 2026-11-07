import { transaction } from '../db.ts';
import { queueNativeNotifications } from './notifications.ts';
import { retainCorrelationData, cleanupStaleMatches } from './operations.ts';
import { Readable } from 'node:stream';
import type { Pool } from 'pg';
import { CorrelationTelemetry } from './telemetry.ts';
import { DeadLetterQueue } from './deadLetter.ts';
import { AdvisoryIngestor } from './ingest.ts';
import { PipelineSupervisor } from './supervisor.ts';
import { AdvisoryStreamProcessor } from './stream.ts';
import { claimPending, renewPending, acknowledgePending, acknowledgePendingExcept, MAX_PENDING_ATTEMPTS } from './pending.ts';

/** Structural equality for pending payloads (plain JSON values only). */
const samePayload = (left: unknown, right: unknown): boolean => {
  if (left === right) return true;
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
};
import { Heartbeat } from './heartbeat.ts';
export class CorrelationRuntime {
  readonly supervisor: PipelineSupervisor;
  readonly processor: AdvisoryStreamProcessor;
  /** Publishes liveness to an external receiver; disabled when no URL is set. */
  readonly heartbeat: Heartbeat;
  private timer?: ReturnType<typeof setInterval>;
  private schedulerTimer?: ReturnType<typeof setInterval>;
  private draining?: Promise<void>;
  private stopped = false;
  private lastMaintenance = 0;
  /**
   * Durable queue depth, sampled by the drain loop rather than by /metrics.
   * /metrics must stay database-independent (it is scraped during outages, which
   * is exactly when the database is unavailable), so the sampler lives here and
   * the route just reads the cached number.
   */
  pendingDepth = -1;
  /** When `pendingDepth` was last refreshed; 0 means never. */
  pendingSampledAt = 0;
  /** Set when a stale-match sweep or retention run last succeeded or failed. */
  private lastMaintenanceAttempt = 0;
  /** Set when the consumer is disabled, so readiness does not claim it runs. */
  readonly workerEnabled: boolean;
  /**
   * Epoch ms of the last pipeline scheduled-run, cached from scheduler_state.
   * /metrics is scraped during outages (when the DB may be unreachable), so the
   * value is sampled by a timer and the route reads the cache. 0 means "never
   * ran or not yet sampled"; the consumer recomputes age at scrape time.
   */
  pipelineLastRun = 0;
  /** When `pipelineLastRun` was last sampled; 0 means never. */
  pipelineLastRunSampledAt = 0;
  /** Cached from the settings record — 1 means the in-app scheduler is enabled. */
  pipelineSchedulerEnabled = false;
  /**
   * Refresh interval for scheduler state (seconds); defaults to intervalSeconds.
   * Must be at least 60 seconds to avoid overwhelming the database with refreshes.
   */
  private scheduledStateRefreshIntervalSeconds: number;
  constructor(
    private readonly pool: Pool,
    keys: string[],
    directory: string,
    options: {
      url: string;
      intervalSeconds: number;
      logLevel?: 'standard' | 'verbose';
      scheduledStateRefreshIntervalSeconds?: number;
      deadLetterStorageMode?: 'database' | 'filesystem';
    } = { url: '', intervalSeconds: 60 },
  ) {
    const telemetry = new CorrelationTelemetry();
    telemetry.verbosity = options.logLevel ?? 'standard';
    const queue = new DeadLetterQueue(directory, keys, telemetry, options.deadLetterStorageMode === 'database');
    this.supervisor = new PipelineSupervisor(pool, new AdvisoryIngestor(telemetry, queue));
    this.processor = new AdvisoryStreamProcessor(this.supervisor);
    this.heartbeat = new Heartbeat({
      url: options.url,
      intervalMs: options.intervalSeconds * 1000,
      suppressOnUnhealthy: true,
    });
    this.workerEnabled = process.env.WORKER_ENABLED !== 'false';
    // Default to the intervalSeconds, but allow override from callers
    this.scheduledStateRefreshIntervalSeconds = options.scheduledStateRefreshIntervalSeconds ?? options.intervalSeconds;
    if (this.scheduledStateRefreshIntervalSeconds < 60) {
      this.scheduledStateRefreshIntervalSeconds = 60;
    }
  }
  start(): void {
    if (this.timer) return;
    this.stopped = false;
    this.supervisor.start();
    // The ping reports on the pipeline, not on the HTTP process: a heartbeat
    // that fires while ingestion is refusing every advisory would tell the
    // external receiver that it is safe to stay silent.
    this.heartbeat.start(() => {
      if (!this.workerEnabled) return { healthy: true, reason: 'WORKER_DISABLED_MONITORING_ONLY' };
      if (this.supervisor.health !== 'HEALTHY')
        return { healthy: false, reason: this.supervisor.health };
      return { healthy: true, reason: 'HEALTHY' };
    });
    this.timer = setInterval(() => {
      if (this.draining || this.stopped || this.supervisor.health !== 'HEALTHY') return;
      this.draining = this.drain()
        .catch(() => {
          this.supervisor.ingestor.telemetry.log('ERROR', 'pending.drain_failed');
        })
        .finally(() => {
          this.draining = undefined;
          // Refresh the queue depth the stuck-ingestion alert depends on. A
          // failure leaves the previous sample rather than reporting zero, which
          // would read as "nothing queued" during a database outage.
          void this.pool
            .query('SELECT count(*)::int AS depth FROM correlation_pending')
            .then((result) => {
              this.pendingDepth = Number(result.rows[0]?.depth ?? 0);
              this.pendingSampledAt = Date.now();
            })
            .catch(() => {});
        });
    }, 1000);
    this.timer.unref();
    this.schedulerTimer = setInterval(() => {
      void this.refreshSchedulerState();
    }, this.scheduledStateRefreshIntervalSeconds * 1000);
    this.schedulerTimer.unref();
  }
  async flushLegacyDeadLetters(): Promise<void> {
    await this.supervisor.ingestor.flushDeadLetters(this.pool);
  }
  private async refreshSchedulerState(): Promise<void> {
    try {
      const row = (await this.pool.query('SELECT last_run FROM scheduler_state WHERE id=1')).rows[0];
      this.pipelineLastRun = row?.last_run ? Date.parse(row.last_run) : 0;
      this.pipelineLastRunSampledAt = Date.now();
      const settingsRow = (
        await this.pool.query<{ enabled: string }>(
          "SELECT data->>'schedulerEnabled' AS enabled FROM records WHERE kind='settings' AND id='main'",
        )
      ).rows[0];
      this.pipelineSchedulerEnabled = settingsRow?.enabled === 'true';
    } catch {
      // Keep previous values on database errors; the age gauge uses the last
      // successful sample, which is the correct semantics for outage scraping.
    }
  }
  private async drain(): Promise<void> {
    await this.cleanupStaleMatches();
    await this.queueNotifications();
    // Rows the claim no longer offers have exhausted MAX_PENDING_ATTEMPTS. Log
    // their count once per drain pass: silently leaving them in the table would
    // make a poisoned advisory invisible while `pending` still counts it.
    try {
      const exhausted = await this.pool.query<{ count: number }>(
        'SELECT count(*)::int AS count FROM correlation_pending WHERE attempts >= $1',
        [MAX_PENDING_ATTEMPTS],
      );
      const count = Number(exhausted.rows[0]?.count ?? 0);
      if (count) this.supervisor.ingestor.telemetry.log('CRITICAL', 'pending.attempts_exhausted', { count });
    } catch {
      // Metrics on a missing column (pre-032 database) must not block draining.
    }
    // The maintenance clock advanced even when the run failed, so a failing
    // sweep (for example a lock timeout while the table is being vacuumed) was
    // not retried for a full minute while its errors filled the log. Back off
    // for the full interval only after success; retry sooner after a failure,
    // bounded so a broken sweep cannot spin.
    if (Date.now() - this.lastMaintenanceAttempt >= 60_000 || Date.now() - this.lastMaintenance >= 10_000) {
      this.lastMaintenanceAttempt = Date.now();
      const retained = await transaction(this.pool, (db) => retainCorrelationData(db)).then(
        () => true,
        () => {
          this.supervisor.ingestor.telemetry.log('ERROR', 'retention.failed');
          return false;
        },
      );
      if (retained) this.lastMaintenance = Date.now();
    }
    while (!this.stopped && this.supervisor.health === 'HEALTHY') {
      // Leased SKIP LOCKED claims survive crashes; final ingestion is idempotent.
      // Claim at most concurrency slots, so leases don't expire behind a local queue.
      const batch = await claimPending(this.pool, this.supervisor.concurrencyLimit);
      if (!batch.jobs.length) return;
      let renewing: Promise<unknown> | undefined;
      const heartbeat = setInterval(() => {
        if (renewing) return;
        renewing = renewPending(this.pool, batch).catch(() => {
          this.supervisor.ingestor.telemetry.log('WARN', 'pending.lease_renewal_failed');
        }).finally(() => { renewing = undefined; });
      }, 20_000);
      heartbeat.unref();
      try {
        await this.processor.processAdvisoryStream(
          Readable.from(batch.jobs.map((job) => job.payload)),
          this.supervisor.concurrencyLimit,
          this.pool,
        );
        await acknowledgePending(this.pool, batch);
      } catch (error) {
        // At least one record could not be made durable. Its pending row is the
        // last copy, so it is retained — but only it. Acknowledging the whole
        // batch would delete the record; acknowledging none replays the entire
        // batch and re-runs every advisory that already committed. The stream
        // reports which payloads failed, and those are matched back to the jobs
        // by payload identity (pending payloads are JSON-round-tripped, so the
        // comparison is structural and stable).
        const failed = (error as { failedRecords?: unknown[] }).failedRecords ?? [];
        const retainedIds = failed.length
          ? batch.jobs
              .filter((job) => failed.some((record) => samePayload(record, job.payload)))
              .map((job) => job.id)
          : // The stream failed before it could attribute records (e.g. the
            // source itself threw): nothing may be acknowledged.
            batch.jobs.map((job) => job.id);
        if (retainedIds.length < batch.jobs.length) {
          await acknowledgePendingExcept(this.pool, batch, retainedIds).catch(() => 0);
        }
        this.supervisor.ingestor.telemetry.log('CRITICAL', 'pending.batch_partially_acknowledged', {
          count: batch.jobs.length - retainedIds.length,
        });
        throw error;
      } finally {
        clearInterval(heartbeat);
        await renewing;
      }
      await this.queueNotifications();
    }
  }
  private async cleanupStaleMatches(): Promise<void> {
    await transaction(this.pool, (db) => cleanupStaleMatches(db)).catch(() => {
      this.supervisor.ingestor.telemetry.log('ERROR', 'stale_matches.cleanup_failed');
    });
  }
  private async queueNotifications(): Promise<void> {
    await transaction(this.pool, (db) => queueNativeNotifications(db)).catch(() => {
      this.supervisor.ingestor.telemetry.log('ERROR', 'notifications.queue_failed');
    });
  }
  async stop(): Promise<void> {
    this.stopped = true;
    clearInterval(this.timer);
    this.timer = undefined;
    clearInterval(this.schedulerTimer);
    this.schedulerTimer = undefined;
    this.heartbeat.stop();
    await this.supervisor.stop();
    await this.draining;
  }
}
