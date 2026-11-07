import { readFileSync, existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
const _envPath = join(process.cwd(), '.env');
if (existsSync(_envPath) && !process.env.DATABASE_URL) {
  const _raw = readFileSync(_envPath, 'utf8');
  for (const _line of _raw.split(String.fromCharCode(10))) {
    const _trimmed = _line.trim();
    if (!_trimmed || _trimmed.startsWith('#')) continue;
    const _eq = _trimmed.indexOf('=');
    if (_eq === -1) continue;
    const _key = _trimmed.slice(0, _eq).trim();
    const _value = _trimmed
      .slice(_eq + 1)
      .trim()
      .replace(/^['"]|['"]$/g, '');
    if (!(_key in process.env)) process.env[_key] = _value;
  }
}

import { backfillCorrelationInventory } from './correlation/inventory.ts';
import { CorrelationRuntime } from './correlation/runtime.ts';
import { describeError, writeEvent } from './events';
import { loadConfig } from './config';
import { createPool, migrate, transaction, get, put, list, REQUIRED_SCHEMA_VERSION } from './db';
import { createApp } from './app';
import { createRequester } from './network';
import { createMailSender, deliverNext } from './delivery';
import { flushDueDigest } from './digest';
import { runDailyDigest } from './dailyDigest';
import { closePdfRenderer } from './pdf';
import { initMlRuntime } from './ml/integration.ts';
import { encryptionKeys } from './secrets';
import { runScheduledTraining, TrainingAlreadyRunningError } from './ml/train/cron.ts';
import type { TrainingSummary } from './ml/train/orchestrator.ts';
import { isTelemetryAnomaly, shouldSampleMlTelemetry } from './ml/integration.ts';
import type { Db } from './db';
import { processPipeline } from './pipeline';
import { runSelfHealCheck } from './selfHealing';
import { runRetention } from './retention';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { AppSettings } from '../src/types/index.ts';
import { reconcileRecommendedFeeds } from './feedBootstrap.ts';

const config = loadConfig(),
  pool = createPool(config.DATABASE_URL);
const mlStorageOptions = {
  directory: config.ML_DIRECTORY,
  signingKey: config.ML_SIGNING_KEY,
  ...(config.ML_STORAGE_MODE === 'database' ? { database: pool } : {}),
};
const VERBOSE = config.LOG_LEVEL === 'verbose';
const verboseLog = (event: string, context: Record<string, unknown> = {}) => {
  if (VERBOSE) console.log(JSON.stringify({ level: 'info', event, ...context }));
};
pool.on('error', (error) =>
  console.error(JSON.stringify({ level: 'error', event: 'database-connection', code: (error as any).code })),
);
if (config.NODE_ENV === 'production') {
  const initialized = await pool.query("SELECT to_regclass('schema_migrations') AS name");
  if (!initialized.rows[0]?.name)
    throw new Error('Database schema is not initialized; run migrations before starting');
  const result = await pool.query('SELECT COALESCE(MAX(version), 0)::int AS version FROM schema_migrations');
  const version = Number(result.rows[0]?.version || 0);
  if (version < REQUIRED_SCHEMA_VERSION)
    throw new Error(
      `Database schema version ${version} is older than required version ${REQUIRED_SCHEMA_VERSION}; run migrations before starting`,
    );
} else await migrate(pool);
await transaction(
  pool,
  async (db) => {
    if (await get(db, 'systemState', 'native-inventory-v1')) return;
    await backfillCorrelationInventory(db);
    await put(db, 'systemState', 'native-inventory-v1', { completedAt: new Date().toISOString() });
  },
  undefined,
  { locks: ['native-inventory-bootstrap'] },
);
await transaction(
  pool,
  async (db) => {
    await reconcileRecommendedFeeds(db, config.BOOTSTRAP_RECOMMENDED_FEEDS === 'true');
  },
  undefined,
  { locks: ['native-inventory-bootstrap'] },
);
// triggered explicitly via `npm run seed` with BOOTSTRAP_RECOMMENDED_FEEDS=true
// (see .env.example), so the server never opens egress to external feeds in
// dev or prod without an operator's deliberate action.
await writeEvent(pool, {
  category: 'SYSTEM',
  code: 'system.started',
  message: 'Application initialized',
  context: { workerEnabled: config.WORKER_ENABLED === 'true' },
});
const request = createRequester(config),
  sendMail = createMailSender(config, pool, request);
// The correlation runtime fetches settings at runtime (via refreshSchedulerState)
  // to keep the 60-minute scheduler aligned with the pipeline's interval.
  const correlation = new CorrelationRuntime(
    pool,
    encryptionKeys(config),
    config.CORRELATION_DLQ_DIRECTORY,
    {
      url: config.HEARTBEAT_URL,
      intervalSeconds: config.HEARTBEAT_INTERVAL_SECONDS,
      logLevel: config.LOG_LEVEL === 'verbose' ? 'verbose' : 'standard',
      scheduledStateRefreshIntervalSeconds: 60,
      deadLetterStorageMode: config.CORRELATION_DLQ_STORAGE_MODE,
    },
  );
  if (config.CORRELATION_DLQ_STORAGE_MODE === 'database') await correlation.flushLegacyDeadLetters();
if (config.WORKER_ENABLED === 'true') correlation.start();
else correlation.supervisor.start();

const mlRuntime = await initMlRuntime(pool, mlStorageOptions)
  .catch((error) => { console.error('ML runtime init failed:', error); return undefined; });
const app = createApp(pool, config, request, { correlation, mlRuntime,
  // The liveness probe only performs the stall check where the probe timeout is
  // comfortably above the block threshold; see the option's documentation.
  hangDetection: config.HANG_DETECTION_ENABLED === 'true',
});
/**
 * Start listening on `port`, retrying up to `maxAttempts` times when the port
 * is already in use (for example a `tsx watch` restart race). The process that
 * holds the port is never terminated: it may be an unrelated service or another
 * healthy instance, so after the retries are exhausted the failure names the
 * conflicting port and is left for the operator to resolve.
 */
async function listenWithRetry(port: number, host: string, maxAttempts = 5): Promise<Server> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const server = createServer(app);
    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error) => reject(error);
        server.on('error', onError);
        server.listen(port, host, () => {
          server.removeListener('error', onError);
          console.log(JSON.stringify({ event: 'listening', port }));
          resolve();
        });
      });
      return server;
    } catch (error: unknown) {
      const code = (error as NodeJS.ErrnoException)?.code;
      if (code !== 'EADDRINUSE') throw error;
      lastError = error;
      if (attempt === maxAttempts) break;
      await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
    }
  }
  const error = new Error(
    `Port ${port} is already in use on ${host} (EADDRINUSE) after ${maxAttempts} attempts. ` +
      'Stop the process using this port or configure a different PORT; no process was terminated.',
  );
  (error as NodeJS.ErrnoException).code = 'EADDRINUSE';
  (error as Error & { cause?: unknown }).cause = lastError;
  throw error;
}
const server = await listenWithRetry(config.PORT, '0.0.0.0');
server.requestTimeout = 30000;
server.headersTimeout = 15000;
let stopping = false,
  pipeline: Promise<unknown> | null = null,
  outbox: Promise<unknown> | null = null,
  digest: Promise<unknown> | null = null;
const report = (event: string) => (error: unknown) => {
  const detail = describeError(error);
  void writeEvent(pool, {
    category: 'ISSUE',
    level: 'ERROR',
    code: 'worker.failed',
    message: 'Background worker failed',
    context: { component: event, ...detail },
  }).catch((writeError: unknown) => {
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'event.write_failed',
        component: event,
        message: writeError instanceof Error ? writeError.message : String(writeError),
      }),
    );
  });
  console.error(JSON.stringify({ level: 'error', event, ...detail }));
};

/**
 * Writes a structured ML training result event to the operational log.
 * Non-blocking: any failure is swallowed so a logging hiccup never blocks the training pipeline.
 */
async function logMlTrainingResult(pool: Db, summary: TrainingSummary): Promise<void> {
  const failed = summary.results.filter((r) => r.status === 'failed');
  const trained = summary.results.filter((r) => r.status === 'trained');
  try {
    await writeEvent(pool, {
      category: 'ML',
      code: 'ml.training.completed',
      message: `ML training cycle finished: ${trained.length} trained, ${failed.length} failed, ${summary.summary.saved} saved`,
      level: failed.length > 0 ? 'WARNING' : 'INFO',
      context: {
        timestamp: summary.timestamp,
        totalModels: summary.summary.total,
        trained: trained.length,
        failed: failed.length,
        saved: summary.summary.saved,
        skipped: summary.summary.skipped ?? 0,
        results: summary.results.map((r) => ({
          modelId: r.modelId,
          status: r.status,
          samplesCollected: r.samplesCollected,
          validationPassed: r.validation.passed,
          failureReason: r.validation.failureReason,
          saved: r.saved,
        })),
      },
    });
  } catch {
    /* ML logging never blocks the training pipeline */
  }
}
/**
 * Backstop for a guarded operation that never settles despite its own deadline.
 * Retention and the digest renderer have explicit cancellation; this only covers
 * the case where cancellation itself cannot complete, so it is deliberately
 * longer than any legitimate run and is a last resort, not the deadline.
 * Configurable via STUCK_PROMISE_MS (default: 5 minutes).
 */
const STUCK_PROMISE_MS = Number(process.env.STUCK_PROMISE_MS ?? 5 * 60_000);
let digestStartedAt = 0;
let pipelineStartedAt = 0;
let outboxStartedAt = 0;
let digestGeneration = 0;
let pipelineController: AbortController | undefined;
let outboxGeneration = 0;
/** In-flight self-healing check; prevents overlapping watchdog runs per tick. */
let selfHealRunning: Promise<void> | null = null;
const tick = () => {
  if (stopping || config.WORKER_ENABLED !== 'true') return;
  verboseLog('worker.tick');
  if (pipeline && !pipelineController?.signal.aborted && Date.now() - pipelineStartedAt > STUCK_PROMISE_MS) {
    const reason = new Error('Pipeline stopped making progress; cancelling the current attempt');
    void report('pipeline')(reason);
    pipelineController?.abort(reason);
  }
  if (!pipeline) {
    pipelineStartedAt = Date.now();
    const controller = new AbortController();
    pipelineController = controller;
    pipeline = processPipeline(pool, config, request, controller.signal, () => {
      if (pipelineController === controller) pipelineStartedAt = Date.now();
    })
      .then((result) => {
        verboseLog('pipeline.completed', { processed: result });
        return result;
      })
      .catch(report('pipeline'))
      .finally(() => {
        if (pipelineController === controller) {
          pipeline = null;
          pipelineController = undefined;
        }
      });
  }
  if (outbox && Date.now() - outboxStartedAt > STUCK_PROMISE_MS) {
    void report('outbox')(new Error('Previous outbox promise is still running; starting a fresh attempt'));
    outboxGeneration++;
    outbox = null;
  }
  if (!outbox) {
    outboxStartedAt = Date.now();
    const generation = ++outboxGeneration;
    outbox = (async () => {
      for (let i = 0; i < 20 && !stopping; i++) {
        const delivered = await deliverNext(pool, config, request, sendMail);
        if (!delivered) break;
        verboseLog('outbox.delivered');
      }
    })()
      .catch(report('outbox'))
      .finally(() => {
        if (outboxGeneration === generation) outbox = null;
      });
  }
  // An in-flight promise must never become a reason to stop running. Both jobs
  // below guard against overlapping with themselves; if such a promise never
  // settles (for example a statement stuck beyond its timeout on a wedged
  // connection), the `.finally` that clears it never runs and the job is
  // skipped for the rest of the process lifetime. Clearing a guard that has been
  // held far longer than any legal operation lets the next tick start a fresh
  // attempt, which is what "always keep running" requires.
  if (digest && Date.now() - digestStartedAt > STUCK_PROMISE_MS) {
    void report('digest')(new Error('Previous digest flush is still running; starting a new attempt'));
    digestGeneration++;
    digest = null;
  }
  if (!digest) {
    digestStartedAt = Date.now();
    const generation = ++digestGeneration;
    digest = flushDueDigest(pool)
      .then((count) => {
        verboseLog('digest.flushed', { count });
        return count;
      })
      .catch(report('digest'))
.finally(() => {
        if (digestGeneration === generation) digest = null;
      });
  }
  // Self-healing auto-recovery check - runs on every worker tick.
  // Monitors pipeline, feeds, and scheduler; triggers recovery and sends
  // immediate alerts to the Security team group when issues are found.
  // Self-healing auto-recovery check — runs on every worker tick. Monitors the
  // pipeline, feeds, system health and scheduler; recovers from degraded states
  // and queues an alert through the durable outbox for the Security team.
  // Guarded against overlap: a slow check would otherwise pile a new promise on
  // every 5 s tick until the pool is exhausted.
  if (!selfHealRunning) {
    selfHealRunning = runSelfHealCheck(pool)
      .catch((err) => {
        verboseLog('selfHeal.check_failed', { error: err instanceof Error ? err.message : String(err) });
      })
      .finally(() => {
        selfHealRunning = null;
      });
  }
};
const WORKER_TICK_MS = Number(process.env.WORKER_TICK_MS ?? 5000);
const timer = setInterval(tick, WORKER_TICK_MS);
tick();
// Retention runs on its own cadence because the policy is operator-configurable
// and can be much slower than the worker tick. The last successful run is
// persisted in the database so replicas do not each schedule the same cleanup,
// and a failed run releases its claim so the next tick can retry immediately.
const RETENTION_SCHEDULE_ID = 'retention-schedule';
/** A retention sweep is abandoned (and its claim released) after this long. */
const RETENTION_RUN_LIMIT_MS = 10 * 60_000;
/** The claim must outlive the run limit, or a second replica steals the claim
 * from a legitimately slow sweep and runs a concurrent cleanup under the same
 * schedule row. It is 2x the run limit so a run that finishes near its deadline
 * is never raced. */
const RETENTION_CLAIM_TTL_MS = 2 * RETENTION_RUN_LIMIT_MS;
async function claimRetention(policy: AppSettings['retentionConfig']): Promise<boolean> {
  return transaction(
    pool,
    async (db) => {
      const row = await db.query("SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE", [
        RETENTION_SCHEDULE_ID,
      ]);
      const data = row.rows[0]?.data ?? {};
      const now = Date.now();
      const lastRun = typeof data.lastRun === 'string' ? Date.parse(data.lastRun) : NaN;
      const claimedAt = typeof data.claimedAt === 'string' ? Date.parse(data.claimedAt) : NaN;
      if (Number.isFinite(lastRun) && now - lastRun < policy.cleanupIntervalMinutes * 60_000) return false;
      if (Number.isFinite(claimedAt) && now - claimedAt < RETENTION_CLAIM_TTL_MS) return false;
      await put(db, 'systemState', RETENTION_SCHEDULE_ID, {
        ...data,
        claimedAt: new Date(now).toISOString(),
      });
      return true;
    },
    undefined,
    // The schedule row may not exist yet; a scoped advisory lock serializes the
    // first claim from multiple replicas before there is a row to lock.
    { locks: ['retention-claim'] },
  );
}
async function releaseRetention(success: boolean, nextRetryAt?: string) {
  await transaction(
    pool,
    async (db) => {
      const row = await db.query("SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE", [
        RETENTION_SCHEDULE_ID,
      ]);
      const data = row.rows[0]?.data ?? {};
      await put(db, 'systemState', RETENTION_SCHEDULE_ID, {
        ...data,
        claimedAt: null,
        lastRun: success ? new Date().toISOString() : (data.lastRun ?? null),
        lastFailedAt: success ? null : new Date().toISOString(),
        nextRetryAt: success ? null : nextRetryAt || new Date(Date.now() + 60_000).toISOString(),
      });
    },
    undefined,
    { locks: ['retention-claim'] },
  );
}
let retentionRunning: Promise<unknown> | null = null;
let retentionStartedAt = 0;
let retentionGeneration = 0;
const retentionTick = () => {
  if (retentionRunning && Date.now() - retentionStartedAt > STUCK_PROMISE_MS) {
    void report('retention')(new Error('Previous retention run is still running; starting a new attempt'));
    retentionGeneration++;
    retentionRunning = null;
  }
  if (stopping || config.WORKER_ENABLED !== 'true' || retentionRunning) return;
  retentionStartedAt = Date.now();
  const generation = ++retentionGeneration;
  retentionRunning = (async () => {
    const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
    const policy = settings.retentionConfig;
    if (!policy?.enabled || !policy.autoCleanup) return;
    const row = await pool.query("SELECT data FROM records WHERE kind='systemState' AND id=$1", [
      RETENTION_SCHEDULE_ID,
    ]);
    const data = row.rows[0]?.data ?? {};
    const now = Date.now();
    // Honor nextRetryAt for failed runs to enable immediate retry.
    if (typeof data.nextRetryAt === 'string' && Date.parse(data.nextRetryAt) > now) return;
    if (!(await claimRetention(policy))) return;
    // Bounded independently of the connection's statement timeout, and the
    // cancellation is delivered to PostgreSQL rather than only abandoning the
    // promise: an abandoned transaction keeps its pool connection until the
    // statement finishes, and a wedged one never does. The claim is released on
    // every failure so another replica (or the next tick here) can retry.
    const controller = new AbortController();
    const timer = setTimeout(
      () =>
        controller.abort(
          new Error(`Retention run exceeded ${RETENTION_RUN_LIMIT_MS}ms; cancellation requested`),
        ),
      RETENTION_RUN_LIMIT_MS,
    );
    timer.unref();
    verboseLog('retention.start');
    try {
      await runRetention(pool, 'system-retention', '', controller.signal);
      await releaseRetention(true);
      verboseLog('retention.completed');
    } catch (error) {
      await releaseRetention(false).catch(() => {});
      throw error;
    } finally {
      clearTimeout(timer);
    }
  })()
    .catch(report('retention'))
    .finally(() => {
      if (retentionGeneration === generation) retentionRunning = null;
    });
};
const retentionTimer = setInterval(retentionTick, 60000);
retentionTick();
// The daily digest is a calendar job (daily summary + health report at the
// configured time/timezone). It is polled on the same cadence as retention and
// self-claims the calendar day, so it needs no separate clock.
let dailyDigestRunning: Promise<unknown> | null = null;
let dailyDigestStartedAt = 0;
let dailyDigestGeneration = 0;
const dailyDigestTick = () => {
  if (dailyDigestRunning && Date.now() - dailyDigestStartedAt > STUCK_PROMISE_MS) {
    void report('dailyDigest')(new Error('Previous daily digest run is still running; starting a new attempt'));
    dailyDigestGeneration++;
    dailyDigestRunning = null;
  }
  if (stopping || config.WORKER_ENABLED !== 'true' || dailyDigestRunning) return;
  dailyDigestStartedAt = Date.now();
  const generation = ++dailyDigestGeneration;
  dailyDigestRunning = (async () => {
    verboseLog('dailyDigest.start');
    await runDailyDigest(pool);
    verboseLog('dailyDigest.completed');
  })()
    .catch(report('dailyDigest'))
    .finally(() => {
      if (dailyDigestGeneration === generation) dailyDigestRunning = null;
    });
};
const ML_TRAINING_INTERVAL_MS = Number(process.env.ML_TRAINING_INTERVAL_MS ?? 60 * 60_000);
const ML_TRAINING_SCHEDULE_ID = 'ml-training-schedule';
let trainingRunning: Promise<unknown> | null = null;
let trainingStartedAt = 0;
let trainingGeneration = 0;
const mlTrainingTick = () => {
  if (stopping || config.WORKER_ENABLED !== 'true') return;
  if (trainingRunning && Date.now() - trainingStartedAt > STUCK_PROMISE_MS) {
    void report('ml.training')(new Error('Previous ML training run is still running; starting a new attempt'));
    trainingGeneration++;
    trainingRunning = null;
  }
  if (trainingRunning) return;
  trainingStartedAt = Date.now();
  const generation = ++trainingGeneration;
  trainingRunning = (async () => {
    const claimToken = randomUUID();
    const claimed = await transaction(
      pool,
      async (db) => {
        const row = await db.query("SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE", [
          ML_TRAINING_SCHEDULE_ID,
        ]);
        const data = row.rows[0]?.data ?? {};
        const now = Date.now();
        const lastRun = typeof data.lastRun === 'string' ? Date.parse(data.lastRun) : NaN;
        if (Number.isFinite(lastRun) && now - lastRun < ML_TRAINING_INTERVAL_MS) return false;
        // The advisory lock also serializes the first claim before its row exists.
        const claimedAt = typeof data.claimedAt === 'string' ? Date.parse(data.claimedAt) : NaN;
        if (Number.isFinite(claimedAt) && now - claimedAt < 2 * STUCK_PROMISE_MS) return false;
        await put(db, 'systemState', ML_TRAINING_SCHEDULE_ID, {
          ...data,
          claimedAt: new Date(now).toISOString(),
          claimToken,
        });
        return true;
      },
      undefined,
      { locks: ['ml-training-claim'] },
    );
    if (!claimed) return;
    verboseLog('ml.training.start');
    const summary = await runScheduledTraining(pool, {
      directory: config.ML_DIRECTORY,
      signingKey: config.ML_SIGNING_KEY,
      ...(config.ML_STORAGE_MODE === 'database' ? { database: pool } : {}),
      lookbackDays: config.ML_LOOKBACK_DAYS,
    }).catch((error) => {
      // Release the claim on failure so the next tick (or another replica) can
      // retry immediately instead of waiting out the claim TTL. A stale run
      // must not clear a newer owner's claim.
      return pool
        .query(
          "UPDATE records SET data=data || jsonb_build_object('claimedAt',NULL,'claimToken',NULL) WHERE kind='systemState' AND id=$1 AND data->>'claimToken'=$2",
          [ML_TRAINING_SCHEDULE_ID, claimToken],
        )
        .catch(() => undefined)
        .then(() => {
          if (error instanceof TrainingAlreadyRunningError) return null;
          throw error;
        });
    });
    if (!summary) return;
    if (summary.summary.saved > 0) {
      await initMlRuntime(pool, mlStorageOptions);
    }
    await pool.query(
      "UPDATE records SET data=jsonb_set(data,'{\"lastRun\"}',to_jsonb(now())) || jsonb_build_object('claimedAt',NULL,'claimToken',NULL) WHERE kind='systemState' AND id=$1 AND data->>'claimToken'=$2",
      [ML_TRAINING_SCHEDULE_ID, claimToken],
    );
    void logMlTrainingResult(pool, summary);
    verboseLog('ml.training.completed', { result: summary.results.map((r) => ({ modelId: r.modelId, status: r.status })) });
  })()
    .catch(report('ml.training'))
    .finally(() => {
      if (trainingGeneration === generation) trainingRunning = null;
    });
};
const dailyDigestTimer = setInterval(dailyDigestTick, 60000);
dailyDigestTick();
const mlTrainingTimer = setInterval(mlTrainingTick, 60000);
mlTrainingTick();
let mlTelemetryRunning: Promise<void> | null = null;
let mlTelemetryPrevious = { time: Date.now(), completed: correlation.supervisor.ingestor.telemetry.completed };
const mlTelemetryTimer = setInterval(() => {
  if (stopping || config.WORKER_ENABLED !== 'true' || mlTelemetryRunning ||
      !shouldSampleMlTelemetry(correlation.pendingDepth, correlation.pendingSampledAt)) return;
  const telemetry = correlation.supervisor.ingestor.telemetry;
  const now = Date.now();
  const metrics = {
    memoryPercent: correlation.supervisor.memoryPercent(),
    activeWorkers: correlation.supervisor.active.size,
    concurrencyLimit: correlation.supervisor.concurrencyLimit,
    latencyMs: telemetry.completed ? telemetry.latencyTotal / telemetry.completed : 0,
    deadLetters: telemetry.deadLetters,
    pendingClaims: Math.max(0, correlation.pendingDepth),
    itemsPerSecond: Math.max(0, telemetry.completed - mlTelemetryPrevious.completed) / Math.max(1, (now - mlTelemetryPrevious.time) / 1000),
    poolWaiting: pool.waitingCount,
  };
  mlTelemetryPrevious = { time: now, completed: telemetry.completed };
  mlTelemetryRunning = writeEvent(pool, {
    category: 'ML', code: 'ml.telemetry.sample', message: 'Observed ML telemetry training sample', context: metrics,
  }).then(() => {
    if (isTelemetryAnomaly(metrics))
      return writeEvent(pool, {
        category: 'ML', level: 'WARNING', code: 'ml.telemetry.anomaly',
        message: 'ML telemetry anomaly detected', context: metrics,
      });
  })
    .catch(report('ml.telemetry'))
    .finally(() => { mlTelemetryRunning = null; });
}, 60000);
const cleanup = setInterval(() => {
  // Session and login-attempt expiry are security invariants, not retained
  // business data. Queue rows and operational events follow the retention
  // policy in runRetention so an operator's configured window stays authoritative.
  void pool
    .query(
      `DELETE FROM sessions WHERE expires_at<now();
       DELETE FROM login_attempts WHERE window_start<now()-interval '1 day';
       DELETE FROM password_reset_tokens WHERE expires_at<now();`,
    )
    .then((result) => {
      verboseLog('session.cleanup', { removed: result?.rowCount ?? 0 });
    })
    .catch(report('session-cleanup'));
}, 60000);
async function shutdown() {
  if (stopping) return;
  stopping = true;
  pipelineController?.abort(new Error('Pipeline cancelled during shutdown'));
  clearInterval(timer);
  clearInterval(retentionTimer);
  clearInterval(dailyDigestTimer);
  clearInterval(mlTrainingTimer);
  clearInterval(mlTelemetryTimer);
  clearInterval(cleanup);
  const deadline = setTimeout(() => process.exit(1), 30000);
  deadline.unref();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await Promise.allSettled(
    [pipeline, outbox, digest, retentionRunning, dailyDigestRunning, trainingRunning, mlTelemetryRunning].filter(Boolean) as Promise<unknown>[],
  );
  await correlation.stop();
  await closePdfRenderer();
  await pool.end();
  clearTimeout(deadline);
}
process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
// Node terminates the process immediately on an unhandled rejection/exception
// with no listener registered. That would skip shutdown() entirely, leaving the
// HTTP server and any in-flight pipeline/outbox work to die mid-transaction
// without the structured event log entry operators rely on to diagnose it.
// PostgreSQL releases the session-level pipeline advisory lock when the
// connection closes, so a crash here is still safe for the next worker to
// recover from; this handler only makes the failure visible and gives
// in-flight work a chance at a clean stop before the process exits.
const fatal = (event: string) => (error: unknown) => {
  correlation.supervisor.ingestor.telemetry.log('CRITICAL', 'process.restart_required');
  report(event)(error);
  // If a graceful SIGTERM/SIGINT shutdown is already under way, let its own
  // 30-second deadline govern the exit instead of racing it with a second,
  // immediate process.exit here.
  if (stopping) return;
  void shutdown().finally(() => process.exit(1));
};
process.on('unhandledRejection', fatal('unhandled-rejection'));
process.on('uncaughtException', fatal('uncaught-exception'));
