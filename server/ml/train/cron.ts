/**
 * Scheduled retraining cron for the ML subsystem.
 *
 * Designed to run as a standalone process (e.g., via a cron job or a
 * background worker). Connects to the database, collects training data,
 * runs the TrainingOrchestrator, and logs the results.
 *
 * Usage:
 *   node --import tsx server/ml/train/cron.ts
 *
 * Or programmatically:
 *   import { runScheduledTraining } from './cron.ts';
 *   await runScheduledTraining(pgPool, { directory: '/var/lib/vulnstream/ml' });
 */
import pg from 'pg';
import { pathToFileURL } from 'node:url';
import { basename, resolve } from 'node:path';
import { schemaLockKey } from '../../db.ts';
import type { Db } from '../../db.ts';
import type { ModelStorageOptions } from '../types.ts';
import { TrainingOrchestrator, type TrainingDataSources, type TrainingSummary } from './orchestrator.ts';
import type { MetricFeatures } from '../models/metricAnomalyDetector.ts';
import type { ThresholdSample } from '../models/autoDispatchThreshold.ts';
import type { DeliveryOutcome } from '../models/deliveryOptimizer.ts';
import type { RemediationFeatures } from '../models/advisoryRemediationHelper.ts';
import type { FindingFeatures } from '../models/reviewRanker.ts';
import type { ExploitRiskFeatures, ExploitRiskLevel } from '../models/exploitRiskModel.ts';
import type { MatchConfidenceFeatures } from '../models/matchConfidenceModel.ts';
import type { FindingImportanceFeatures } from '../models/findingImportanceRanker.ts';
import type { CredibilitySample } from '../models/newsCredibilityWeightModel.ts';
import type { DeliveryErrorFeatures } from '../models/deliveryErrorClassifier.ts';
import type { ZeroDayRateLimitSample } from '../models/zeroDayRateLimitOptimizer.ts';
import type { DigestSelectionFeatures } from '../models/digestFindingSelector.ts';
import type { SeverityTierFeatures, SeverityTier } from '../models/severityTierModel.ts';
import type { FeedRecoverySample } from '../models/feedRecoveryBackoffOptimizer.ts';
import type { AliasConfidenceFeatures } from '../models/aliasConfidenceModel.ts';
import type { EmailCompositionFeatures, PerFindingFeatures } from '../models/advisoryComposer.ts';

const { Pool } = pg;
const TRAINING_LOCK_NAMESPACE = 800004;

export class TrainingAlreadyRunningError extends Error {
  constructor() {
    super('Another process already holds the ML training lock');
    this.name = 'TrainingAlreadyRunningError';
  }
}

/**
 * Collects training data from the database for all ML models.
 *
 * Samples come from persisted application records and delivery jobs within
 * the configured lookback. Models without recorded history receive no samples.
 */
export interface CronTrainingData {
  cpeStrings: string[];
  telemetryHistory: MetricFeatures[];
  dispatchOutcomes: ThresholdSample[];
  reviewOutcomeHistory: Array<{
    features: FindingFeatures;
    statusAfterReview: 'FALSE_POSITIVE' | 'PATCHED' | 'RESOLVED' | 'DELIVERED' | 'EXPIRED';
    daysToAction: number;
  }>;
  calibrationPairs: Array<{ credibilityScore: number; isActionable: boolean }>;
  deliveryOutcomes: DeliveryOutcome[];
  remediationFindings: Array<{
    features: RemediationFeatures;
    playbook: Record<string, unknown>;
  }>;
  exploitRiskSamples: Array<{
    features: ExploitRiskFeatures;
    riskLevel: ExploitRiskLevel;
  }>;
  matchConfidenceSamples: Array<{
    features: MatchConfidenceFeatures;
    isTruePositive: boolean;
  }>;
  importanceRankSamples: Array<{
    features: FindingImportanceFeatures;
    wasActionable: boolean;
    daysToAction: number;
  }>;
  credibilityWeightSamples: CredibilitySample[];
  deliveryErrorSamples: Array<{
    provider: string;
    statusCode: number;
    errorMessage: string;
    attemptNumber: number;
    hourOfDay: number;
    isPermanent: boolean;
  }>;
  zeroDayRateLimitSamples: ZeroDayRateLimitSample[];
  digestSelectionSamples: Array<{
    features: DigestSelectionFeatures;
    isRelevant: boolean;
  }>;
  severityTierSamples: Array<{
    features: SeverityTierFeatures;
    tier: SeverityTier;
  }>;
  feedRecoverySamples: FeedRecoverySample[];
  aliasConfidenceSamples: Array<{
    features: AliasConfidenceFeatures;
    isConfirmed: boolean;
  }>;
  emailCompositionSamples: Array<{
    features: EmailCompositionFeatures;
    perFinding: PerFindingFeatures[];
    summaryStyle: import('../models/advisoryComposer.ts').SummaryStyle;
    priorityEmphasis: import('../models/advisoryComposer.ts').PriorityEmphasis;
    remediationEmphasis: import('../models/advisoryComposer.ts').RemediationEmphasis;
    subjectTemplate: import('../models/advisoryComposer.ts').SubjectTemplate;
    wasActionable: boolean;
  }>;
}

const DEFAULT_LOOKBACK_DAYS = 30;

/**
 * Default data provider — queries the VulnStream database directly.
 *
 * Each query fetches data from the last `lookbackDays` days.
 * Results are mapped to the TrainingSample format expected by the orchestrator.
 */
export { CronDataProvider } from './dataProvider.ts';
import { CronDataProvider } from './dataProvider.ts';

/**
 * Custom data provider function type — allows callers to provide
 * their own data collection logic instead of querying the database.
 */
export type DataCollector = (db: Db) => Promise<TrainingDataSources>;

/**
 * Runs a full scheduled training cycle.
 *
 * 1. Collects training data from the database via the provided data collector
 * 2. Trains all models via TrainingOrchestrator
 * 3. Returns a summary with per-model results
 *
 * Throws only if the database query fails — model training failures are
 * captured in the summary (status: 'failed'), not thrown.
 */
export async function runScheduledTraining(
  pool: pg.Pool,
  options: ModelStorageOptions & {
    lookbackDays?: number;
    dataCollector?: DataCollector;
  },
): Promise<TrainingSummary> {
  const lookbackDays = options.lookbackDays ?? DEFAULT_LOOKBACK_DAYS;
  const dataCollector = options.dataCollector ?? ((db) => new CronDataProvider(lookbackDays).collectAll(db));

  const client = await pool.connect();
  let lockAcquired = false;
  let releaseWithError = false;
  const onConnectionError = () => {
    releaseWithError = true;
  };
  client.on('error', onConnectionError);
  try {
    let lockResult;
    try {
      lockResult = await client.query<{ locked: boolean }>(
        `SELECT pg_try_advisory_lock(${TRAINING_LOCK_NAMESPACE}, ${schemaLockKey}) AS locked`,
      );
    } catch (error) {
      releaseWithError = true;
      throw error;
    }
    if (lockResult.rows[0]?.locked !== true) throw new TrainingAlreadyRunningError();
    lockAcquired = true;

    const data = await dataCollector(client);
    const orchestrator = new TrainingOrchestrator({
      directory: options.directory,
      signingKey: options.signingKey,
      database: options.database,
    });
    const summary = await orchestrator.trainAll(data);

    // Log summary
    console.log(
      `[ML Training] ${summary.timestamp} — ${summary.summary.trained}/${summary.summary.total} models trained, ${summary.summary.saved} saved, ${summary.summary.failed} failed`,
    );

    for (const result of summary.results) {
      const status = result.status === 'trained' ? '✔' : result.status === 'skipped' ? '⊘' : '✗';
      const saved = result.saved ? ' saved' : '';
      console.log(
        `  ${status} ${result.modelId}: ${result.samplesCollected} samples → ${result.validation.passed ? 'passed gate' : `failed: ${result.validation.failureReason ?? 'unknown'}`}${saved}`,
      );
    }

    return summary;
  } finally {
    if (lockAcquired) {
      try {
        const result = await client.query<{ unlocked: boolean }>(
          `SELECT pg_advisory_unlock(${TRAINING_LOCK_NAMESPACE}, ${schemaLockKey}) AS unlocked`,
        );
        if (result.rows[0]?.unlocked !== true) releaseWithError = true;
      } catch {
        releaseWithError = true;
      }
    }
    client.removeListener('error', onConnectionError);
    client.release(releaseWithError);
  }
}

/**
 * CLI entry point — runs scheduled training with a database pool.
 * Exits with code 1 if any model fails to train or fails its quality gate.
 */
export async function main(): Promise<void> {
  const connectionString = process.env.DATABASE_URL ?? process.env.PG_CONNECTION_STRING;
  const mlDir = process.env.ML_DIRECTORY ?? '/var/lib/vulnstream/ml';
  const lookbackDays = process.env.ML_LOOKBACK_DAYS
    ? parseInt(process.env.ML_LOOKBACK_DAYS, 10)
    : DEFAULT_LOOKBACK_DAYS;

  if (!connectionString) {
    console.error('ERROR: DATABASE_URL or PG_CONNECTION_STRING environment variable is required');
    process.exit(1);
  }

  const pool = new Pool({ connectionString });

  try {
    const summary = await runScheduledTraining(pool, {
      directory: mlDir,
      signingKey: process.env.ML_SIGNING_KEY,
      ...(process.env.ML_STORAGE_MODE === 'database' ? { database: pool } : {}),
      lookbackDays,
    });

    const failed = summary.results.filter((r) => r.status === 'failed');
    if (failed.length > 0) {
      console.error(`ERROR: ${failed.length} model(s) failed training:`);
      for (const f of failed) {
        console.error(`  - ${f.modelId}: ${f.error ?? f.validation.failureReason ?? 'unknown'}`);
      }
      process.exit(1);
    }

    console.log('Training complete.');
  } finally {
    await pool.end();
  }
}

// Run as CLI when executed directly
export function isCronCliEntrypoint(moduleUrl: string, entrypoint: string | undefined): boolean {
  return Boolean(
    entrypoint && /^cron\.(?:[cm]?js|tsx?)$/i.test(basename(entrypoint)) &&
    moduleUrl === pathToFileURL(resolve(entrypoint)).href,
  );
}

if (isCronCliEntrypoint(import.meta.url, process.argv[1])) {
  void main().catch((error) => { console.error('ML training failed:', error); process.exitCode = 1; });
}
