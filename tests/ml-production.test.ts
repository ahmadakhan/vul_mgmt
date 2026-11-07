import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mlFeedbackSchema, appendMlFeedback } from '../server/ml/feedback.ts';
import { assessFinding, assessFindings } from '../server/ml/assessment.ts';
import { findingFeatures } from '../server/ml/findingFeatures.ts';
import { initMlRuntime } from '../server/ml/integration.ts';
import { ZeroDayRateLimitOptimizer } from '../server/ml/models/zeroDayRateLimitOptimizer.ts';
import { TrainingOrchestrator, type TrainingDataSources } from '../server/ml/train/orchestrator.ts';
import { CronDataProvider } from '../server/ml/train/dataProvider.ts';
import type { Db } from '../server/db.ts';
import { INITIAL_FINDINGS } from './fixtures/seedData.ts';

const db = { query: async () => ({ rows: [] }) } as unknown as Db;
const risk = { cvssScore: 8, epssScore: 0.6, cisaKev: true, exploitStatus: 'Reported In Wild',
  daysSincePublished: 5 };
const samples = [
  { source: 'calibrationPairs', sample: { credibilityScore: 80, isActionable: true } },
  { source: 'exploitRiskSamples', sample: { features: { ...risk, exploitationSourcesCount: 1 }, riskLevel: 'REPORTED_IN_WILD_EXPLOIT' } },
  { source: 'severityTierSamples', sample: { features: { ...risk, cweRiskLevel: 0, sourceFeedWeight: 20 }, tier: 'HIGH' } },
  { source: 'digestSelectionSamples', sample: { features: {
    cvssScore: 8, epssScore: 0.6, cisaKev: true, exploitStatus: 2, daysSincePublished: 5,
    sourceFeedWeight: 20, credibilityScore: 80, assetCriticality: 0, recipientTier: 'ALL',
    findingInDigest: true, timeInDigestMinutes: 10,
  }, isRelevant: true } },
  { source: 'zeroDayRateLimitSamples', sample: {
    zeroDayCount: 2, credibilityScores: [80, 10], outcomes: ['PATCHED', 'FALSE_POSITIVE'],
  } },
  { source: 'emailCompositionSamples', sample: {
    features: {
      criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0, unknownCount: 0,
      totalFindings: 1, maxCvssScore: 8, avgCvssScore: 8, maxEpssScore: 0.6, avgEpssScore: 0.6,
      kevCount: 1, weaponizedCount: 0, reportedInWildCount: 1, pocCount: 0,
      affectedAssetCount: 1, uniqueVendorCount: 1, avgMatchConfidence: 90,
      avgDaysSincePublished: 5, avgSourceFeedWeight: 20,
    }, perFinding: [{ ...risk, matchConfidence: 90, sourceFeedWeight: 20, assetCriticality: 0 }],
    summaryStyle: 'URGENT', priorityEmphasis: 'REVIEW', remediationEmphasis: 'VENDOR_GUIDANCE_FIRST',
    subjectTemplate: 'Vulnerability notice: {count} {sev}', wasActionable: true,
  } },
];

test('all formerly missing analyst label sources accept validated feedback and reject invented outcomes', () => {
  const data: TrainingDataSources = {};
  for (const sample of samples) appendMlFeedback(data, sample);
  assert.equal(Object.keys(data).length, 6);
  assert.ok(Object.values(data).every((rows) => rows.length === 1));
  assert.throws(() => mlFeedbackSchema.parse({ source: 'calibrationPairs', sample: { credibilityScore: 101, isActionable: true } }));
  assert.throws(() => mlFeedbackSchema.parse({ source: 'calibrationPairs', sample: { credibilityScore: 50, isActionable: 'yes' } }));
  assert.throws(() => mlFeedbackSchema.parse({ source: 'zeroDayRateLimitSamples', sample: {
    zeroDayCount: 2, credibilityScores: [90], outcomes: ['DELIVERED'],
  } }));
  assert.throws(() => mlFeedbackSchema.parse({ source: 'severityTierSamples', sample: { features: risk, tier: 'MADE_UP' } }));
});

test('zero-day feedback accepts every modeled outcome and skips legacy unpaired labels', () => {
  const data: TrainingDataSources = {};
  const outcomes = ['TIDY', 'PATCHED', 'RESOLVED', 'DELIVERED', 'FALSE_POSITIVE'] as const;
  for (let index = 0; index < 20; index++) {
    const outcome = outcomes[index % outcomes.length];
    appendMlFeedback(data, {
      source: 'zeroDayRateLimitSamples',
      sample: { zeroDayCount: 1, credibilityScores: [50], outcomes: [outcome] },
    });
  }
  assert.equal(data.zeroDayRateLimitSamples?.length, 20);
  const model = new ZeroDayRateLimitOptimizer();
  model.train(data.zeroDayRateLimitSamples);
  assert.equal(model.getDecisionPoints()[0].keptTruePositiveRate, 0.6);
  assert.throws(() => mlFeedbackSchema.parse({
    source: 'zeroDayRateLimitSamples',
    sample: { zeroDayCount: 1, credibilityScores: [50], keptOutcomes: ['PATCHED'], droppedOutcomes: [] },
  }));
  appendMlFeedback(data, {
    source: 'zeroDayRateLimitSamples',
    sample: { zeroDayCount: 1, credibilityScores: [50], keptOutcomes: ['PATCHED'], droppedOutcomes: [] },
  });
  assert.equal(data.zeroDayRateLimitSamples?.length, 20);
});

test('training collectors read observed telemetry, delivery and every analyst label from persisted events', async () => {
  const telemetry = { memoryPercent: 40, activeWorkers: 1, concurrencyLimit: 4, latencyMs: 20,
    deadLetters: 0, pendingClaims: 1, itemsPerSecond: 2, poolWaiting: 0 };
  const delivery = { provider: 'SMTP', attempt: 2, delayMs: 300000, succeeded: true,
    isRateLimited: false, isPermanentFailure: false };
  const error = { provider: 'SMTP', statusCode: 0, errorMessage: 'Observed SMTP failure',
    attemptNumber: 1, hourOfDay: 12, isPermanent: true };
  const observed = {
    query: async (sql: string, params: unknown[] = []) => {
      if (sql.includes('code=$1')) {
        const contexts = params[0] === 'ml.telemetry.sample' ? [telemetry]
          : params[0] === 'ml.delivery.outcome' ? [delivery, { ...delivery, delayObserved: false }]
            : params[0] === 'ml.delivery.error' ? [error]
            : params[0] === 'ml.training.feedback' ? samples : [];
        return { rows: contexts.map((context) => ({ context })) };
      }
      return { rows: [] };
    },
  } as unknown as Db;
  const data = await new CronDataProvider().collectAll(observed);
  assert.equal(Object.keys(data).length, 18);
  assert.deepEqual(data.telemetryHistory, [telemetry]);
  assert.deepEqual(data.deliveryOutcomes, [delivery]);
  assert.deepEqual(data.deliveryErrorSamples, [error]);
  for (const sample of samples) assert.equal(data[sample.source as keyof TrainingDataSources]?.length, 1);
  const broken = { query: async () => { throw new Error('Database unavailable'); } } as unknown as Db;
  await assert.rejects(new CronDataProvider().collectTelemetry(broken), /Database unavailable/);
  await assert.rejects(new CronDataProvider().collectFeedRecoverySamples(broken), /Database unavailable/);
});

test('trained finding models produce recommendations without changing authoritative delivery decisions', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ml-production-assessment-'));
  try {
    const runtime = await initMlRuntime(db, { directory });
    t.mock.method(runtime.matchConfidence, 'isTrained', () => true);
    t.mock.method(runtime.matchConfidence, 'predictConfidence', () => 99);
    t.mock.method(runtime.cpeValidityGate, 'isTrained', () => true);
    t.mock.method(runtime.cpeValidityGate, 'shouldParse', () => false);
    t.mock.method(runtime.aliasConfidence, 'isTrained', () => true);
    t.mock.method(runtime.aliasConfidence, 'predictConfirmationProbability', () => 1);
    const original = { ...structuredClone(INITIAL_FINDINGS[0]), confidence: 0,
      notificationStatus: 'REVIEW_REQUIRED' as const };
    const result = assessFinding(original);
    assert.equal(result.mlAssessment?.matchConfidence, 99);
    assert.equal(result.mlAssessment?.cpeParseRecommended, false);
    assert.equal(result.confidence, 0);
    assert.equal(result.notificationStatus, 'REVIEW_REQUIRED');
    assert.equal(result.exploitRisk, original.exploitRisk);
    assert.deepEqual(result.cve, original.cve);
    assert.equal(original.mlAssessment, undefined);
    original.cve.exploitStatus = 'Reported In Wild';
    original.matchedCpe = 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*';
    const alias = t.mock.method(runtime.aliasConfidence, 'predictConfirmationProbability', () => 1);
    t.mock.method(runtime.reviewRanker, 'isTrained', () => true);
    const rank = t.mock.method(runtime.reviewRanker, 'predictBatch', () => [{ score: 0.8, probability: 0.8 }]);
    assessFindings([original]);
    const features = findingFeatures(original);
    const aliasFeatures = alias.mock.calls[0]?.arguments[0];
    const rankFeatures = rank.mock.calls[0]?.arguments[0]?.[0];
    assert.ok(aliasFeatures);
    assert.ok(rankFeatures);
    assert.equal(aliasFeatures.exploitStatus, features.exploitStatus);
    assert.equal(features.exploitStatus, 1);
    assert.equal(rankFeatures.has_version_evidence, 1);
    assert.equal(rankFeatures.exploit_status, features.exploitStatus);
    const sourceFinding = {
      ...original,
      cve: { ...original.cve, sourceFeeds: ['nvd-source', 'kev-source'] },
    };
    const feedTypesById = new Map([
      ['nvd-source', 'NVD_API'],
      ['kev-source', 'CISA_KEV'],
    ] as const);
    assert.equal(findingFeatures(sourceFinding, feedTypesById).sourceFeedWeight, 40);
    assessFindings([sourceFinding], feedTypesById);
    const sourceRankFeatures = rank.mock.calls[rank.mock.calls.length - 1]?.arguments[0]?.[0];
    assert.equal(sourceRankFeatures?.source_feed_weight, 40);
    assert.equal(findingFeatures({ ...sourceFinding, cve: { ...sourceFinding.cve, sourceFeeds: ['kev-source'] } }, feedTypesById).sourceFeedWeight, 10);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('feed recovery training records failed probes and only verified recovery transitions', async () => {
  const observed = {
    query: async () => ({ rows: [
      { occurred_at: '2026-11-01T10:00:00Z', context: { feedId: 'feed', healthStatus: 'DOWN', consecutiveFailures: 1 } },
      { occurred_at: '2026-11-01T10:05:00Z', context: { feedId: 'feed', healthStatus: 'DOWN', consecutiveFailures: 2 } },
      { occurred_at: '2026-11-01T10:10:00Z', context: { feedId: 'feed', healthStatus: 'DEGRADED', consecutiveFailures: 3 } },
      { occurred_at: '2026-11-01T10:15:00Z', context: { feedId: 'feed', healthStatus: 'DEGRADED', consecutiveFailures: 0 } },
      { occurred_at: '2026-11-01T10:20:00Z', context: { feedId: 'feed', healthStatus: 'HEALTHY', consecutiveFailures: 0 } },
    ] }),
  } as unknown as Db;
  const samples = await new CronDataProvider().collectFeedRecoverySamples(observed);
  assert.deepEqual(samples.map((sample) => sample.recovered), [false, false, true]);
  assert.deepEqual(samples.map((sample) => sample.failureCount), [1, 2, 3]);
  assert.deepEqual(samples.map((sample) => sample.delayMinutes), [5, 5, 5]);
});

test('signed retraining retains rollback versions and refreshes the runtime reference used by callers', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ml-production-refresh-'));
  const storage = { directory, signingKey: 'test-only-ml-signing-key' };
  try {
    const reference = await initMlRuntime(db, storage);
    const cpeStrings = Array.from({ length: 200 }, (_, i) =>
      i % 2 ? `cpe:2.3:a:vendor${i}:product${i}:1.0:*:*:*:*:*:*:*` : `invalid-${i}`);
    for (let i = 0; i < 2; i++) {
      const result = await new TrainingOrchestrator(storage).trainAll({ cpeStrings });
      assert.equal(result.results.find((r) => r.modelId === 'cpe-validity-gate')?.saved, true);
    }
    const refreshed = await initMlRuntime(db, storage);
    assert.equal(refreshed, reference);
    assert.equal(reference.cpeValidityGate.isTrained(), true);
    const manifest = JSON.parse(await readFile(join(directory, 'model-manifest.json'), 'utf8'));
    const history = manifest['cpe-validity-gate'].artifacts;
    assert.equal(history.length, 2);
    assert.notEqual(history[0].version, history[1].version);
    assert.equal(reference.registry.get('cpe-validity-gate')?.metadata.version, manifest['cpe-validity-gate'].activeVersion);
    for (const entry of history) {
      const artifact = JSON.parse(await readFile(join(directory, entry.path), 'utf8'));
      assert.equal(typeof artifact.signature, 'string');
      assert.equal(artifact.metadata.version, entry.version);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
