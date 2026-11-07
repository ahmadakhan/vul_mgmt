import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import os from 'node:os';
import fs from 'node:fs';

import { initMlRuntime, getMlRuntime, cpePreFilter, calibrateCredibilityScore, shouldAutoDispatch, rankReviewFindings, isTelemetryAnomaly, shouldSampleMlTelemetry, computeRetryDelay, predictRemediation } from '../server/ml/integration.ts';
import type { TrainingDataSources } from '../server/ml/train/orchestrator.ts';
import { TrainingOrchestrator } from '../server/ml/train/orchestrator.ts';
import type { MetricFeatures } from '../server/ml/models/metricAnomalyDetector.ts';
import type { RemediationFeatures } from '../server/ml/models/advisoryRemediationHelper.ts';
import type { ThresholdSample } from '../server/ml/models/autoDispatchThreshold.ts';
import type { Finding } from '../src/types/index.ts';
import type { Db } from '../server/db.ts';

const tmpDir = () => join(os.tmpdir(), `ml-int-test-${Math.random().toString(36).slice(2)}`);
const mockDb: Db = { query: async () => ({ rows: [] }) } as unknown as Db;

describe('ML pipeline integration', () => {
  describe('runtime initialization', () => {
    it('getMlRuntime returns null before init', () => {
      assert.equal(getMlRuntime(), null);
    });

    it('initMlRuntime creates and caches runtime', async () => {
      const dir = tmpDir();
      const runtime = await initMlRuntime(mockDb, { directory: dir });
      assert.ok(runtime);
      assert.equal(getMlRuntime(), runtime);
      fs.rmSync(dir, { recursive: true, force: true });
    });
  });

  describe('cpePreFilter', () => {
    it('returns true for untrained model (always parse)', () => {
      assert.equal(cpePreFilter('garbage-not-cpe'), true);
      assert.equal(cpePreFilter('cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*'), true);
    });
  });

  describe('calibrateCredibilityScore', () => {
    it('returns raw score when untrained', () => {
      const result = calibrateCredibilityScore(75);
      assert.equal(result.score, 75);
      assert.equal(result.probability, 0.75);
      assert.equal(calibrateCredibilityScore(0).score, 0);
      assert.equal(calibrateCredibilityScore(100).score, 100);
      assert.equal(result.confidence, 'LOW');
    });

    it('calibrates score when trained', async () => {
      const dir = tmpDir();
      const orch = new TrainingOrchestrator({ directory: dir });

      const calibrationPairs = [];
      for (let i = 0; i < 200; i++) {
        const score = 5 + (i % 95);
        calibrationPairs.push({ credibilityScore: score, isActionable: score >= 50 });
      }

      await orch.trainAll({ calibrationPairs });
      await initMlRuntime(mockDb, { directory: dir });

      const result = calibrateCredibilityScore(80);
      assert.ok(result.probability >= 0.7, `Expected probability >= 0.7, got ${result.probability}`);
      assert.equal(result.score, result.probability * 100);
      assert.equal(calibrateCredibilityScore(0).score, 0);
      assert.equal(calibrateCredibilityScore(100).score, 100);
      assert.equal(result.confidence !== 'LOW', true);

      fs.rmSync(dir, { recursive: true, force: true });
    });
  });

  describe('shouldAutoDispatch', () => {
    it('uses 90 threshold when untrained', () => {
      assert.equal(shouldAutoDispatch(91, { autoDispatchConfidenceThreshold: 90 }), true);
      assert.equal(shouldAutoDispatch(89, { autoDispatchConfidenceThreshold: 90 }), false);
    });

    it('respects settings threshold when untrained', () => {
      assert.equal(shouldAutoDispatch(85, { autoDispatchConfidenceThreshold: 50 }), true);
      assert.equal(shouldAutoDispatch(49, { autoDispatchConfidenceThreshold: 50 }), false);
    });
    it('a trained model cannot override the configured threshold', (t) => {
      const model = getMlRuntime()?.autoDispatchThreshold;
      assert.ok(model);
      let recommendation = 10;
      t.mock.method(model, 'isTrained', () => true);
      t.mock.method(model, 'getThreshold', () => recommendation);
      assert.equal(shouldAutoDispatch(80, { autoDispatchConfidenceThreshold: 90 }), false);
      recommendation = 99;
      assert.equal(shouldAutoDispatch(80, { autoDispatchConfidenceThreshold: 70 }), true);
      assert.equal(shouldAutoDispatch(70, { autoDispatchConfidenceThreshold: 70 }), true);
      for (const confidence of [NaN, Infinity, -1, 101])
        assert.equal(shouldAutoDispatch(confidence, { autoDispatchConfidenceThreshold: 0 }), false);
    });
  });

  describe('rankReviewFindings', () => {
    it('falls back to confidence sort when untrained', () => {
      const findings: Finding[] = [
        { id: 'f1', cveId: 'CVE-2024-1', cve: {} as never, confidence: 60, matchedAssetId: '', matchedAssetName: '', matchedCpe: '', matchingMethod: 'STRICT_CPE', matchingEvidence: '', exposure: 'INTERNAL', exploitRisk: 'NONE', notificationStatus: 'QUEUED_FOR_DISPATCH', status: 'MONITORED', autoDispatchedAt: null, advisoryId: null, reviewNotifiedAt: null, timeline: [] } as unknown as Finding,
        { id: 'f2', cveId: 'CVE-2024-2', cve: {} as never, confidence: 90, matchedAssetId: '', matchedAssetName: '', matchedCpe: '', matchingMethod: 'STRICT_CPE', matchingEvidence: '', exposure: 'INTERNAL', exploitRisk: 'NONE', notificationStatus: 'QUEUED_FOR_DISPATCH', status: 'MONITORED', autoDispatchedAt: null, advisoryId: null, reviewNotifiedAt: null, timeline: [] } as unknown as Finding,
      ];

      const ranked = rankReviewFindings(findings);
      assert.equal(ranked[0].id, 'f2');
      assert.equal(ranked[1].id, 'f1');
    });
  });

  describe('isTelemetryAnomaly', () => {
    it('returns false when untrained', () => {
      const metrics: MetricFeatures = {
        memoryPercent: 50,
        activeWorkers: 4,
        concurrencyLimit: 10,
        latencyMs: 100,
        deadLetters: 0,
        pendingClaims: 5,
        itemsPerSecond: 100,
        poolWaiting: 2,
      };
      assert.equal(isTelemetryAnomaly(metrics), false);
    });
  });

  describe('shouldSampleMlTelemetry', () => {
    it('samples once before pending depth has ever been refreshed', () => {
      assert.equal(shouldSampleMlTelemetry(-1, 0), true);
      assert.equal(shouldSampleMlTelemetry(-1, 1), false);
      assert.equal(shouldSampleMlTelemetry(0, 1), true);
    });
  });

  it('does not persist per-prediction informational events', async () => {
    const dir = tmpDir();
    let queries = 0;
    const pool = {
      query: async () => {
        queries++;
        return { rows: [] };
      },
    } as unknown as Db;
    try {
      await initMlRuntime(pool, { directory: dir });
      const initializationQueries = queries;
      calibrateCredibilityScore(75);
      computeRetryDelay(1);
      assert.equal(queries, initializationQueries);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  describe('computeRetryDelay', () => {
    it('uses default exponential backoff when untrained', () => {
      const delay1 = computeRetryDelay(1);
      const delay2 = computeRetryDelay(2);
      assert.equal(delay1, 300_000); // 5 minutes
      assert.equal(delay2, 600_000); // 10 minutes (5 * 2^1)
    });

    it('capped at max delay', () => {
      const delay = computeRetryDelay(100);
      assert.ok(delay <= 1440 * 60_000, `delay ${delay} exceeds max ${1440 * 60_000}`);
    });
  });

  describe('predictRemediation', () => {
    it('returns rule-based defaults when untrained', () => {
      const features: RemediationFeatures = {
        cvssScore: 8,
        epssScore: 0.7,
        cisaKev: true,
        daysSincePublished: 5,
        sourceFeedWeight: 30,
        hasVersionEvidence: true,
        cweRiskLevel: 2,
        exploitStatus: 3,
      };

      const result = predictRemediation(features);
      assert.equal(result.vendorAdvisory, 0.8);
      assert.equal(result.immediateActions, 0.7);
      assert.equal(result.stepByStep, 0.7);
      assert.ok(['complete', 'partial', 'sparse'].includes(result.recommendation));
    });

    it('generates fallback content for missing playbook fields', () => {
      const features: RemediationFeatures = {
        cvssScore: 3,
        epssScore: 0.1,
        cisaKev: false,
        daysSincePublished: 60,
        sourceFeedWeight: 10,
        hasVersionEvidence: false,
        cweRiskLevel: 0,
        exploitStatus: 0,
      };

      const result = predictRemediation(features);
      assert.ok(result.generatedContent);
    });
  });

  describe('full training pipeline with integration', () => {
    it('trains all models and integration functions use trained state', async () => {
      const dir = tmpDir();
      const orch = new TrainingOrchestrator({ directory: dir });

      const cpeStrings = [
        ...Array.from({ length: 100 }, (_, i) => `cpe:2.3:a:vendor${i}:product${i}:1.0:*:*:*:*:*:*:*`),
        ...Array.from({ length: 100 }, (_, i) => `garbage-${i}`),
      ];
      const calibrationPairs = [];
      for (let i = 0; i < 200; i++) {
        const score = 5 + (i % 95);
        calibrationPairs.push({ credibilityScore: score, isActionable: score >= 50 });
      }
      const dispatchOutcomes: ThresholdSample[] = [];
      for (let i = 0; i < 200; i++) {
        const confidence = 50 + (i % 50);
        const dispatched = confidence >= 80;
        const isFalsePositive = dispatched && i % 10 === 0;
        dispatchOutcomes.push({
          confidence,
          dispatched,
          wasFalsePositive: isFalsePositive,
          foundTruePositive: dispatched && !isFalsePositive,
        });
      }
      const telemetryHistory: MetricFeatures[] = [];
      for (let i = 0; i < 200; i++) {
        telemetryHistory.push({
          memoryPercent: 35 + (Math.random() * 20),
          activeWorkers: 3 + Math.floor(Math.random() * 3),
          concurrencyLimit: 10,
          latencyMs: 40 + Math.random() * 30,
          deadLetters: Math.random() < 0.05 ? 1 : 0,
          pendingClaims: Math.floor(Math.random() * 5),
          itemsPerSecond: 90 + Math.random() * 30,
          poolWaiting: Math.floor(Math.random() * 3),
        });
      }

      const data: TrainingDataSources = {
        cpeStrings,
        calibrationPairs,
        dispatchOutcomes,
        telemetryHistory,
      };

      await orch.trainAll(data);
      await initMlRuntime(mockDb, { directory: dir });

      // CPE filter should now work for trained model
      const validCpe = cpePreFilter('cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*');
      assert.equal(validCpe, true);

      // Trained recommendations must not replace the configured dispatch policy.
      const dispatchResult = shouldAutoDispatch(95, { autoDispatchConfidenceThreshold: 90 });
      assert.ok(typeof dispatchResult === 'boolean');

      // Retry delay should use learned policy
      const delay = computeRetryDelay(3);
      assert.ok(typeof delay === 'number');
      assert.ok(delay > 0);

      // Telemetry anomaly should work
      const anomaly = isTelemetryAnomaly(telemetryHistory[0]);
      assert.equal(typeof anomaly, 'boolean');

      fs.rmSync(dir, { recursive: true, force: true });
    });
  });
});
