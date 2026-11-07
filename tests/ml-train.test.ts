import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';

import {
  TrainingOrchestrator,
  type TrainingDataSources,
} from '../server/ml/train/orchestrator.ts';
import { QUALITY_GATES, toModelSelfValidation } from '../server/ml/train/qualityGates.ts';
import { computePsi, detectConceptDrift, shouldRetrain } from '../server/ml/train/driftDetection.ts';
import { evaluateClassifier, computeEce, splitData, toLabel } from '../server/ml/train/evaluation.ts';
import { CpeValidityGateModel } from '../server/ml/models/cpeValidityGate.ts';
import { type MetricFeatures } from '../server/ml/models/metricAnomalyDetector.ts';
import type { TrainingSample } from '../server/ml/types.ts';
import fs from 'node:fs';
import os from 'node:os';

const tmpDir = () => join(os.tmpdir(), `ml-train-test-${Math.random().toString(36).slice(2)}`);

describe('evaluation utilities', () => {
  it('evaluateClassifier computes correct metrics for perfect predictions', () => {
    const samples: TrainingSample[] = [
      { id: '1', features: { x: 1 }, label: 1, timestamp: '2025-01-01' },
      { id: '2', features: { x: 0 }, label: 0, timestamp: '2025-01-01' },
      { id: '3', features: { x: 1 }, label: 1, timestamp: '2025-01-01' },
      { id: '4', features: { x: 0 }, label: 0, timestamp: '2025-01-01' },
    ];
    const predict = (f: Record<string, number>) =>
      f.x >= 0.5
        ? { score: 1, probability: 1, confidence: 'HIGH' as const, reason: 'x>=0.5' }
        : { score: 0, probability: 0, confidence: 'HIGH' as const, reason: 'x<0.5' };

    const metrics = evaluateClassifier(samples, predict);
    assert.equal(metrics.accuracy, 1);
    assert.equal(metrics.precision, 1);
    assert.equal(metrics.recall, 1);
    assert.equal(metrics.f1, 1);
    assert.equal(metrics.aucRoc, 1);
    assert.equal(metrics.tP, 2);
    assert.equal(metrics.tN, 2);
  });

  it('evaluateClassifier handles empty input', () => {
    const metrics = evaluateClassifier([], () => ({ score: 0.5, confidence: 'LOW', reason: 'empty' }));
    assert.equal(metrics.accuracy, 0);
    assert.equal(metrics.aucRoc, 0.5);
  });

  it('splitData produces reproducible splits with same seed', () => {
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({ id: `s${i}`, features: { x: i }, label: i % 2, timestamp: '2025-01-01' });
    }

    const [train1, test1] = splitData(samples, 0.2, 42);
    const [train2, test2] = splitData(samples, 0.2, 42);

    assert.equal(train1.length, train2.length);
    assert.equal(test1.length, test2.length);
    assert.deepEqual(train1.map((s) => s.id), train2.map((s) => s.id));
  });

  it('splitData different seeds produce different splits', () => {
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({ id: `s${i}`, features: { x: i }, label: i % 2, timestamp: '2025-01-01' });
    }

    const [train1] = splitData(samples, 0.2, 42);
    const [train2] = splitData(samples, 0.2, 99);

    const ids1 = train1.map((s) => s.id).sort();
    const ids2 = train2.map((s) => s.id).sort();
    assert.notDeepEqual(ids1, ids2);
  });

  it('computeEce returns 0 for perfectly calibrated predictions', () => {
    const predictions = [];
    for (let i = 0; i < 10; i++) {
      predictions.push({ prob: 0.5, label: i < 5 ? 1 : 0 });
    }
    const ece = computeEce(predictions, 10);
    assert.ok(ece.ece < 0.1, `ECE should be near 0 for calibrated predictions, got ${ece.ece}`);
  });

  it('computeEce detects miscalibration', () => {
    const predictions = [
      { prob: 0.9, label: 0 },
      { prob: 0.9, label: 0 },
      { prob: 0.9, label: 0 },
      { prob: 0.1, label: 1 },
      { prob: 0.1, label: 1 },
    ];
    const ece = computeEce(predictions, 5);
    assert.ok(ece.ece > 0.3, `ECE should be high for miscalibrated predictions, got ${ece.ece}`);
  });

  it('toLabel converts boolean and numeric labels', () => {
    assert.equal(toLabel(true), 1);
    assert.equal(toLabel(false), 0);
    assert.equal(toLabel(1), 1);
    assert.equal(toLabel(0), 0);
    assert.equal(toLabel(0.5), 0.5);
  });
});

describe('quality gates', () => {
  it('QUALITY_GATES has an entry for all 18 models', () => {
    assert.ok(QUALITY_GATES['cpe-validity-gate']);
    assert.ok(QUALITY_GATES['metric-anomaly-detector']);
    assert.ok(QUALITY_GATES['auto-dispatch-threshold']);
    assert.ok(QUALITY_GATES['review-ranker']);
    assert.ok(QUALITY_GATES['confidence-calibrator']);
    assert.ok(QUALITY_GATES['delivery-optimizer']);
    assert.ok(QUALITY_GATES['advisory-remediation-helper']);
    assert.ok(QUALITY_GATES['exploit-risk-model']);
    assert.ok(QUALITY_GATES['match-confidence-model']);
    assert.ok(QUALITY_GATES['finding-importance-ranker']);
    assert.ok(QUALITY_GATES['news-credibility-weight-model']);
    assert.ok(QUALITY_GATES['delivery-error-classifier']);
    assert.ok(QUALITY_GATES['zero-day-rate-limit-optimizer']);
    assert.ok(QUALITY_GATES['digest-finding-selector']);
    assert.ok(QUALITY_GATES['severity-tier-model']);
    assert.ok(QUALITY_GATES['feed-recovery-backoff-optimizer']);
    assert.ok(QUALITY_GATES['alias-confidence-model']);
    assert.ok(QUALITY_GATES['advisory-composer']);
  });

  it('toModelSelfValidation converts QualityGateResult', () => {
    const gate = {
      passed: true,
      metrics: { accuracy: 0.95, precision: 0.96, recall: 0.92 },
      gateThresholds: { precision: 0.95, recall: 0.9 },
    };
    const validation = toModelSelfValidation(gate);
    assert.equal(validation.passed, true);
    assert.equal(validation.metrics.accuracy, 0.95);
  });

  it('CpeValidityGateQualityGate has correct minimum samples', () => {
    const gate = QUALITY_GATES['cpe-validity-gate'];
    assert.equal(gate.minimumSamples, 100);
    assert.equal(gate.modelId, 'cpe-validity-gate');
  });

  it('MetricAnomalyDetectorQualityGate has correct minimum samples', () => {
    const gate = QUALITY_GATES['metric-anomaly-detector'];
    assert.equal(gate.minimumSamples, 50);
  });

  it('ConfidenceCalibratorQualityGate enforces ECE <= 0.05', () => {
    const gate = QUALITY_GATES['confidence-calibrator'];
    const perfectModel = {
      predict: (_f: Record<string, number>) => ({ score: 0.9, probability: 0.9, confidence: 'HIGH' as const, reason: 'test' }),
    };
    const testSamples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      testSamples.push({
        id: `c${i}`,
        features: { credibility_score: 90 },
        label: 1,
        timestamp: '2025-01-01',
      });
    }
    const result = gate.evaluate(perfectModel, testSamples);
    assert.ok(result.passed);
  });
});

describe('drift detection', () => {
  it('computePsi returns NO_DRIFT for identical distributions', () => {
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({
        id: `s${i}`,
        features: { x: Math.random() },
        label: 0,
        timestamp: '2025-01-01',
      });
    }
    const report = computePsi(samples, samples, 'x');
    assert.equal(report.status, 'NO_DRIFT');
    assert.equal(report.psi, 0);
  });

  it('computePsi detects significant drift', () => {
    const reference: TrainingSample[] = [];
    const comparison: TrainingSample[] = [];
    for (let i = 0; i < 200; i++) {
      reference.push({ id: `r${i}`, features: { x: Math.random() * 10 }, label: 0, timestamp: '2025-01-01' });
      comparison.push({ id: `c${i}`, features: { x: 100 + Math.random() * 10 }, label: 0, timestamp: '2025-01-01' });
    }
    const report = computePsi(reference, comparison, 'x');
    assert.equal(report.status, 'SIGNIFICANT_DRIFT');
    assert.ok(report.psi >= 0.2);
  });

  it('detectConceptDrift returns DEGRADATION when performance drops', () => {
    const model = {
      predict: (_f: Record<string, number>) => ({
        score: 0.3,
        probability: 0.3,
        confidence: 'LOW' as const,
        reason: 'test',
      }),
    };
    const testData: TrainingSample[] = [];
    for (let i = 0; i < 50; i++) {
      testData.push({
        id: `s${i}`,
        features: { x: i },
        label: 1,
        timestamp: '2025-01-01',
      });
    }
    const metadata = {
      id: 'test',
      type: 'logistic' as const,
      version: '1.0.0',
      trainedAt: '2025-01-01',
      featureSchema: ['x'],
      description: 'test',
      performance: { accuracy: 0.95, precision: 0.95, recall: 0.9, aucRoc: 0.95 },
    };
    const results = detectConceptDrift(model, testData, metadata);
    assert.ok(results.some((r) => r.status === 'DEGRADATION'));
  });

  it('detectConceptDrift returns NO_DRIFT when performance is stable', () => {
    const model = {
      predict: (f: Record<string, number>) => ({
        score: f.x >= 5 ? 0.9 : 0.1,
        probability: f.x >= 5 ? 0.9 : 0.1,
        confidence: 'HIGH' as const,
        reason: 'test',
      }),
    };
    const testData: TrainingSample[] = [];
    for (let i = 0; i < 50; i++) {
      testData.push({
        id: `s${i}`,
        features: { x: i },
        label: i >= 5 ? 1 : 0,
        timestamp: '2025-01-01',
      });
    }
    const metadata = {
      id: 'test',
      type: 'logistic' as const,
      version: '1.0.0',
      trainedAt: '2025-01-01',
      featureSchema: ['x'],
      description: 'test',
      performance: { accuracy: 0.95, precision: 0.95, recall: 0.9, aucRoc: 0.95 },
    };
    const results = detectConceptDrift(model, testData, metadata);
    assert.ok(results.every((r) => r.status === 'NO_DRIFT'));
  });

  it('shouldRetrain returns true on significant feature drift', () => {
    const model = {
      predict: (_f: Record<string, number>) => ({
        score: 0.5,
        probability: 0.5,
        confidence: 'LOW' as const,
        reason: 'test',
      }),
    };
    const testData: TrainingSample[] = [];
    for (let i = 0; i < 50; i++) {
      testData.push({ id: `s${i}`, features: { x: 0.5 }, label: 1, timestamp: '2025-01-01' });
    }
    const metadata = {
      id: 'test',
      type: 'logistic' as const,
      version: '1.0.0',
      trainedAt: '2025-01-01',
      featureSchema: ['x'],
      description: 'test',
    };
    const recentSamples: TrainingSample[] = [];
    const trainSamples: TrainingSample[] = [];
    for (let i = 0; i < 200; i++) {
      trainSamples.push({ id: `t${i}`, features: { x: Math.random() * 10 }, label: 0, timestamp: '2025-01-01' });
      recentSamples.push({ id: `r${i}`, features: { x: 100 + Math.random() * 10 }, label: 0, timestamp: '2025-01-01' });
    }
    const result = shouldRetrain(model, testData, metadata, ['x'], recentSamples, trainSamples);
    assert.ok(result);
  });
});

describe('training orchestrator', () => {
  it('skips training when insufficient samples', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const data: TrainingDataSources = {
      cpeStrings: [],
      telemetryHistory: [],
      dispatchOutcomes: [],
      reviewOutcomeHistory: [],
      calibrationPairs: [],
      deliveryOutcomes: [],
      remediationFindings: [],
    };

    const result = await orch.trainAll(data);
    assert.equal(result.summary.total, 18);
    assert.equal(result.summary.skipped, 18);
    assert.equal(result.summary.trained, 0);
    assert.equal(result.summary.failed, 0);
    assert.equal(result.summary.saved, 0);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('trains CPE validity gate with valid/invalid CPE strings', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const cpeStrings = [
      'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
      'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
      'garbage-not-a-cpe',
      'cpe:2.3:a:adobe:reader:2020:*:*:*:*:*:*:*',
    ];
    for (let i = 0; i < 50; i++) {
      cpeStrings.push(`cpe:2.3:a:vendor${i}:product${i}:${i}.0:*:*:*:*:*:*:*`);
      cpeStrings.push(`invalid-${i}`);
    }

    const data: TrainingDataSources = {
      cpeStrings,
    };
    const result = await orch.trainAll(data);
    const cpeResult = result.results.find((r) => r.modelId === 'cpe-validity-gate')!;

    assert.equal(cpeResult.status, 'trained');
    assert.ok(cpeResult.validation.passed);
    assert.ok(cpeResult.saved);
    assert.ok(cpeResult.samplesCollected > 0);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('trains confidence calibrator with calibration pairs', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const calibrationPairs = [];
    for (let i = 0; i < 200; i++) {
      const score = 5 + (i % 95);
      const isActionable = score >= 50;
      calibrationPairs.push({ credibilityScore: score, isActionable });
    }

    const data: TrainingDataSources = { calibrationPairs };
    const result = await orch.trainAll(data);
    const calResult = result.results.find((r) => r.modelId === 'confidence-calibrator')!;

    assert.equal(calResult.status, 'trained');
    assert.ok(calResult.validation.passed);
    assert.ok(calResult.saved);

    fs.rmSync(dir, { recursive: true, force: true });
  });

   it('trains metric anomaly detector with telemetry history', async () => {
     const dir = tmpDir();
     const orch = new TrainingOrchestrator({ directory: dir });

     const telemetryHistory: MetricFeatures[] = [];
     for (let i = 0; i < 200; i++) {
       telemetryHistory.push({
         memoryPercent: 35 + Math.sin(i / 10) * 10,
         activeWorkers: 3 + (i % 3),
         concurrencyLimit: 10,
         latencyMs: 40 + (i % 30),
         deadLetters: 0,
         pendingClaims: i % 5,
         itemsPerSecond: 90 + (i % 30),
         poolWaiting: i % 3,
       });
     }
     // Inject 10 anomalies
     for (let i = 0; i < 10; i++) {
       telemetryHistory.push({
         memoryPercent: 95 - i,
         activeWorkers: 10,
         concurrencyLimit: 10,
         latencyMs: 700 + i * 10,
         deadLetters: 5,
         pendingClaims: 50,
         itemsPerSecond: 1,
         poolWaiting: 20,
       });
     }

    const data: TrainingDataSources = { telemetryHistory };
    const result = await orch.trainAll(data);
    const metricResult = result.results.find((r) => r.modelId === 'metric-anomaly-detector')!;

    assert.equal(metricResult.status, 'trained');
    assert.ok(metricResult.validation.passed);
    assert.ok(metricResult.saved);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('trains review ranker with review outcomes', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const reviewOutcomes = [];
    for (let i = 0; i < 200; i++) {
      const isMatch = i % 2 === 0;
      reviewOutcomes.push({
        features: {
          matchConfidence: isMatch ? 90 + (i % 10) : 30 + (i % 40),
          cvssScore: 5 + (i % 5),
          epssScore: 0.1 + (i % 3) * 0.3,
          cisaKev: i % 3 === 0,
          exploitStatus: i % 4,
          cweRiskLevel: i % 3,
          signalDensity: 0.5 + (i % 5) * 0.1,
          matchMethod: 'STRICT_CPE',
          sourceFeedWeight: 10 + (i % 20),
          assetCriticality: i % 3,
          hasVersionEvidence: i % 2 === 0,
          daysSincePublished: i % 30,
          negated: false,
        },
        statusAfterReview: isMatch ? 'PATCHED' as const : 'FALSE_POSITIVE' as const,
        daysToAction: isMatch ? 1 + (i % 5) : 30,
      });
    }

    const data: TrainingDataSources = { reviewOutcomeHistory: reviewOutcomes };
    const result = await orch.trainAll(data);
    const rankerResult = result.results.find((r) => r.modelId === 'review-ranker')!;

    assert.equal(rankerResult.status, 'trained');
    assert.ok(rankerResult.validation.passed);
    assert.ok(rankerResult.saved);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('trains auto-dispatch threshold with dispatch outcomes', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const dispatchOutcomes = [];
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

    const data: TrainingDataSources = { dispatchOutcomes };
    const result = await orch.trainAll(data);
    const dispatchResult = result.results.find((r) => r.modelId === 'auto-dispatch-threshold')!;

    assert.equal(dispatchResult.status, 'trained');
    assert.ok(dispatchResult.validation.passed);
    assert.ok(dispatchResult.saved);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('trains delivery optimizer with delivery outcomes', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const deliveryOutcomes = [];
    for (let i = 0; i < 200; i++) {
      deliveryOutcomes.push({
        provider: i % 2 === 0 ? 'smtp' : 'sendgrid',
        attempt: 1 + (i % 3),
        delayMs: 300_000 * (i % 3),
        succeeded: i % 5 !== 0,
        isRateLimited: i % 7 === 0,
        isPermanentFailure: i % 11 === 0,
      });
    }

    const data: TrainingDataSources = { deliveryOutcomes };
    const result = await orch.trainAll(data);
    const deliverResult = result.results.find((r) => r.modelId === 'delivery-optimizer')!;

    assert.equal(deliverResult.status, 'trained');
    assert.ok(deliverResult.validation.passed);
    assert.ok(deliverResult.saved);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('trains advisory remediation helper with remediation findings', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const remediationFindings = [];
    for (let i = 0; i < 200; i++) {
      const hasPatchUrl = i % 3 === 0;
      remediationFindings.push({
        features: {
          cvssScore: 5 + (i % 5),
          epssScore: 0.1 + (i % 3) * 0.3,
          cisaKev: i % 4 === 0,
          daysSincePublished: i % 30,
          sourceFeedWeight: 10 + (i % 20),
          hasVersionEvidence: i % 2 === 0,
          cweRiskLevel: i % 3,
          exploitStatus: i % 4,
        },
        playbook: hasPatchUrl
          ? { patchUrl: 'https://example.com/patch', immediateActions: ['patch'] }
          : { workarounds: ['block network'] },
      });
    }

    const data: TrainingDataSources = { remediationFindings };
    const result = await orch.trainAll(data);
    const remedResult = result.results.find((r) => r.modelId === 'advisory-remediation-helper')!;

    assert.equal(remedResult.status, 'trained');
    assert.ok(remedResult.validation.passed);
    assert.ok(remedResult.saved);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('full training summary has correct structure', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const data: TrainingDataSources = {};
    const result = await orch.trainAll(data);

    assert.ok(result.timestamp);
    assert.equal(result.storageDir, dir);
    assert.equal(result.results.length, 18);
    assert.equal(result.summary.total, 18);
    assert.equal(result.summary.trained + result.summary.skipped + result.summary.failed + result.summary.notNeeded, result.summary.total);

    for (const r of result.results) {
      assert.ok(r.modelId);
      assert.ok(r.modelType);
      assert.ok(Object.values(['trained', 'skipped', 'failed', 'not_needed']).includes(r.status));
      assert.equal(typeof r.samplesCollected, 'number');
      assert.equal(typeof r.samplesTrained, 'number');
      assert.equal(typeof r.saved, 'boolean');
    }

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('saved models can be reloaded from registry', async () => {
    const dir = tmpDir();
    const orch = new TrainingOrchestrator({ directory: dir });

    const cpeStrings = ['cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', ...Array.from({ length: 80 }, (_, i) => `cpe:2.3:a:v${i}:p${i}:1.0:*:*:*:*:*:*:*`), ...Array.from({ length: 80 }, (_, i) => `garbage-${i}`)];

    const data: TrainingDataSources = { cpeStrings };
    await orch.trainAll(data);

    const loadedGate = new CpeValidityGateModel();
    const loaded = await orch.getRegistry().load(loadedGate, 'cpe-validity-gate');
    assert.ok(loaded);
    assert.ok(loadedGate.isTrained());

    const sample = loadedGate.predict({ length: 35, segment_count: 13, has_valid_prefix: 1, has_wildcard_vendor_or_product: 0, numeric_token_ratio: 0.2, char_entropy: 3, colon_count: 12, escaped_char_count: 0, alpha_token_ratio: 0.5, max_segment_length: 10 });
    assert.ok(typeof sample.score === 'number');

    fs.rmSync(dir, { recursive: true, force: true });
  });
});
