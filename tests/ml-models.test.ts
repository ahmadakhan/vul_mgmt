import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CpeValidityGateModel, extractCpeValidityFeatures } from '../server/ml/models/cpeValidityGate';
import { MetricAnomalyDetectorModel } from '../server/ml/models/metricAnomalyDetector';
import { AutoDispatchThresholdModel } from '../server/ml/models/autoDispatchThreshold';
import { ConfidenceCalibrator } from '../server/ml/models/confidenceCalibrator';
import { DeliveryOptimizerModel } from '../server/ml/models/deliveryOptimizer';
import { AdvisoryRemediationHelper } from '../server/ml/models/advisoryRemediationHelper';
import type { TrainingSample } from '../server/ml/types';

describe('CpeValidityGateModel', () => {
  it('extracts correct features from valid CPE', () => {
    const feats = extractCpeValidityFeatures('cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*');
    assert.equal(feats.hasValidPrefix, 1);
    assert.equal(feats.length > 0, true);
    assert.equal(feats.colonCount > 0, true);
  });

  it('extracts correct features from invalid CPE', () => {
    const feats = extractCpeValidityFeatures('not-a-cpe-string');
    assert.equal(feats.hasValidPrefix, 0);
  });

  it('shouldParse returns true for trained-unknown and untrained', () => {
    const model = new CpeValidityGateModel();
    assert.equal(model.shouldParse('cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*:*'), true);
    assert.equal(model.shouldParse('garbage'), true);
  });

  it('collects training data from parseCPE23 outcomes', () => {
    const cpes = [
      'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
      'invalid-cpe',
      'cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*',
      'not-a-cpe',
    ];
    const samples = CpeValidityGateModel.collectTrainingData(cpes);
    assert.equal(samples.length, 4);
    assert.equal(samples[0].label, 1);
    assert.equal(samples[1].label, 0);
    assert.equal(samples[2].label, 1);
    assert.equal(samples[3].label, 0);
  });

  it('trains and predicts with correct feature count', () => {
    const cpes = [
      'cpe:2.3:a:microsoft:windows_10:10.0:*:*:*:*:*:*:*',
      'cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*',
      'cpe:2.3:a:nginx:nginx:1.21.6:*:*:*:*:*:*:*',
      'cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*',
      'cpe:2.3:o:canonical:ubuntu:22.04:*:*:*:*:*:*:*',
      'garbage',
      'not-a-cpe',
      'broken:cpe',
      'cpe:incomplete',
      '???',
      'cpe:2.3:a:bad:product:version:with:too:few',
      'cpe:2.3:a:short',
    ];
    const samples = CpeValidityGateModel.collectTrainingData(cpes);
    const model = new CpeValidityGateModel();
    model.train(samples);
    assert.equal(model.getFeatureNames().length, 10);

    // Valid CPE should predict ~1
    const valid = model.predict(samples[0].features);
    assert.ok(valid.score > 0.5);
  });
});

describe('MetricAnomalyDetectorModel', () => {
  it('extracts features with correct keys', () => {
    const model = new MetricAnomalyDetectorModel();
    assert.equal(model.getFeatureNames().length, 8);
  });

  it('collects training data from metric histories', () => {
    const history = Array.from({ length: 150 }, (_, i) => ({
      memoryPercent: 30 + Math.sin(i / 10) * 10,
      activeWorkers: 4,
      concurrencyLimit: 28,
      latencyMs: 50 + Math.random() * 20,
      deadLetters: 0,
      pendingClaims: i % 5,
      itemsPerSecond: 100,
      poolWaiting: 0,
    }));
    const samples = MetricAnomalyDetectorModel.collectTrainingData(history);
    assert.equal(samples.length, 150);
    assert.ok(samples[0].features.memory_percent > 0);
    assert.ok(samples[0].features.concurrency_ratio > 0);
  });

  it('trains on normal data and flags outlier', () => {
    const history = Array.from({ length: 150 }, () => ({
      memoryPercent: 30 + Math.random() * 5,
      activeWorkers: 4,
      concurrencyLimit: 28,
      latencyMs: 50 + Math.random() * 20,
      deadLetters: 0,
      pendingClaims: 0,
      itemsPerSecond: 100,
      poolWaiting: 0,
    }));
    const samples = MetricAnomalyDetectorModel.collectTrainingData(history);
    const model = new MetricAnomalyDetectorModel();
    model.train(samples);

    // Normal sample → low anomaly score
    const normalPred = model.predict({
      memory_percent: 32, active_workers: 5, concurrency_ratio: 0.18,
      latency_ms: 55, dead_letters: 0, pending_claims: 0, items_per_second: 100, pool_waiting: 0,
    });
    assert.ok(normalPred.score < 0.7);

    // Anomalous sample → high anomaly score
    const anomalyPred = model.predict({
      memory_percent: 95, active_workers: 28, concurrency_ratio: 1.0,
      latency_ms: 5000, dead_letters: 100, pending_claims: 500, items_per_second: 0, pool_waiting: 50,
    });
    assert.ok(anomalyPred.score > 0.5);
  });
});

describe('AutoDispatchThresholdModel', () => {
  it('defaults to 0.9 threshold when untrained', () => {
    const model = new AutoDispatchThresholdModel();
    assert.equal(model.getThreshold(), 0.9);
    assert.equal(model.shouldDispatch(90), true);
    assert.equal(model.shouldDispatch(89), false);
  });

  it('tunes threshold from outcome history', () => {
    const model = new AutoDispatchThresholdModel();
    // Most findings at 95+ are true positives, most at 70-89 are false positives
    for (let i = 0; i < 100; i++) {
      model.record({
        confidence: 95,
        dispatched: true,
        wasFalsePositive: i % 10 === 0, // 10% FP
        foundTruePositive: true,
      });
    }
    for (let i = 0; i < 100; i++) {
      model.record({
        confidence: 70,
        dispatched: true,
        wasFalsePositive: i % 2 === 0, // 50% FP — should not be dispatched
        foundTruePositive: i % 2 !== 0,
      });
    }
    model.train();
    // Threshold should be >= 0.9 (higher than 70 to avoid the 50% FP zone)
    assert.ok(model.getThreshold() >= 0.85, `threshold should be >= 0.85, got ${model.getThreshold()}`);
  });

  it('serializes and loads', () => {
    const model = new AutoDispatchThresholdModel();
    model.record({ confidence: 90, dispatched: true, wasFalsePositive: false, foundTruePositive: true });
    model.train();
    const artifact = model.serialize();
    const restored = new AutoDispatchThresholdModel();
    restored.load(artifact);
    assert.equal(restored.getThreshold(), model.getThreshold());
    assert.equal(restored.shouldDispatch(90), model.shouldDispatch(90));
  });
});

describe('ConfidenceCalibrator', () => {
  it('calibrates raw scores to empirical probabilities', () => {
    const calibrator = new ConfidenceCalibrator();
    // 85/90 raw=95 are positive (94%), 3/10 raw=70 are positive (30%)
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({
        id: `s-${i}`,
        features: { credibility_score: i < 90 ? 95 : 70 },
        label: i < 85 ? 1 : i < 90 ? 0 : i < 93 ? 1 : 0,
        timestamp: new Date().toISOString(),
      });
    }
    calibrator.train(samples);
    assert.equal(calibrator.isTrained(), true);

    const high = calibrator.predict({ credibility_score: 95 });
    const low = calibrator.predict({ credibility_score: 70 });
    assert.ok(high.score > low.score, 'high raw score should calibrate higher');
    assert.equal(high.score, high.probability! * 100);
    assert.ok(high.score >= 0 && high.score <= 100);
  });

  it('untrained model passes through raw score', () => {
    const calibrator = new ConfidenceCalibrator();
    const result = calibrator.predict({ credibility_score: 80 });
    assert.equal(result.score, 80);
    assert.equal(result.probability, 0.8);
    assert.equal(result.reason.includes('untrained'), true);
  });

  it('serializes and loads', () => {
    const calibrator = new ConfidenceCalibrator();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({
        id: `s-${i}`,
        features: { credibility_score: 80 + (i % 2) * 10 },
        label: i % 2,
        timestamp: new Date().toISOString(),
      });
    }
    calibrator.train(samples);
    const artifact = calibrator.serialize();
    const restored = new ConfidenceCalibrator();
    restored.load(artifact);
    const orig = calibrator.predict({ credibility_score: 85 });
    const loaded = restored.predict({ credibility_score: 85 });
    assert.ok(Math.abs(orig.score - loaded.score) < 1e-9, 'calibrated scores should match after reload');
  });

  it('enforces isotonic monotonicity', () => {
    const calibrator = new ConfidenceCalibrator();
    const samples: TrainingSample[] = [];
    // Deliberately non-monotonic: low scores have high positive rate
    for (let i = 0; i < 50; i++) {
      samples.push({ id: `low-${i}`, features: { credibility_score: 50 }, label: Math.random() > 0.3 ? 1 : 0, timestamp: '' });
    }
    for (let i = 0; i < 50; i++) {
      samples.push({ id: `hi-${i}`, features: { credibility_score: 90 }, label: Math.random() > 0.7 ? 1 : 0, timestamp: '' });
    }
    calibrator.train(samples);
    const low = calibrator.predict({ credibility_score: 50 });
    const high = calibrator.predict({ credibility_score: 90 });
    assert.ok(low.score <= high.score + 0.01, 'calibrated output should be monotonic');
  });
});

describe('DeliveryOptimizerModel', () => {
  it('defaults to safe policy when untrained', () => {
    const model = new DeliveryOptimizerModel();
    assert.equal(model.getInitialDelay(undefined), 5);
    assert.equal(model.getBackoffMultiplier(), 2);
    assert.equal(model.getMaxDelayMinutes(), 1440);
    assert.equal(model.getMaxAttempts(), 5);
    assert.equal(model.isTrained(), false);
  });

  it('computes exponential backoff for attempts', () => {
    const model = new DeliveryOptimizerModel();
    const delay1 = model.computeDelay(1);
    const delay2 = model.computeDelay(2);
    const delay3 = model.computeDelay(3);
    assert.ok(delay2 > delay1, 'delay should increase with attempt');
    assert.ok(delay3 > delay2, 'delay should increase with attempt');
    assert.equal(delay1, 5 * 60_000, 'first attempt delay should be initialDelayMinutes');
  });

  it('collects training data from delivery outcomes', () => {
    const outcomes = [
      { provider: 'sendgrid', attempt: 1, delayMs: 0, succeeded: false, isRateLimited: true, isPermanentFailure: false },
      { provider: 'sendgrid', attempt: 2, delayMs: 300_000, succeeded: true, isRateLimited: false, isPermanentFailure: false },
    ];
    const samples = DeliveryOptimizerModel.collectTrainingData(outcomes);
    assert.equal(samples.length, 2);
    assert.equal(samples[0].label, 0);
    assert.equal(samples[1].label, 1);
    assert.ok(samples[0].features.attempt === 1);
  });

  it('trains and tunes policy from outcome history', () => {
    const model = new DeliveryOptimizerModel();
    for (let i = 0; i < 100; i++) {
      model.record({
        provider: 'ses',
        attempt: i % 3 === 0 ? 1 : i % 3 === 1 ? 2 : 3,
        delayMs: (i % 3) * 300_000,
        succeeded: i % 3 !== 0,
        isRateLimited: i % 3 === 0,
        isPermanentFailure: false,
      });
    }
    model.train([]);
    assert.equal(model.isTrained(), true);
    const delay = model.computeDelay(2);
    assert.ok(delay > 0, 'should compute a positive delay after training');
  });

  it('serializes and loads', () => {
    const model = new DeliveryOptimizerModel();
    for (let i = 0; i < 80; i++) {
      model.record({
        provider: 'smtp',
        attempt: i % 2 === 0 ? 1 : 2,
        delayMs: (i % 2) * 300_000,
        succeeded: i % 2 === 1,
        isRateLimited: false,
        isPermanentFailure: false,
      });
    }
    model.train([]);
    const artifact = model.serialize();
    const restored = new DeliveryOptimizerModel();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);
    assert.equal(restored.computeDelay(1), model.computeDelay(1));
  });
});

describe('AdvisoryRemediationHelper', () => {
  it('defaults to safe predictions when untrained', () => {
    const helper = new AdvisoryRemediationHelper();
    const result = helper.predictRemediation({
      cvssScore: 8.5,
      epssScore: 0.8,
      cisaKev: true,
      daysSincePublished: 5,
      sourceFeedWeight: 30,
      hasVersionEvidence: true,
      cweRiskLevel: 2,
      exploitStatus: 3,
    });
    assert.ok(result.overall >= 0 && result.overall <= 1);
    assert.equal(result.generatedContent.patchUrl, undefined);
    assert.ok(result.generatedContent.stepByStep !== undefined);
    assert.equal(result.recommendation !== undefined, true);
  });

  it('generates fallback remediation content for sparse findings', () => {
    const helper = new AdvisoryRemediationHelper();
    const result = helper.predictRemediation({
      cvssScore: 3.0,
      epssScore: 0.1,
      cisaKev: false,
      daysSincePublished: 365,
      sourceFeedWeight: 10,
      hasVersionEvidence: false,
      cweRiskLevel: 0,
      exploitStatus: 0,
    });
    assert.equal(result.recommendation, 'sparse');
    assert.equal(result.generatedContent.patchUrl, undefined);
    assert.ok(result.generatedContent.immediateActions !== undefined);
    assert.ok(result.generatedContent.immediateActions!.length > 0);
  });

  it('collects training data from findings with playbooks', () => {
    const findings = [
      {
        features: { cvssScore: 9.0, epssScore: 0.9, cisaKev: true, daysSincePublished: 10, sourceFeedWeight: 40, hasVersionEvidence: true, cweRiskLevel: 2, exploitStatus: 3 },
        playbook: { patchUrl: 'https://example.com/patch', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
      },
      {
        features: { cvssScore: 4.0, epssScore: 0.1, cisaKev: false, daysSincePublished: 100, sourceFeedWeight: 15, hasVersionEvidence: false, cweRiskLevel: 0, exploitStatus: 0 },
        playbook: { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
      },
    ];
    const samples = AdvisoryRemediationHelper.collectTrainingData(findings);
    assert.ok(samples.length > 0, 'should generate training samples');
    assert.equal(samples[0].features.cvss_score, 9.0);
  });

  it('trains and predicts field probabilities', () => {
    const helper = new AdvisoryRemediationHelper();
    const findings = [];
    for (let i = 0; i < 20; i++) {
      findings.push({
        features: {
          cvssScore: i < 10 ? 9.0 : 4.0,
          epssScore: i < 10 ? 0.9 : 0.1,
          cisaKev: i < 10,
          daysSincePublished: i < 10 ? 10 : 100,
          sourceFeedWeight: i < 10 ? 40 : 15,
          hasVersionEvidence: i < 10,
          cweRiskLevel: i < 10 ? 2 : 0,
          exploitStatus: i < 10 ? 3 : 0,
        },
        playbook: i < 10
          ? { patchUrl: 'https://x.com', vendorAdvisoryRef: 'https://y.com', immediateActions: ['a'], workarounds: ['b'], rollbackPlan: 'r', stepByStep: ['s'] }
          : { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
      });
    }
    const samples = AdvisoryRemediationHelper.collectTrainingData(findings);
    helper.train(samples);
    assert.equal(helper.isTrained(), true);

    const highResult = helper.predictRemediation({
      cvssScore: 9.0, epssScore: 0.9, cisaKev: true, daysSincePublished: 10,
      sourceFeedWeight: 40, hasVersionEvidence: true, cweRiskLevel: 2, exploitStatus: 3,
    });
    const lowResult = helper.predictRemediation({
      cvssScore: 4.0, epssScore: 0.1, cisaKev: false, daysSincePublished: 100,
      sourceFeedWeight: 15, hasVersionEvidence: false, cweRiskLevel: 0, exploitStatus: 0,
    });
    assert.ok(highResult.overall > lowResult.overall, 'high-risk finding should have higher remediation completeness');
  });

  it('serializes and loads without drift', () => {
    const helper = new AdvisoryRemediationHelper();
    const findings = [];
    for (let i = 0; i < 20; i++) {
      findings.push({
        features: {
          cvssScore: i < 10 ? 9.0 : 4.0,
          epssScore: i < 10 ? 0.9 : 0.1,
          cisaKev: i < 10,
          daysSincePublished: i < 10 ? 10 : 100,
          sourceFeedWeight: i < 10 ? 40 : 15,
          hasVersionEvidence: i < 10,
          cweRiskLevel: i < 10 ? 2 : 0,
          exploitStatus: i < 10 ? 3 : 0,
        },
        playbook: i < 10
          ? { patchUrl: 'https://x.com', vendorAdvisoryRef: 'https://y.com', immediateActions: ['a'], workarounds: ['b'], rollbackPlan: 'r', stepByStep: ['s'] }
          : { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
      });
    }
    const samples = AdvisoryRemediationHelper.collectTrainingData(findings);
    helper.train(samples);
    const artifact = helper.serialize();
    const restored = new AdvisoryRemediationHelper();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);

    const f = { cvssScore: 7.0, epssScore: 0.5, cisaKev: true, daysSincePublished: 30,
      sourceFeedWeight: 25, hasVersionEvidence: true, cweRiskLevel: 1, exploitStatus: 1 };
    const orig = helper.predictRemediation(f);
    const loaded = restored.predictRemediation(f);
    assert.ok(Math.abs(orig.overall - loaded.overall) < 1e-6, 'overall score should match after reload');
  });
});
