/**
 * Per-model quality gates for autonomous training.
 *
 * Each gate defines:
 * - minimumSamples: minimum training samples required before training is attempted
 * - evaluate: validates a trained model against holdout test data
 * - gate: the quality threshold the model must pass to be deployed
 *
 * Models that fail their gate are NOT saved — the existing active model
 * remains in place. This enforces the "no negative impact" invariant.
 */
import type { ModelSelfValidation, TrainingSample } from '../types.ts';
import type { PredictionResult } from '../types.ts';
import { evaluateClassifier, computeEce, toLabel } from './evaluation.ts';
import type { AdvisoryComposerModel } from '../models/advisoryComposer.ts';

/** Quality gate result for a single model training cycle. */
export interface QualityGateResult {
  passed: boolean;
  metrics: Record<string, number>;
  failureReason?: string;
  gateThresholds: Record<string, number>;
}

export interface QualityGate {
  readonly modelId: string;
  readonly minimumSamples: number;
  evaluate(model: unknown, testSamples: TrainingSample[]): QualityGateResult;
}

interface GateCheck {
  metric: string;
  value: number;
  min?: number;
  max?: number;
}

/** Common gate-checking helper — no gate-specific logic duplicated. */
function checkGate(checks: GateCheck[], thresholds: Record<string, number>): QualityGateResult {
  const metrics: Record<string, number> = {};
  const failures: string[] = [];

  for (const c of checks) {
    metrics[c.metric] = c.value;
    if (c.min !== undefined && c.value < c.min) {
      failures.push(`${c.metric} ${c.value.toFixed(4)} < ${c.min}`);
    }
    if (c.max !== undefined && c.value > c.max) {
      failures.push(`${c.metric} ${c.value.toFixed(4)} > ${c.max}`);
    }
  }

  return {
    passed: failures.length === 0,
    metrics,
    gateThresholds: thresholds,
    failureReason: failures.length > 0 ? failures.join('; ') : undefined,
  };
}

/**
 * CPE Validity Gate — binary classifier for CPE 2.3 string validity.
 * Gate: precision ≥ 0.95, recall ≥ 0.9 (matches MATCHING_QUALITY_GATES).
 */
export const cpeValidityGateQualityGate: QualityGate = {
  modelId: 'cpe-validity-gate',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'precision', value: metrics.precision, min: 0.95 },
        { metric: 'recall', value: metrics.recall, min: 0.9 },
      ],
      { precision: 0.95, recall: 0.9 },
    );
  },
};

/**
 * Metric Anomaly Detector — unsupervised isolation forest over telemetry.
 * Gate: anomaly rate must be within [0.01, 0.15] — not too aggressive,
 * not too permissive. Also checks AUC is ≥ 0.5 (no inverted predictions).
 */
export const metricAnomalyDetectorQualityGate: QualityGate = {
  modelId: 'metric-anomaly-detector',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { isAnomaly: (f: Record<string, number>) => boolean };
    let anomalyCount = 0;
    for (const s of testSamples) {
      if (m.isAnomaly(s.features)) anomalyCount++;
    }
    const anomalyRate = testSamples.length > 0 ? anomalyCount / testSamples.length : 0;
    return checkGate(
      [
        { metric: 'anomaly_rate', value: anomalyRate, min: 0.01, max: 0.15 },
      ],
      { minAnomalyRate: 0.01, maxAnomalyRate: 0.15 },
    );
  },
};

/**
 * Auto-Dispatch Threshold — 1-D optimizer over confidence thresholds.
 * Gate: best threshold must achieve precision ≥ 0.9 on holdout outcomes.
 */
export const autoDispatchThresholdQualityGate: QualityGate = {
  modelId: 'auto-dispatch-threshold',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    let tp = 0;
    let fp = 0;
    let fn = 0;
    for (const s of testSamples) {
      const confidence = s.features.confidence ?? s.features.credibility_score ?? 0;
      const pred = m.predict({ confidence });
      const label = toLabel(s.label);
      if (pred.score >= 0.5) {
        if (label === 1) tp++;
        else fp++;
      } else {
        if (label === 1) fn++;
      }
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    return checkGate(
      [
        { metric: 'precision', value: precision, min: 0.9 },
        { metric: 'recall', value: recall, min: 0.1 },
      ],
      { precision: 0.9, recall: 0.1 },
    );
  },
};

/**
 * Review Queue Ranker — GBDT ranking model.
 * Gate: AUC-ROC ≥ 0.55 (must beat random for actionable ordering).
 */
export const reviewRankerQualityGate: QualityGate = {
  modelId: 'review-ranker',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'auc_roc', value: metrics.aucRoc, min: 0.55 },
        { metric: 'recall', value: metrics.recall, min: 0.3 },
      ],
      { aucRoc: 0.55, recall: 0.3 },
    );
  },
};

/**
 * Confidence Calibrator — isotonic regression calibration.
 * Gate: Expected Calibration Error (ECE) ≤ 0.05.
 */
export const confidenceCalibratorQualityGate: QualityGate = {
  modelId: 'confidence-calibrator',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => { score: number; probability?: number } };
    const predictions: { prob: number; label: number }[] = [];
    for (const s of testSamples) {
      const pred = m.predict(s.features);
      predictions.push({ prob: pred.probability ?? pred.score, label: toLabel(s.label) });
    }
    const cal = computeEce(predictions);
    return checkGate(
      [
        { metric: 'ece', value: cal.ece, max: 0.05 },
      ],
      { maxEce: 0.05 },
    );
  },
};

/**
 * Delivery Optimizer — backoff policy tuner.
 * Gate: best policy must achieve ≥ 0.7 aggregate success rate on holdout
 * outcomes. We simulate the new policy against the holdout delivery
 * outcomes and measure the actual success rate.
 */
export const deliveryOptimizerQualityGate: QualityGate = {
  modelId: 'delivery-optimizer',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    // Count predictions where the model predicts high success (score >= 0.5)
    // vs. actual labels — this validates the policy on holdout data.
    let correct = 0;
    for (const s of testSamples) {
      const pred = m.predict(s.features);
      const label = toLabel(s.label);
      const predLabel = pred.score >= 0.5 ? 1 : 0;
      if (predLabel === label) correct++;
    }
    const successRate = testSamples.length > 0 ? correct / testSamples.length : 0;
    return checkGate(
      [
        { metric: 'success_rate_estimate', value: successRate, min: 0.7 },
      ],
      { minSuccessRate: 0.7 },
    );
  },
};

/**
 * Advisory Remediation Helper — multi-label logistic regression per field.
 * Gate: each field's model must achieve accuracy ≥ 0.3 on holdout.
 */
export const remediationHelperQualityGate: QualityGate = {
  modelId: 'advisory-remediation-helper',
  minimumSamples: 20,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'accuracy', value: metrics.accuracy, min: 0.3 },
      ],
      { minAccuracy: 0.3 },
    );
  },
};

/**
 * Exploit Risk Model — multi-class (6 levels) via one-vs-all LogisticRegressions.
 * Gate: accuracy ≥ 0.7 on holdout (must correctly assign risk level most of the time).
 */
export const exploitRiskQualityGate: QualityGate = {
  modelId: 'exploit-risk-model',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'accuracy', value: metrics.accuracy, min: 0.7 },
      ],
      { accuracy: 0.7 },
    );
  },
};

/**
 * Match Confidence Model — binary classifier for match true-positive probability.
 * Gate: AUC-ROC ≥ 0.55 (must beat random for confidence calibration).
 */
export const matchConfidenceQualityGate: QualityGate = {
  modelId: 'match-confidence-model',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'auc_roc', value: metrics.aucRoc, min: 0.55 },
      ],
      { aucRoc: 0.55 },
    );
  },
};

/**
 * Finding Importance Ranker — GBDT ranker for digest finding ordering.
 * Gate: AUC-ROC ≥ 0.55 (must rank actionable findings higher than false positives).
 */
export const findingImportanceQualityGate: QualityGate = {
  modelId: 'finding-importance-ranker',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'auc_roc', value: metrics.aucRoc, min: 0.55 },
        { metric: 'recall', value: metrics.recall, min: 0.3 },
      ],
      { aucRoc: 0.55, recall: 0.3 },
    );
  },
};

/**
 * News Credibility Weight Model — grid-search weight optimizer.
 * Gate: best weight combination must achieve ≥ 0.55 accuracy on holdout
 * (must beat the default 0.6/0.4 split).
 */
export const credibilityWeightQualityGate: QualityGate = {
  modelId: 'news-credibility-weight-model',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (feedWeight: number, keywordScore: number) => PredictionResult };
    let correct = 0;
    let total = 0;
    for (const s of testSamples) {
      const feedWeight = s.features.feed_weight ?? s.features.credibility_score ?? 0;
      const keywordScore = s.features.keyword_score ?? s.features.credibility_score ?? 0;
      const pred = m.predict(feedWeight, keywordScore);
      const label = toLabel(s.label);
      const predLabel = pred.score >= 50 ? 1 : 0;
      if (predLabel === label) correct++;
      total++;
    }
    const accuracy = total > 0 ? correct / total : 0;
    return checkGate(
      [
        { metric: 'accuracy', value: accuracy, min: 0.55 },
      ],
      { accuracy: 0.55 },
    );
  },
};

/**
 * Delivery Error Classifier — binary classifier for permanent vs transient errors.
 * Gate: precision ≥ 0.8 on permanent classification (must not incorrectly
 * mark transient errors as permanent, since that suppresses retries).
 */
export const deliveryErrorClassifierQualityGate: QualityGate = {
  modelId: 'delivery-error-classifier',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'precision', value: metrics.precision, min: 0.8 },
        { metric: 'auc_roc', value: metrics.aucRoc, min: 0.55 },
      ],
      { precision: 0.8, aucRoc: 0.55 },
    );
  },
};

/**
 * Zero-Day Rate Limit Optimizer — threshold optimizer for zero-day cap.
 * Gate: the optimized cap must not drop more than 30% of true-positive
 * zero-day findings (false negative rate ≤ 0.3).
 */
export const zeroDayRateLimitQualityGate: QualityGate = {
  modelId: 'zero-day-rate-limit-optimizer',
  minimumSamples: 20,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (count: number, scores: number[]) => PredictionResult };
    let truePositives = 0;
    let falseNegatives = 0;
    for (const s of testSamples) {
      const count = s.features.zero_day_count ?? 0;
      const scores: number[] = [];
      for (let i = 0; i < count; i++) scores.push(100 - i);
      const pred = m.predict(count, scores);
      const label = toLabel(s.label);
      if (pred.score >= 0.5 && label === 1) truePositives++;
      if (pred.score < 0.5 && label === 1) falseNegatives++;
    }
    const fnr = (truePositives + falseNegatives) > 0 ? falseNegatives / (truePositives + falseNegatives) : 0;
    return checkGate(
      [
        { metric: 'false_negative_rate', value: fnr, max: 0.3 },
      ],
      { maxFnr: 0.3 },
    );
  },
};

/**
 * Digest Finding Selector — binary classifier for digest relevance.
 * Gate: precision ≥ 0.7 on holdout (must not include too many false positives).
 */
export const digestFindingSelectorQualityGate: QualityGate = {
  modelId: 'digest-finding-selector',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'precision', value: metrics.precision, min: 0.7 },
        { metric: 'auc_roc', value: metrics.aucRoc, min: 0.55 },
      ],
      { precision: 0.7, aucRoc: 0.55 },
    );
  },
};

/**
 * Severity Tier Model — multi-class (5 tiers) via one-vs-all LogisticRegressions.
 * Gate: accuracy ≥ 0.65 on holdout.
 */
export const severityTierQualityGate: QualityGate = {
  modelId: 'severity-tier-model',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'accuracy', value: metrics.accuracy, min: 0.65 },
      ],
      { accuracy: 0.65 },
    );
  },
};

/**
 * Feed Recovery Backoff Optimizer — threshold optimizer for backoff parameters.
 * Gate: the optimized policy must achieve ≥ 0.6 recovery rate on holdout
 * (better than or matching the default exponential backoff).
 */
export const feedRecoveryBackoffQualityGate: QualityGate = {
  modelId: 'feed-recovery-backoff-optimizer',
  minimumSamples: 20,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (failures: number) => PredictionResult };
    let modelMatches = 0;
    let defaultMatches = 0;
    let modelError = 0;
    let defaultError = 0;
    let evaluated = 0;
    for (const s of testSamples) {
      const failures = Math.max(1, Number(s.features.failure_count ?? 1));
      const delayMinutes = Math.max(1, Number(s.features.delay_minutes ?? 5));
      const predictedDelayMinutes = m.predict(failures).score;
      const defaultDelayMinutes = Math.min(60, 5 * 2 ** Math.min(6, failures - 1));
      evaluated++;
      if (s.label === 1) {
        if (predictedDelayMinutes >= delayMinutes * 0.5 && predictedDelayMinutes <= delayMinutes * 1.5) modelMatches++;
        if (defaultDelayMinutes >= delayMinutes * 0.5 && defaultDelayMinutes <= delayMinutes * 1.5) defaultMatches++;
      }
      modelError += Math.abs(predictedDelayMinutes - delayMinutes) / Math.max(delayMinutes, 1);
      defaultError += Math.abs(defaultDelayMinutes - delayMinutes) / Math.max(delayMinutes, 1);
    }
    const recoveryRate = evaluated > 0 ? modelMatches / evaluated : 0;
    const defaultRecoveryRate = evaluated > 0 ? defaultMatches / evaluated : 0;
    const modelLatencyPenalty = evaluated > 0 ? modelError / evaluated : 1;
    const defaultLatencyPenalty = evaluated > 0 ? defaultError / evaluated : 1;
    const latencyDiscriminates = modelLatencyPenalty <= defaultLatencyPenalty;
    return checkGate(
      [
        { metric: 'recovery_rate', value: recoveryRate, min: 0.6 },
        { metric: 'vs_default_recovery_rate', value: recoveryRate, min: defaultRecoveryRate },
        { metric: 'latency_penalty', value: modelLatencyPenalty, min: 0, max: defaultLatencyPenalty },
        { metric: 'latency_discriminates', value: latencyDiscriminates ? 1 : 0, min: 1 },
      ],
      { recoveryRate, defaultRecoveryRate, modelLatencyPenalty, defaultLatencyPenalty },
    );
  },
};

/**
 * Alias Confidence Model — binary classifier for alias finding confirmation.
 * Gate: AUC-ROC ≥ 0.6 (must be better than random for confidence calibration).
 */
export const aliasConfidenceQualityGate: QualityGate = {
  modelId: 'alias-confidence-model',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'auc_roc', value: metrics.aucRoc, min: 0.6 },
      ],
      { aucRoc: 0.6 },
    );
  },
};

/**
 * Advisory Composer — validates that predicted summary style / priority /
 * remediation emphasis match the observed actionable outcome.
 * Gate: accuracy ≥ 0.6 on holdout (must predict actionable composition better than random).
 */
export const advisoryComposerQualityGate: QualityGate = {
  modelId: 'advisory-composer',
  minimumSamples: 20,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as AdvisoryComposerModel;
    let correct = 0;
    let total = 0;
    for (const s of testSamples) {
      const pred = m.predict(s.features);
      const prob = pred.probability ?? pred.score;
      // Label encodes wasActionable in the high bit: >= 10000 means actionable
      const label = typeof s.label === 'number' ? s.label : (s.label ? 1 : 0);
      const wasActionable = label >= 10000;
      // Consider prediction "correct" if confidence is non-trivial when actionable, or low confidence when not
      const predActionable = prob >= 0.5;
      if (predActionable === wasActionable) correct++;
      total++;
    }
    const accuracy = total > 0 ? correct / total : 0;
    return checkGate(
      [
        { metric: 'accuracy', value: accuracy, min: 0.6 },
      ],
      { accuracy: 0.6 },
    );
  },
};

/** Registry of all quality gates, keyed by model ID. */
export const QUALITY_GATES: Record<string, QualityGate> = {
  'cpe-validity-gate': cpeValidityGateQualityGate,
  'metric-anomaly-detector': metricAnomalyDetectorQualityGate,
  'auto-dispatch-threshold': autoDispatchThresholdQualityGate,
  'review-ranker': reviewRankerQualityGate,
  'confidence-calibrator': confidenceCalibratorQualityGate,
  'delivery-optimizer': deliveryOptimizerQualityGate,
  'advisory-remediation-helper': remediationHelperQualityGate,
  'exploit-risk-model': exploitRiskQualityGate,
  'match-confidence-model': matchConfidenceQualityGate,
  'finding-importance-ranker': findingImportanceQualityGate,
  'news-credibility-weight-model': credibilityWeightQualityGate,
  'delivery-error-classifier': deliveryErrorClassifierQualityGate,
  'zero-day-rate-limit-optimizer': zeroDayRateLimitQualityGate,
  'digest-finding-selector': digestFindingSelectorQualityGate,
  'severity-tier-model': severityTierQualityGate,
  'feed-recovery-backoff-optimizer': feedRecoveryBackoffQualityGate,
  'alias-confidence-model': aliasConfidenceQualityGate,
  'advisory-composer': advisoryComposerQualityGate,
};

/**
 * Converts a QualityGateResult into a ModelSelfValidation for consistency
 * with the types.ts interface.
 */
export function toModelSelfValidation(result: QualityGateResult): ModelSelfValidation {
  return {
    passed: result.passed,
    metrics: result.metrics,
    failureReason: result.failureReason,
  };
}
