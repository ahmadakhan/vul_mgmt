/**
 * Drift detection for the ML subsystem — both feature (data) drift and
 * concept (performance) drift.
 *
 * Feature drift: Population Stability Index (PSI) compares the distribution
 * of a feature in the training data vs. recent production data.
 *
 * Concept drift: compares the current model's performance on recent data
 * against the performance metrics recorded at training time. If the
 * metrics degrade beyond thresholds, the model should be retrained.
 *
 * All computation is pure-TS, CPU-friendly, and deterministic.
 */
import type { ModelMetadata, TrainingSample, PredictionResult } from '../types.ts';
import { evaluateClassifier } from './evaluation.ts';

/** PSI thresholds — standard industry values. */
export const PSI_THRESHOLDS = {
  NO_DRIFT: 0.1,
  SIGNIFICANT_DRIFT: 0.2,
} as const;

/** Concept drift thresholds — relative degradation allowed before retraining. */
export const CONCEPT_DRIFT_THRESHOLDS = {
  AUC_ROC_DEGRADE: 0.1,
  PRECISION_DEGRADE: 0.15,
  RECALL_DEGRADE: 0.2,
} as const;

export interface FeatureDriftReport {
  feature: string;
  psi: number;
  status: 'NO_DRIFT' | 'MODERATE_DRIFT' | 'SIGNIFICANT_DRIFT';
  referenceBins: number;
  comparisonBins: number;
}

export interface ConceptDriftReport {
  metric: string;
  referenceValue: number;
  currentValue: number;
  degradation: number;
  status: 'NO_DRIFT' | 'DEGRADATION';
  threshold: number;
}

export interface DriftReport {
  timestamp: string;
  modelId: string;
  featureDrift: FeatureDriftReport[];
  conceptDrift: ConceptDriftReport[];
  needsRetraining: boolean;
  summary: string;
}

/**
 * Computes Population Stability Index (PSI) for a single feature.
 *
 * PSI = Σ (p_i - q_i) * ln(p_i / q_i)
 * where p_i is the proportion in bin i for reference, q_i for comparison.
 *
 * Both distributions are binned into `nBins` equal-width bins based on the
 * reference range. Empty bins in comparison get a small epsilon to avoid
 * division by zero.
 */
export function computePsi(reference: TrainingSample[], comparison: TrainingSample[], featureName: string, nBins = 10): FeatureDriftReport {
  const refValues = reference.map((s) => s.features[featureName] ?? 0);
  const cmpValues = comparison.map((s) => s.features[featureName] ?? 0);

  if (refValues.length === 0 || cmpValues.length === 0) {
    return { feature: featureName, psi: 0, status: 'NO_DRIFT', referenceBins: 0, comparisonBins: 0 };
  }

  const refMin = Math.min(...refValues);
  const refMax = Math.max(...refValues);
  const range = refMax - refMin;
  if (range === 0) {
    return { feature: featureName, psi: 0, status: 'NO_DRIFT', referenceBins: refValues.length, comparisonBins: cmpValues.length };
  }

  const binEdges: number[] = [];
  for (let i = 0; i <= nBins; i++) {
    binEdges.push(refMin + (range * i) / nBins);
  }
  binEdges[nBins] = Infinity;

  const refCounts = new Array(nBins).fill(0);
  const cmpCounts = new Array(nBins).fill(0);

  for (const v of cmpValues) {
    let binIdx = 0;
    for (let i = 0; i < binEdges.length - 1; i++) {
      if (v >= binEdges[i] && v < binEdges[i + 1]) {
        binIdx = i;
        break;
      }
      if (i === binEdges.length - 2) binIdx = i;
    }
    cmpCounts[binIdx]++;
  }

  for (const v of refValues) {
    let binIdx = 0;
    for (let i = 0; i < binEdges.length - 1; i++) {
      if (v >= binEdges[i] && v < binEdges[i + 1]) {
        binIdx = i;
        break;
      }
      if (i === binEdges.length - 2) binIdx = i;
    }
    refCounts[binIdx]++;
  }

  const refTotal = refCounts.reduce((a, b) => a + b, 0);
  const cmpTotal = cmpCounts.reduce((a, b) => a + b, 0);
  const epsilon = 1e-6;

  let psi = 0;
  for (let i = 0; i < nBins; i++) {
    const p = refCounts[i] / refTotal;
    const q = cmpCounts[i] / cmpTotal;
    if (p > epsilon && q > epsilon) {
      psi += (q - p) * Math.log(q / p);
    }
  }

  let status: FeatureDriftReport['status'] = 'NO_DRIFT';
  if (psi >= PSI_THRESHOLDS.SIGNIFICANT_DRIFT) status = 'SIGNIFICANT_DRIFT';
  else if (psi >= PSI_THRESHOLDS.NO_DRIFT) status = 'MODERATE_DRIFT';

  return {
    feature: featureName,
    psi: Math.round(psi * 10000) / 10000,
    status,
    referenceBins: refValues.length,
    comparisonBins: cmpValues.length,
  };
}

/**
 * Computes PSI across all features of a model's training data.
 */
export function detectFeatureDrift(
  reference: TrainingSample[],
  comparison: TrainingSample[],
  featureNames: string[],
  nBins = 10,
): FeatureDriftReport[] {
  if (reference.length === 0 || comparison.length === 0) return [];
  return featureNames.map((f) => computePsi(reference, comparison, f, nBins));
}

/**
 * Detects concept drift by comparing current model performance against
 * the performance recorded in the model's metadata at training time.
 */
export function detectConceptDrift(
  model: { predict: (f: Record<string, number>) => PredictionResult },
  testData: TrainingSample[],
  metadata: ModelMetadata,
): ConceptDriftReport[] {
  if (!metadata.performance || testData.length === 0) return [];

  const { accuracy, precision, recall, aucRoc } = evaluateClassifier(testData, model.predict.bind(model));
  const perf = metadata.performance;
  const results: ConceptDriftReport[] = [];

  if (perf.aucRoc !== undefined) {
    const degradation = perf.aucRoc - aucRoc;
    results.push({
      metric: 'auc_roc',
      referenceValue: perf.aucRoc,
      currentValue: aucRoc,
      degradation,
      status: degradation > CONCEPT_DRIFT_THRESHOLDS.AUC_ROC_DEGRADE ? 'DEGRADATION' : 'NO_DRIFT',
      threshold: CONCEPT_DRIFT_THRESHOLDS.AUC_ROC_DEGRADE,
    });
  }

  if (perf.precision !== undefined) {
    const degradation = perf.precision - precision;
    results.push({
      metric: 'precision',
      referenceValue: perf.precision,
      currentValue: precision,
      degradation,
      status: degradation > CONCEPT_DRIFT_THRESHOLDS.PRECISION_DEGRADE ? 'DEGRADATION' : 'NO_DRIFT',
      threshold: CONCEPT_DRIFT_THRESHOLDS.PRECISION_DEGRADE,
    });
  }

  if (perf.recall !== undefined) {
    const degradation = perf.recall - recall;
    results.push({
      metric: 'recall',
      referenceValue: perf.recall,
      currentValue: recall,
      degradation,
      status: degradation > CONCEPT_DRIFT_THRESHOLDS.RECALL_DEGRADE ? 'DEGRADATION' : 'NO_DRIFT',
      threshold: CONCEPT_DRIFT_THRESHOLDS.RECALL_DEGRADE,
    });
  }

  if (perf.accuracy !== undefined) {
    const degradation = perf.accuracy - accuracy;
    results.push({
      metric: 'accuracy',
      referenceValue: perf.accuracy,
      currentValue: accuracy,
      degradation,
      status: degradation > CONCEPT_DRIFT_THRESHOLDS.RECALL_DEGRADE ? 'DEGRADATION' : 'NO_DRIFT',
      threshold: CONCEPT_DRIFT_THRESHOLDS.RECALL_DEGRADE,
    });
  }

  return results;
}

/**
 * Computes drift on recent vs. historical data to inform whether
 * retraining should be triggered. Returns a boolean decision.
 */
export function shouldRetrain(
  model: { predict: (f: Record<string, number>) => PredictionResult },
  testData: TrainingSample[],
  metadata: ModelMetadata,
  featureNames: string[],
  recentSamples: TrainingSample[] = [],
  trainSamples: TrainingSample[] = [],
): boolean {
  const conceptDrift = detectConceptDrift(model, testData, metadata);
  if (conceptDrift.some((d) => d.status === 'DEGRADATION')) return true;

  if (recentSamples.length > 0 && trainSamples.length > 0 && featureNames.length > 0) {
    const featureDrift = detectFeatureDrift(trainSamples, recentSamples, featureNames);
    if (featureDrift.some((d) => d.status === 'SIGNIFICANT_DRIFT')) return true;
  }

  return false;
}
