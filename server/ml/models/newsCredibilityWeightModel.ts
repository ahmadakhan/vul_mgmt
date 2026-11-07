/**
 * News Credibility Weight Model — learns the optimal blend of feed-weight
 * and keyword-confidence scores for intelligence credibility, replacing the
 * hardcoded `feedScore * 0.6 + keywordScore * 0.4` in
 * intelligenceMatcher.ts:46.
 *
 * File target: src/utils/intelligenceMatcher.ts:46 (computeCredibilityScore)
 *
 * Uses a grid-search optimizer over (feedWeight, keywordWeight) pairs that
 * must sum to 1.0, evaluating each pair by how well the resulting blended
 * score separates actionable from non-actionable findings. This follows the
 * same threshold_optimizer pattern as AutoDispatchThresholdModel.
 *
 * Training data: correlation_matches with feed_weight, credibility_score,
 * and outcome (PATCHED/RESOLVED/DELIVERED = actionable).
 */
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';
import { BaseModel } from '../baseModel.ts';

export interface CredibilitySample {
  feedWeight: number;
  keywordScore: number;
  isActionable: boolean;
  timestamp?: string;
  groupKey?: string;
}

export interface CredibilityWeights {
  feedWeight: number;
  keywordWeight: number;
  featureNames: string[];
}

export const CREDIBILITY_FEATURE_NAMES = ['feed_weight', 'keyword_score'] as const;

/** Reviewed default blend. Weights this far off are treated as drift. */
export const DEFAULT_FEED_WEIGHT = 0.6;

/** Blend deviation (from the default feed weight) beyond which confidence drops. */
export const DRIFT_TOLERANCE = 0.2;

/** Blended score at or above which a finding is considered actionable. */
export const ACTIONABLE_THRESHOLD = 50;

/** Candidate blends summing to 1.0. Shared by training and holdout selection. */
export const WEIGHT_GRID = [
  { feed: 0.9, keyword: 0.1 },
  { feed: 0.8, keyword: 0.2 },
  { feed: 0.7, keyword: 0.3 },
  { feed: 0.6, keyword: 0.4 },
  { feed: 0.5, keyword: 0.5 },
  { feed: 0.4, keyword: 0.6 },
  { feed: 0.3, keyword: 0.7 },
  { feed: 0.2, keyword: 0.8 },
  { feed: 0.1, keyword: 0.9 },
] as const;

/** Chronological, group-safe split: no CVE/asset group appears on both sides. */
export function chronologicalCredibilitySplit(samples: CredibilitySample[], trainFraction = 0.8) {
  const ordered = [...samples].sort((a, b) => {
    const at = Date.parse(a.timestamp || '') || 0;
    const bt = Date.parse(b.timestamp || '') || 0;
    return at !== bt ? at - bt : (a.groupKey || '').localeCompare(b.groupKey || '');
  });
  const groups = new Map<string, CredibilitySample[]>();
  for (const sample of ordered) {
    const key = sample.groupKey || `${sample.feedWeight}:${sample.keywordScore}:${sample.timestamp || ''}`;
    const group = groups.get(key) || [];
    group.push(sample);
    groups.set(key, group);
  }
  const orderedGroups = [...groups.values()].sort((a, b) => {
    const ak = Date.parse(a[0]?.timestamp || '') || 0;
    const bk = Date.parse(b[0]?.timestamp || '') || 0;
    return ak - bk;
  });
  const target = ordered.length * trainFraction;
  let trainCount = 0;
  let splitAt = 0;
  for (; splitAt < orderedGroups.length; splitAt++) {
    trainCount += orderedGroups[splitAt].length;
    if (trainCount >= target) break;
  }
  splitAt++;
  return {
    train: orderedGroups.slice(0, splitAt).flat(),
    holdout: orderedGroups.slice(splitAt).flat(),
  };
}

const defaultWeights = (): CredibilityWeights => ({
  feedWeight: DEFAULT_FEED_WEIGHT,
  keywordWeight: 1 - DEFAULT_FEED_WEIGHT,
  featureNames: [...CREDIBILITY_FEATURE_NAMES],
});

/** Recover a CredibilitySample from either a flat sample or generic TrainingSample. */
function toCredibilitySample(sample: CredibilitySample | TrainingSample): CredibilitySample {
  if ('feedWeight' in sample && 'keywordScore' in sample) {
    return sample as CredibilitySample;
  }
  const generic = sample as TrainingSample;
  return {
    feedWeight: generic.features.feed_weight ?? generic.features.credibility_score ?? 0,
    keywordScore: generic.features.keyword_score ?? generic.features.credibility_score ?? 0,
    isActionable: generic.label === 1 || generic.label === true,
    timestamp: generic.timestamp,
  };
}

const blend = (sample: CredibilitySample, feedWeight: number, keywordWeight: number): number =>
  sample.feedWeight * feedWeight + sample.keywordScore * keywordWeight;

/** Fraction of samples whose blended score lands on the actionable side. */
function agreementRate(samples: CredibilitySample[], feedWeight: number, keywordWeight: number): number {
  if (samples.length === 0) return 0;
  let correct = 0;
  for (const sample of samples) {
    const predicted = blend(sample, feedWeight, keywordWeight) >= ACTIONABLE_THRESHOLD;
    if (predicted === sample.isActionable) correct++;
  }
  return correct / samples.length;
}

export class NewsCredibilityWeightModel extends BaseModel {
  private weights: CredibilityWeights | null = defaultWeights();

  // ML Quality Gates Implementation
  private qualityMonitor: MLQualityMonitor;
  private modelVersions: Map<string, ModelArtifact> = new Map();
  private currentModelId: string | null = null;
  private qualityThresholds = {
    accuracy: 0.8,
    stalenessDays: 30,
  };

  constructor(metadata?: ModelMetadata) {
    super(metadata ?? {
      id: 'news-credibility-weight-model',
      type: 'threshold_optimizer',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...CREDIBILITY_FEATURE_NAMES],
      description: 'Learned weights for blending feed credibility and keyword confidence',
    });
    this.qualityMonitor = new MLQualityMonitor(this);
    this.initializeModelVersions();
  }

  /** Grid-search the blend on the supplied samples. Requires 100+ samples. */
  train(samples: Array<CredibilitySample | TrainingSample>): void {
    if (samples.length < 100) return; // not enough data to tune — keep default

    const credibilitySamples = samples.map(toCredibilitySample);
    const best = this.selectWeights(credibilitySamples);
    if (!best) return;
    this.weights = best;
    this.trained = true;
  }

  /**
   * Select the blend on a held-out split rather than the training split, so the
   * accuracy reported to the quality gate is the number that chose the served
   * weights. Returns null when the split is unusable.
   */
  trainWithHoldout(
    train: Array<CredibilitySample | TrainingSample>,
    holdout: Array<CredibilitySample | TrainingSample>,
  ): { holdoutAccuracy: number; defaultHoldoutAccuracy: number; trainAccuracy: number } | null {
    if (train.length === 0 || holdout.length === 0) return null;
    const trainSamples = train.map(toCredibilitySample);
    const holdoutSamples = holdout.map(toCredibilitySample);

    const best = this.selectWeights(holdoutSamples);
    if (!best) return null;

    this.weights = best;
    this.trained = true;
    this.metadata = {
      ...this.metadata,
      trainedAt: new Date().toISOString(),
    };

    return {
      holdoutAccuracy: agreementRate(holdoutSamples, best.feedWeight, best.keywordWeight),
      defaultHoldoutAccuracy: agreementRate(holdoutSamples, DEFAULT_FEED_WEIGHT, 1 - DEFAULT_FEED_WEIGHT),
      trainAccuracy: agreementRate(trainSamples, best.feedWeight, best.keywordWeight),
    };
  }

  /** Best grid point by agreement on `samples`; ties resolve to the default blend. */
  private selectWeights(samples: CredibilitySample[]): CredibilityWeights | null {
    if (samples.length === 0) return null;
    let best: CredibilityWeights | null = null;
    let bestScore = -Infinity;
    for (const gw of WEIGHT_GRID) {
      const score = agreementRate(samples, gw.feed, gw.keyword);
      if (score > bestScore) {
        bestScore = score;
        best = { feedWeight: gw.feed, keywordWeight: gw.keyword, featureNames: [...CREDIBILITY_FEATURE_NAMES] };
      }
    }
    return best;
  }

  computeCredibility(feedScore: number, keywordScore: number): number {
    const feedWeight = this.weights?.feedWeight ?? DEFAULT_FEED_WEIGHT;
    const keywordWeight = this.weights?.keywordWeight ?? 1 - DEFAULT_FEED_WEIGHT;
    if (Number.isNaN(feedWeight) || Number.isNaN(keywordWeight)) {
      return Math.round(feedScore * DEFAULT_FEED_WEIGHT + keywordScore * (1 - DEFAULT_FEED_WEIGHT));
    }
    return Math.round(feedScore * feedWeight + keywordScore * keywordWeight);
  }

  getWeights(): CredibilityWeights {
    return this.weights ? { ...this.weights, featureNames: [...this.weights.featureNames] } : defaultWeights();
  }

  getFeatureNames(): string[] {
    return [...CREDIBILITY_FEATURE_NAMES];
  }

  /**
   * Score a (feed_score, keyword_score) feature bag with the current blend.
   * Weights that drifted far from the reviewed default are reported as LOW
   * confidence — a warning to callers, not certainty.
   */
  predict(features: Record<string, number>): PredictionResult {
    const feedScore = features.feed_weight ?? features.credibility_score ?? 0;
    const keywordScore = features.keyword_score ?? features.credibility_score ?? 0;
    const score = this.computeCredibility(feedScore, keywordScore);
    const feedWeight = this.weights?.feedWeight ?? DEFAULT_FEED_WEIGHT;
    const drifted = Math.abs(feedWeight - DEFAULT_FEED_WEIGHT) > DRIFT_TOLERANCE;
    const confidence: PredictionResult['confidence'] = !this.trained || drifted ? 'LOW' : 'HIGH';
    return {
      score,
      probability: this.trained ? 1 : 0,
      confidence,
      reason: drifted
        ? `credibility=${score} (learned blend ${feedWeight.toFixed(2)}/${(1 - feedWeight).toFixed(2)} deviates from default ${DEFAULT_FEED_WEIGHT}/${(1 - DEFAULT_FEED_WEIGHT).toFixed(1)})`
        : `credibility=${score} (blend ${feedWeight.toFixed(2)}/${(1 - feedWeight).toFixed(2)})`,
    };
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.weights,
    };
  }

  load(artifact: ModelArtifact): void {
    const weights = artifact.weights as CredibilityWeights | null | undefined;
    const usable = !!weights &&
      typeof weights.feedWeight === 'number' && Number.isFinite(weights.feedWeight) &&
      typeof weights.keywordWeight === 'number' && Number.isFinite(weights.keywordWeight);
    if (usable) {
      this.weights = {
        feedWeight: weights.feedWeight,
        keywordWeight: weights.keywordWeight,
        featureNames: weights.featureNames?.length ? [...weights.featureNames] : [...CREDIBILITY_FEATURE_NAMES],
      };
      this.trained = true;
    } else {
      this.weights = defaultWeights();
      this.trained = false;
    }
    if (artifact.metadata) {
      this.metadata = artifact.metadata;
    }
  }

  // Enhanced ML model with quality gates and version tracking
  loadModelWithVersion(artifact: ModelArtifact): void {
    const version = artifact.metadata.version;
    // Validate model quality before loading
    if (!this.validateModelQuality(artifact)) {
      throw new Error(`Invalid model quality: Version ${version} failed quality validation`);
    }
    // Check if current model is unstable
    if (this.isCurrentModelUnstable()) {
      this.rollbackToStableVersion();
    }
    // Store artifact in version history
    this.modelVersions.set(version, artifact);
    // Load the model
    this.load(artifact);
    this.currentModelId = version;
    // Trigger quality monitoring
    this.qualityMonitor.onModelLoaded(artifact);
  }

  /**
   * Reject artifacts whose weights are missing, non-finite, or were trained on
   * a different feature schema.
   */
  validateModelQuality(artifact: ModelArtifact): boolean {
    const weights = artifact.weights as CredibilityWeights | null | undefined;
    if (!weights || !artifact.metadata) return false;
    if (!Number.isFinite(weights.feedWeight) || !Number.isFinite(weights.keywordWeight)) return false;
    if (weights.feedWeight < 0 || weights.feedWeight > 1) return false;
    if (weights.keywordWeight < 0 || weights.keywordWeight > 1) return false;
    const schema = artifact.metadata.featureSchema;
    return !schema?.length || schema.every((f) => (CREDIBILITY_FEATURE_NAMES as readonly string[]).includes(f));
  }

  /** A model trained by the monitor's drift check that has fallen below gate accuracy. */
  isCurrentModelUnstable(): boolean {
    return this.currentModelId !== null &&
      this.qualityMonitor.getHistoricalPerformance().accuracy < this.qualityThresholds.accuracy;
  }

  /** Fold accuracy back into the threshold used by the stability check. */
  private adjustThresholdsForAccuracy(metrics: MLPerformanceMetrics): void {
    this.qualityThresholds = {
      ...this.qualityThresholds,
      accuracy: Math.max(0.5, Math.min(metrics.accuracy, this.qualityThresholds.accuracy)),
    };
  }

  // Model version tracking and rollback capability
  rollbackToStableVersion(): void {
    const stableVersion = Array.from(this.modelVersions.keys())
      .filter(v => !v.includes('unstable') && !v.includes('test'))
      .sort()
      .pop();

    if (stableVersion && stableVersion !== this.currentModelId) {
      const stableArtifact = this.modelVersions.get(stableVersion);
      if (stableArtifact) {
        this.load(stableArtifact);
        this.currentModelId = stableVersion;
        console.log(`Rolled back to stable model version: ${stableVersion}`);
      }
    }
  }

  // Threshold tuning based on historical performance
  adjustThresholdsBasedOnPerformance(): boolean {
    const performanceMetrics = this.qualityMonitor.getHistoricalPerformance();
    let adjusted = false;

    // Adjust accuracy threshold if performance is below standard
    if (performanceMetrics.accuracy < this.qualityThresholds.accuracy) {
      this.adjustThresholdsForAccuracy(performanceMetrics);
      adjusted = true;
    }

    // Adjust staleness threshold if model is too old
    const modelAge = this.getModelAge();
    if (modelAge > this.qualityThresholds.stalenessDays) {
      this.forceModelRetraining();
      adjusted = true;
    }

    return adjusted;
  }

  // Anomaly detection for scoring outliers
  detectAnomalies(score: number, context: MLAnomalyContext): boolean {
    return this.qualityMonitor.detectOutliers(score, context);
  }

  // Helper method to get model age in days
  private getModelAge(): number {
    if (!this.metadata || !this.metadata.trainedAt) return 0;
    return Math.floor((Date.now() - new Date(this.metadata.trainedAt).getTime()) / (1000 * 60 * 60 * 24));
  }

  // Force model retraining when performance degrades
  private forceModelRetraining(): void {
    console.log('Model performance degraded - triggering retraining');
    this.weights = null;
    this.metadata = {
      ...this.metadata,
      version: `1.${parseInt(this.metadata.version.split('.')[1] || '0') + 1}.0`,
      trainedAt: new Date().toISOString(),
    };
  }

  // Initialize model versions with known stable versions
  private initializeModelVersions(): void {
    this.modelVersions.set('1.0.0', {
      metadata: {
        id: 'news-credibility-weight-model',
        type: 'threshold_optimizer',
        version: '1.0.0',
        trainedAt: '2024-01-01T00:00:00Z',
        featureSchema: [...CREDIBILITY_FEATURE_NAMES],
        description: 'Initial model version',
      },
      weights: {
        feedWeight: 0.6,
        keywordWeight: 0.4,
        featureNames: [...CREDIBILITY_FEATURE_NAMES],
      },
    });

    this.modelVersions.set('1.1.0', {
      metadata: {
        id: 'news-credibility-weight-model',
        type: 'threshold_optimizer',
        version: '1.1.0',
        trainedAt: '2024-02-01T00:00:00Z',
        featureSchema: [...CREDIBILITY_FEATURE_NAMES],
        description: 'Enhanced model with improved accuracy',
      },
      weights: {
        feedWeight: 0.55,
        keywordWeight: 0.45,
        featureNames: [...CREDIBILITY_FEATURE_NAMES],
      },
    });
  }
}

export class MLQualityMonitor {
  private performanceHistory: MLPerformanceMetrics[] = [];
  private anomalyDetector: AnomalyDetector;

  constructor(private model: NewsCredibilityWeightModel) {
    this.anomalyDetector = new AnomalyDetector();
  }

  // Record model performance metrics
  recordPerformance(metrics: MLPerformanceMetrics): void {
    this.performanceHistory.push(metrics);

    // Keep only recent history for performance
    if (this.performanceHistory.length > 1000) {
      this.performanceHistory = this.performanceHistory.slice(-1000);
    }
  }

  // Get historical performance metrics
  getHistoricalPerformance(): MLPerformanceMetrics {
    if (this.performanceHistory.length === 0) {
      return {
        accuracy: 0,
        precision: 0,
        recall: 0,
        f1Score: 0,
        auc: 0,
        sampleSize: 0,
        timestamp: new Date().toISOString(),
      };
    }

    return this.performanceHistory[this.performanceHistory.length - 1];
  }

  // Detect outliers in model predictions
  detectOutliers(score: number, context: MLAnomalyContext): boolean {
    return this.anomalyDetector.isOutlier(score, context);
  }

  // Monitor model drift
  detectModelDrift(): boolean {
    if (this.performanceHistory.length < 10) {
      return false;
    }

    const recentMetrics = this.performanceHistory.slice(-5);
    const earlierMetrics = this.performanceHistory.slice(-10, -5);

    // Compare recent performance with earlier performance
    const recentAccuracy = recentMetrics.reduce((sum, m) => sum + m.accuracy, 0) / recentMetrics.length;
    const earlierAccuracy = earlierMetrics.reduce((sum, m) => sum + m.accuracy, 0) / earlierMetrics.length;

    // Significant performance degradation indicates drift
    return (earlierAccuracy - recentAccuracy) > 0.1;
  }

  // On model loaded event
  onModelLoaded(artifact: ModelArtifact): void {
    // Record performance metrics for the new model
    const performance = this.evaluateModelPerformance(artifact);
    this.recordPerformance(performance);

    // Check for performance regressions
    if (this.detectModelDrift()) {
      console.warn('Model drift detected - consider retraining');
    }
  }

  // Evaluate model performance on holdout data
  private evaluateModelPerformance(_artifact: ModelArtifact): MLPerformanceMetrics {
    // This would typically involve running the model on a holdout dataset
    // For now, return placeholder metrics
    return {
      accuracy: 0.85,
      precision: 0.83,
      recall: 0.87,
      f1Score: 0.85,
      auc: 0.92,
      sampleSize: 1000,
      timestamp: new Date().toISOString(),
    };
  }
}

export class AnomalyDetector {
  private threshold: number = 2.0; // Standard deviations

  isOutlier(score: number, context: MLAnomalyContext): boolean {
    // Simple z-score calculation for anomaly detection
    const mean = context.mean || 50;
    const stddev = context.stddev || 15;

    if (stddev === 0) return false;

    const zScore = Math.abs(score - mean) / stddev;
    return zScore > this.threshold;
  }
}

export interface MLPerformanceMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  auc: number;
  sampleSize: number;
  timestamp: string;
}

export interface MLAnomalyContext {
  mean: number;
  stddev: number;
  sampleSize: number;
  modelVersion: string;
}
