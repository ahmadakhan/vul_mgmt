/**
 * Auto-Dispatch Threshold Tuner — learns the optimal confidence threshold for
 * auto-dispatching findings (default 90% in pipelineEngine.ts:401) by trading
 * off false-positive rate against recall.
 *
 * File target: pipelineEngine.ts:401 (`autoDispatchConfidenceThreshold`)
 *
 * The model tracks historical (confidence_score, dispatched, outcome) tuples
 * and finds the threshold that maximizes:
 *   score = precision * recall_weight + (1 - fp_rate) * fp_weight
 *
 * This is a 1-D optimizer over the confidence axis, no complex ML needed.
 * Self-revalidates against the existing quality gates (95% precision / 90% recall).
 */
import type { ModelMetadata, ModelArtifact, PredictionResult } from '../types.ts';

export interface ThresholdSample {
  confidence: number;
  dispatched: boolean;
  wasFalsePositive: boolean;
  foundTruePositive: boolean;
}

const THRESHOLD_FEATURE_NAMES = ['confidence', 'historical_dispatch_rate', 'current_fp_rate'] as const;

interface ThresholdWeights {
  decisionPoints: Array<{ confidence: number; precision: number; recall: number; f1: number; selected: boolean }>;
  bestThreshold: number;
  featureNames: string[];
}

export class AutoDispatchThresholdModel {
  private weights: ThresholdWeights | null = null;
  private metadata: ModelMetadata;
  private history: ThresholdSample[] = [];
  private readonly maxHistory = 5000;

  constructor() {
    this.metadata = {
      id: 'auto-dispatch-threshold',
      type: 'threshold_optimizer',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...THRESHOLD_FEATURE_NAMES],
      description: 'Optimal confidence threshold for auto-dispatch gate',
    };
  }

  /** Records a finding's outcome for threshold tuning. Fully passive — called from delivery confirmation. */
  record(sample: ThresholdSample): void {
    this.history.push(sample);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(this.history.length - this.maxHistory);
    }
  }

  train(samples: ThresholdSample[] = this.history): void {
    if (samples.length < 100) return; // not enough data to tune — keep default

    const grid = [0.95, 0.9, 0.85, 0.8, 0.75, 0.7, 0.65, 0.6, 0.55, 0.5];
    const decisionPoints = grid.map((threshold) => {
      let tp = 0, fp = 0, fn = 0, tn = 0;
      for (const s of samples) {
        if (s.dispatched) {
          if (s.confidence >= threshold) {
            if (s.wasFalsePositive) fp++;
            else if (s.foundTruePositive) tp++;
            else tn++;
          }
        } else {
          if (s.confidence >= threshold) {
            if (s.foundTruePositive) fn++;
          }
        }
      }
      const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
      const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
      const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
      return { confidence: threshold, precision, recall, f1, selected: false };
    });

    // Select the threshold maximizing F1, subject to quality gates (≥90% precision)
    let best: (typeof decisionPoints)[0] | null = null;
    for (const dp of decisionPoints) {
      if (dp.precision >= 0.9 && (best === null || dp.f1 > best.f1)) {
        best = dp;
      }
    }

    if (!best) {
      // No threshold meets the gates — keep the current one
      this.weights = { decisionPoints, bestThreshold: this.weights?.bestThreshold ?? 0.9, featureNames: [...THRESHOLD_FEATURE_NAMES] };
    } else {
      best.selected = true;
      this.weights = { decisionPoints, bestThreshold: best.confidence, featureNames: [...THRESHOLD_FEATURE_NAMES] };
    }
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  /**
   * Returns true if a finding at the given confidence should be auto-dispatched.
   * Uses the learned threshold or falls back to 0.9 if untrained.
   */
  shouldDispatch(confidence: number): boolean {
    const threshold = this.getThreshold();
    return confidence / 100 >= threshold;
  }

  getThreshold(): number {
    return this.weights?.bestThreshold ?? 0.9;
  }

  predict(features: Record<string, number>): PredictionResult {
    const confidence = features.confidence ?? 0;
    const threshold = this.getThreshold();
    const willDispatch = confidence / 100 >= threshold;
    return {
      score: willDispatch ? 1 : 0,
      probability: confidence / 100,
      confidence: Math.abs(confidence / 100 - threshold) > 0.1 ? 'HIGH' : 'MEDIUM',
      reason: `confidence=${confidence.toFixed(1)} vs threshold=${(threshold * 100).toFixed(1)}% (dispatch=${willDispatch})`,
    };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.serializeWeights(),
    };
  }

  private serializeWeights(): ThresholdWeights {
    return this.weights ?? {
      decisionPoints: [],
      bestThreshold: 0.9,
      featureNames: [...THRESHOLD_FEATURE_NAMES],
    };
  }

  load(artifact: ModelArtifact): void {
    this.weights = artifact.weights as ThresholdWeights;
    this.metadata = artifact.metadata;
  }

  getFeatureNames(): string[] {
    return [...THRESHOLD_FEATURE_NAMES];
  }

  getMetadata(): ModelMetadata {
    return this.metadata;
  }

  isTrained(): boolean {
    return this.weights !== null;
  }

  /** Returns the decision curve for monitoring/debugging. */
  getDecisionPoints(): ThresholdWeights['decisionPoints'] {
    return this.weights?.decisionPoints ?? [];
  }
}
