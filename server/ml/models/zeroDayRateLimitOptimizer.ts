/**
 * Zero-Day Rate Limit Optimizer — learns the optimal cap on zero-day
 * matches per pipeline run, replacing the hardcoded
 * `MAX_ZERO_DAYS_PER_RUN = 50` in pipelineEngine.ts:101.
 *
 * File target: src/engine/pipelineEngine.ts:101 (MAX_ZERO_DAYS_PER_RUN)
 *
 * Uses a grid-search optimizer over cap values, finding the cap that
 * maximizes the true-positive rate while minimizing the false-positive rate
 * from the dropped (digest-consolidated) matches. This follows the same
 * threshold_optimizer pattern as AutoDispatchThresholdModel.
 *
 * Training data: pipeline runs where zero-day finds exceeded the cap,
 * with credibility scores and known outcomes.
 */
import type { ModelMetadata, ModelArtifact, PredictionResult } from '../types.ts';

export interface ZeroDayRateLimitSample {
  zeroDayCount: number;
  credibilityScores: number[];
  outcomes: Array<'TIDY' | 'PATCHED' | 'RESOLVED' | 'DELIVERED' | 'FALSE_POSITIVE'>;
}

export interface ZeroDayRateLimitWeights {
  bestCap: number;
  decisionPoints: Array<{
    cap: number;
    keptTruePositiveRate: number;
    droppedFalsePositiveRate: number;
    score: number;
    selected: boolean;
  }>;
  featureNames: string[];
}

export const ZERO_DAY_RATE_LIMIT_FEATURE_NAMES = ['zero_day_count', 'avg_credibility'] as const;

export class ZeroDayRateLimitOptimizer {
  private weights: ZeroDayRateLimitWeights | null = null;
  private metadata: ModelMetadata;
  private history: ZeroDayRateLimitSample[] = [];
  private readonly maxHistory = 2000;

  constructor() {
    this.metadata = {
      id: 'zero-day-rate-limit-optimizer',
      type: 'threshold_optimizer',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...ZERO_DAY_RATE_LIMIT_FEATURE_NAMES],
      description: 'Optimal cap on zero-day findings per pipeline run',
    };
  }

  record(sample: ZeroDayRateLimitSample): void {
    this.history.push(sample);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(this.history.length - this.maxHistory);
    }
  }

  train(samples: ZeroDayRateLimitSample[] = this.history): void {
    const validSamples = samples.filter((sample) =>
      Number.isInteger(sample.zeroDayCount) && sample.zeroDayCount >= 0 &&
      sample.credibilityScores.length === sample.zeroDayCount &&
      sample.outcomes.length === sample.zeroDayCount,
    );
    if (validSamples.length < 20) return;

    const caps = [10, 20, 30, 40, 50, 75, 100, 150, 200, 300];
    const threshold = 50;

    const decisionPoints = caps.map((cap) => {
      let truePositives = 0;
      let falsePositives = 0;
      let keptTotal = 0;
      let droppedTotal = 0;
      let droppedTruePositives = 0;

      for (const s of validSamples) {
        const total = s.zeroDayCount;
        const ranked = s.credibilityScores
          .map((score, index) => ({ score, outcome: s.outcomes[index] }))
          .sort((a, b) => b.score - a.score);
        const keptCount = Math.min(cap, total);
        const droppedCount = total - keptCount;

        for (let i = 0; i < keptCount; i++) {
          const outcome = ranked[i]?.outcome;
          if (outcome === 'PATCHED' || outcome === 'RESOLVED' || outcome === 'DELIVERED') {
            truePositives++;
          } else {
            falsePositives++;
          }
          keptTotal++;
        }

        for (let i = 0; i < droppedCount; i++) {
          const outcome = ranked[keptCount + i]?.outcome;
          if (outcome === 'PATCHED' || outcome === 'RESOLVED' || outcome === 'DELIVERED') {
            droppedTruePositives++;
          }
          droppedTotal++;
        }
      }

      const keptTruePositiveRate = keptTotal > 0 ? truePositives / keptTotal : 0;
      const droppedFalsePositiveRate = droppedTotal > 0
        ? (droppedTotal - droppedTruePositives) / droppedTotal
        : 0;

      const score = keptTruePositiveRate - droppedFalsePositiveRate * 0.5;

      return {
        cap,
        keptTruePositiveRate,
        droppedFalsePositiveRate,
        score,
        selected: false,
      };
    });

    const best = decisionPoints.reduce((best, dp) => (dp.score > best.score ? dp : best));
    best.selected = true;

    this.weights = {
      bestCap: best.cap,
      decisionPoints,
      featureNames: [...ZERO_DAY_RATE_LIMIT_FEATURE_NAMES],
    };
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  getCap(): number {
    return this.weights?.bestCap ?? 50;
  }

  predict(zeroDayCount: number, credibilityScores: number[]): PredictionResult {
    const cap = this.getCap();
    const willExceed = zeroDayCount > cap;

    const confidence: PredictionResult['confidence'] = willExceed ? 'HIGH' : 'LOW';
    return {
      score: willExceed ? 1 : 0,
      probability: willExceed ? 1 : 0,
      confidence,
      reason: `zero_day_count=${zeroDayCount} vs learned cap=${cap} (exceeds=${willExceed})`,
    };
  }

  shouldTruncate(count: number, credibilityScores: number[]): { truncate: boolean; cap: number } {
    const cap = this.getCap();
    return { truncate: count > cap, cap };
  }

  getDecisionPoints(): ZeroDayRateLimitWeights['decisionPoints'] {
    return this.weights?.decisionPoints ?? [];
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.weights ?? {
        bestCap: 50,
        decisionPoints: [],
        featureNames: [...ZERO_DAY_RATE_LIMIT_FEATURE_NAMES],
      },
    };
  }

  load(artifact: ModelArtifact): void {
    this.weights = artifact.weights as ZeroDayRateLimitWeights;
    this.metadata = artifact.metadata;
  }

  getFeatureNames(): string[] {
    return [...ZERO_DAY_RATE_LIMIT_FEATURE_NAMES];
  }

  getMetadata(): ModelMetadata {
    return this.metadata;
  }

  isTrained(): boolean {
    return this.weights !== null;
  }

  static collectTrainingData(samples: Array<{
    zeroDayCount: number;
    credibilityScores: number[];
    outcomes: Array<'TIDY' | 'PATCHED' | 'RESOLVED' | 'DELIVERED' | 'FALSE_POSITIVE'>;
  }>): ZeroDayRateLimitSample[] {
    return samples;
  }
}
