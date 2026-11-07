/**
 * Feed Recovery Backoff Optimizer — learns the optimal exponential backoff
 * parameters for feed recovery, replacing the hardcoded backoff in
 * feedRecovery.ts:12.
 *
 * File target: server/feedRecovery.ts:12 (recoveryAt)
 *
 * The current hardcoded backoff is:
 *   base = (recoveryDelayMinutes ?? 5) * 60000
 *   delay = max(base, min(3600000, base * 2^min(6, failures - 1)))
 *
 * This model learns (initialDelay, multiplier, maxDelay, maxSteps) by
 * finding the curve that maximizes recovery success rate while minimizing
 * recovery latency, following the same threshold_optimizer pattern as
 * AutoDispatchThresholdModel and DeliveryOptimizerModel.
 *
 * Training data: feed health transition history (DOWN→UP timing and success).
 */
import type { ModelMetadata, ModelArtifact, PredictionResult } from '../types.ts';

export interface FeedRecoverySample {
  feedType: string;
  provider: string;
  timeOfDay: number;
  failureCount: number;
  delayMinutes: number;
  recovered: boolean;
  recoveryLatencyMinutes: number;
  observedAt?: string;
}

export interface FeedRecoveryWeights {
  bestPolicy: {
    initialDelayMinutes: number;
    backoffMultiplier: number;
    maxDelayMinutes: number;
    maxSteps: number;
    maxAttempts: number;
  };
  curve: Array<{
    initialDelayMinutes: number;
    backoffMultiplier: number;
    maxDelayMinutes: number;
    maxSteps: number;
    maxAttempts: number;
    recoveryRate: number;
    avgLatencyMinutes: number;
    score: number;
  }>;
  featureNames: string[];
}

export const FEED_RECOVERY_FEATURE_NAMES = ['failure_count', 'delay_minutes', 'time_of_day'] as const;

export class FeedRecoveryBackoffOptimizer {
  private weights: FeedRecoveryWeights | null = null;
  private metadata: ModelMetadata;
  private history: FeedRecoverySample[] = [];
  private readonly maxHistory = 3000;

  constructor() {
    this.metadata = {
      id: 'feed-recovery-backoff-optimizer',
      type: 'threshold_optimizer',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...FEED_RECOVERY_FEATURE_NAMES],
      description: 'Learns optimal backoff parameters for feed recovery probes',
    };
  }

  record(sample: FeedRecoverySample): void {
    this.history.push(sample);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(this.history.length - this.maxHistory);
    }
  }

  train(samples: FeedRecoverySample[] = this.history): void {
    if (samples.length < 20) return;

    const initialDelays = [2, 5, 10, 15];
    const multipliers = [1.5, 2, 3];
    const maxDelays = [30, 60, 120, 240, 1440];
    const maxSteps = [4, 5, 6, 8];

    const curves: FeedRecoveryWeights['curve'] = [];

    for (const init of initialDelays) {
      for (const mult of multipliers) {
        for (const maxDelay of maxDelays) {
          for (const steps of maxSteps) {
            let successes = 0;
            let totalLatency = 0;
            let totalSamples = 0;

            for (const s of samples) {
              const predictedDelay = this.simulateDelay(s.failureCount, init, mult, maxDelay, steps);
              if (predictedDelay >= s.delayMinutes * 0.5 && predictedDelay <= s.delayMinutes * 1.5) {
                totalSamples++;
                if (s.recovered) {
                  successes++;
                  totalLatency += s.recoveryLatencyMinutes;
                }
              }
            }

            if (totalSamples > 0) {
              const recoveryRate = successes / totalSamples;
              const avgLatencyMinutes = totalLatency / Math.max(1, successes);
              const score = recoveryRate * 0.7 + (1 - avgLatencyMinutes / 1440) * 0.3;
              curves.push({
                initialDelayMinutes: init,
                backoffMultiplier: mult,
                maxDelayMinutes: maxDelay,
                maxSteps: steps,
                maxAttempts: steps + 2,
                recoveryRate,
                avgLatencyMinutes,
                score,
              });
            }
          }
        }
      }
    }

    curves.sort((a, b) => b.score - a.score);
    const best = curves[0];

    if (best) {
      this.weights = {
        bestPolicy: {
          initialDelayMinutes: best.initialDelayMinutes,
          backoffMultiplier: best.backoffMultiplier,
          maxDelayMinutes: best.maxDelayMinutes,
          maxSteps: best.maxSteps,
          maxAttempts: best.maxAttempts,
        },
        curve: curves.slice(0, 10),
        featureNames: [...FEED_RECOVERY_FEATURE_NAMES],
      };
    }
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  private simulateDelay(attempt: number, init: number, mult: number, maxDelay: number, maxSteps: number): number {
    if (attempt <= 1) return init;
    const steps = Math.min(maxSteps, attempt - 1);
    let delay = init * Math.pow(mult, steps - 1);
    delay = Math.min(delay, maxDelay);
    return delay;
  }

  getPolicy(): { initialDelayMinutes: number; backoffMultiplier: number; maxDelayMinutes: number; maxSteps: number; maxAttempts: number } {
    return this.weights?.bestPolicy ?? {
      initialDelayMinutes: 5,
      backoffMultiplier: 2,
      maxDelayMinutes: 1440,
      maxSteps: 6,
      maxAttempts: 5,
    };
  }

  computeRecoveryDelay(failures: number): number {
    const policy = this.getPolicy();
    const delay = this.simulateDelay(failures, policy.initialDelayMinutes, policy.backoffMultiplier, policy.maxDelayMinutes, policy.maxSteps);
    return delay * 60_000;
  }

  predict(failures: number): PredictionResult {
    const policy = this.getPolicy();
    const delayMs = this.computeRecoveryDelay(failures);
    const confidence: PredictionResult['confidence'] = this.weights ? 'HIGH' : 'LOW';
    return {
      score: delayMs / 60_000,
      probability: 1,
      confidence,
      reason: `delay=${(delayMs / 60_000).toFixed(1)}min (policy: init=${policy.initialDelayMinutes}, mult=${policy.backoffMultiplier}, max=${policy.maxDelayMinutes})`,
    };
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.weights ?? {
        bestPolicy: {
          initialDelayMinutes: 5,
          backoffMultiplier: 2,
          maxDelayMinutes: 1440,
          maxSteps: 6,
          maxAttempts: 5,
        },
        curve: [],
        featureNames: [...FEED_RECOVERY_FEATURE_NAMES],
      },
    };
  }

  load(artifact: ModelArtifact): void {
    this.weights = artifact.weights as FeedRecoveryWeights;
    this.metadata = artifact.metadata;
  }

  getFeatureNames(): string[] {
    return [...FEED_RECOVERY_FEATURE_NAMES];
  }

  getRecoveryRate(): number {
    if (!this.weights?.curve?.length) return 0;
    const best = this.weights.curve[0];
    return best.recoveryRate || 0;
  }

  getMetadata(): ModelMetadata {
    return this.metadata;
  }

  isTrained(): boolean {
    return this.weights !== null;
  }
}
