/**
 * Delivery Optimizer — tunes the exponential backoff retry policy based on
 * historical delivery outcomes from the email delivery log.
 *
 * File target: delivery.ts:183-187 (emailRetryDelayMs / EmailRetryPolicy)
 *
 * The model records (provider, attempt_number, delay_ms, succeeded) tuples
 * from delivery confirmations and finds the backoff curve (initialDelay,
 * multiplier, maxDelay) that minimizes expected time-to-success while
 * respecting provider rate-limit behavior.
 *
 * This is a 1-D optimizer over the backoff parameters, constrained by the
 * existing policy shape (min 1m, max 10080m, multiplier 2).
 */
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export interface DeliveryOutcome {
  provider: string;
  attempt: number;
  delayMs: number;
  succeeded: boolean;
  isRateLimited: boolean;
  isPermanentFailure: boolean;
}

interface BackoffPoint {
  attempt: number;
  initialDelayMinutes: number;
  backoffMultiplier: number;
  maxDelayMinutes: number;
  successRate: number;
  avgDelayToSuccess: number;
  rateLimitRate: number;
}

interface DeliveryOptimizerWeights {
  providerCurves: Record<string, BackoffPoint[]>;
  bestPolicy: {
    initialDelayMinutes: number;
    backoffMultiplier: number;
    maxDelayMinutes: number;
    maxAttempts: number;
  };
  featureNames: string[];
}

const FEATURE_NAMES = ['provider_type', 'attempt', 'delay_minutes', 'rate_limited', 'hour_of_day'] as const;

export class DeliveryOptimizerModel {
  private weights: DeliveryOptimizerWeights | null = null;
  private metadata: ModelMetadata;
  private outcomes: DeliveryOutcome[] = [];
  private readonly maxHistory = 5000;

  constructor() {
    this.metadata = {
      id: 'delivery-optimizer',
      type: 'threshold_optimizer',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...FEATURE_NAMES],
      description: 'Optimal backoff retry policy from delivery outcome history',
    };
  }

  /** Records a delivery outcome for policy tuning. Called from delivery.ts confirmation. */
  record(outcome: DeliveryOutcome): void {
    this.outcomes.push(outcome);
    if (this.outcomes.length > this.maxHistory) {
      this.outcomes = this.outcomes.slice(this.outcomes.length - this.maxHistory);
    }
  }

  train(samples: TrainingSample[] = []): void {
    const outcomes = [...this.outcomes, ...samples.map((s) => ({
      provider: s.id.split(':')[0] || 'unknown',
      attempt: s.features.attempt ? Math.max(1, Math.round(s.features.attempt)) : 1,
      delayMs: s.features.delay_ms || 0,
      succeeded: s.label === 1 || s.label === true,
      isRateLimited: s.features.rate_limited > 0.5,
      isPermanentFailure: s.features.permanent_failure > 0.5,
    } as DeliveryOutcome))];

    if (outcomes.length < 50) return;

    const providers = new Set(outcomes.map((o) => o.provider));
    const providerCurves: Record<string, BackoffPoint[]> = {};

    for (const provider of providers) {
      const providerOutcomes = outcomes.filter((o) => o.provider === provider);
      const maxAttempt = Math.max(...providerOutcomes.map((o) => o.attempt));

      const curves: BackoffPoint[] = [];
      for (const attempt of Array.from({ length: maxAttempt }, (_, i) => i + 1)) {
        const attemptOutcomes = providerOutcomes.filter((o) => o.attempt === attempt);
        const succeeded = attemptOutcomes.filter((o) => o.succeeded);
        const rateLimited = attemptOutcomes.filter((o) => o.isRateLimited);
        const successRate = attemptOutcomes.length > 0 ? succeeded.length / attemptOutcomes.length : 0;
        const avgDelay = succeeded.length > 0 ? succeeded.reduce((sum, o) => sum + o.delayMs, 0) / succeeded.length : 0;
        const rateLimitRate = attemptOutcomes.length > 0 ? rateLimited.length / attemptOutcomes.length : 0;

        curves.push({
          attempt,
          initialDelayMinutes: 0,
          backoffMultiplier: 2,
          maxDelayMinutes: 1440,
          successRate,
          avgDelayToSuccess: avgDelay,
          rateLimitRate,
        });
      }
      providerCurves[provider] = curves;
    }

    const best = this.findBestPolicy(outcomes);
    this.weights = {
      providerCurves,
      bestPolicy: best,
      featureNames: [...FEATURE_NAMES],
    };
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  private findBestPolicy(outcomes: DeliveryOutcome[]): DeliveryOptimizerWeights['bestPolicy'] {
    let bestCost = Infinity;
    let best: DeliveryOptimizerWeights['bestPolicy'] = {
      initialDelayMinutes: 5,
      backoffMultiplier: 2,
      maxDelayMinutes: 1440,
      maxAttempts: 5,
    };

    const initialDelays = [1, 3, 5, 10, 15, 30];
    const multipliers = [1.5, 2, 2.5, 3];
    const maxDelays = [60, 1440, 2880];
    const maxAttempts = [3, 5, 10];

    for (const initDelay of initialDelays) {
      for (const mult of multipliers) {
        for (const maxDelay of maxDelays) {
          for (const maxAtt of maxAttempts) {
            const cost = this.simulatePolicy(outcomes, initDelay, mult, maxDelay, maxAtt);
            if (cost < bestCost) {
              bestCost = cost;
              best = { initialDelayMinutes: initDelay, backoffMultiplier: mult, maxDelayMinutes: maxDelay, maxAttempts: maxAtt };
            }
          }
        }
      }
    }
    return best;
  }

  private simulatePolicy(outcomes: DeliveryOutcome[], initDelay: number, mult: number, maxDelay: number, maxAtt: number): number {
    let totalCost = 0;
    let successCount = 0;
    const byProvider = new Map<string, DeliveryOutcome[]>();
    for (const o of outcomes) {
      const arr = byProvider.get(o.provider) ?? [];
      arr.push(o);
      byProvider.set(o.provider, arr);
    }

    for (const [, providerOutcomes] of byProvider) {
      const attemptSuccessRates = this.computeAttemptSuccessRates(providerOutcomes, maxAtt);
      let cumulativeDelay = 0;
      let providerCost = 0;
      let succeeded = false;
      for (let attempt = 1; attempt <= maxAtt; attempt++) {
        const delay = Math.min(maxDelay * 60_000, initDelay * 60_000 * mult ** (attempt - 1));
        cumulativeDelay += delay;
        const successProb = attemptSuccessRates[attempt] ?? 0;
        providerCost += cumulativeDelay * successProb;
        succeeded = true;
      }
      if (succeeded) successCount++;
      totalCost += providerCost;
    }

    if (successCount === 0) return Infinity;
    return totalCost / successCount;
  }

  private computeAttemptSuccessRates(outcomes: DeliveryOutcome[], maxAttempt: number): Record<number, number> {
    const rates: Record<number, number> = {};
    for (let a = 1; a <= maxAttempt; a++) {
      const atAttempt = outcomes.filter((o) => o.attempt === a);
      if (atAttempt.length === 0) {
        rates[a] = 0;
        continue;
      }
      rates[a] = atAttempt.filter((o) => o.succeeded).length / atAttempt.length;
    }
    return rates;
  }

  /** Returns the optimal initial delay (minutes) for the given provider. */
  getInitialDelay(_provider?: string): number {
    if (!this.weights) return 5;
    return this.weights.bestPolicy.initialDelayMinutes;
  }

  /** Returns the optimal backoff multiplier. */
  getBackoffMultiplier(): number {
    if (!this.weights) return 2;
    return this.weights.bestPolicy.backoffMultiplier;
  }

  /** Returns the optimal max delay (minutes). */
  getMaxDelayMinutes(): number {
    if (!this.weights) return 1440;
    return this.weights.bestPolicy.maxDelayMinutes;
  }

  /** Returns the optimal max attempts. */
  getMaxAttempts(): number {
    if (!this.weights) return 5;
    return this.weights.bestPolicy.maxAttempts;
  }

  /** Computes the delay for a given attempt using the learned policy. */
  computeDelay(attempt: number): number {
    if (!this.weights) {
      return Math.min(1440 * 60_000, 5 * 60_000 * 2 ** Math.max(0, attempt - 1));
    }
    const { initialDelayMinutes, backoffMultiplier, maxDelayMinutes } = this.weights.bestPolicy;
    return Math.min(
      maxDelayMinutes * 60_000,
      initialDelayMinutes * 60_000 * backoffMultiplier ** Math.max(0, attempt - 1),
    );
  }

  /** Predicts whether a delivery attempt at this delay would likely succeed. */
  predict(features: Record<string, number>): PredictionResult {
    const attempt = features.attempt || 1;
    const provider = features.provider_type || 0;
    const delayMin = features.delay_minutes || 0;
    if (!this.weights) {
      return { score: 0.5, confidence: 'LOW', reason: 'optimizer untrained — using default policy' };
    }
    const curve = this.weights.providerCurves[provider.toString()];
    if (!curve) {
      return { score: 0.5, confidence: 'LOW', reason: 'provider unknown to optimizer' };
    }
    const point = curve.find((p) => p.attempt === attempt);
    const score = point ? point.successRate : 0;
    const confidence: PredictionResult['confidence'] = Math.abs(score - 0.5) > 0.3 ? 'HIGH' : 'MEDIUM';
    return { score, confidence, reason: `provider=${provider} attempt=${attempt} delay=${delayMin}m successRate=${score.toFixed(3)}` };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.weights ?? {
        providerCurves: {},
        bestPolicy: { initialDelayMinutes: 5, backoffMultiplier: 2, maxDelayMinutes: 1440, maxAttempts: 5 },
        featureNames: [...FEATURE_NAMES],
      },
    };
  }

  load(artifact: ModelArtifact): void {
    this.weights = artifact.weights as DeliveryOptimizerWeights;
    this.metadata = artifact.metadata;
  }

  getFeatureNames(): string[] {
    return [...FEATURE_NAMES];
  }

  getMetadata(): ModelMetadata {
    return this.metadata;
  }

  isTrained(): boolean {
    return this.weights !== null;
  }

  /** Returns the decision curve for a provider for monitoring/debugging. */
  getProviderCurve(provider: string): BackoffPoint[] | undefined {
    return this.weights?.providerCurves[provider];
  }

  /** Generates training data from delivery log outcomes. */
  static collectTrainingData(outcomes: DeliveryOutcome[]): TrainingSample[] {
    return outcomes.map((o, i) => ({
      id: `${o.provider}:${i}`,
      features: {
        provider_type: o.provider === 'smtp' ? 1 : o.provider === 'sendgrid' ? 2 : o.provider === 'ses' ? 3 : 0,
        attempt: o.attempt,
        delay_ms: o.delayMs,
        delay_minutes: o.delayMs / 60_000,
        rate_limited: o.isRateLimited ? 1 : 0,
        permanent_failure: o.isPermanentFailure ? 1 : 0,
        hour_of_day: new Date().getHours(),
      },
      label: o.succeeded ? 1 : 0,
      weight: 1,
      timestamp: new Date().toISOString(),
    }));
  }
}
