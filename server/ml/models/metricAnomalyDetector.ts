/**
 * Metric Anomaly Detector — unsupervised isolation forest over Prometheus
 * pipeline telemetry gauges.
 *
 * File target: server/correlation/metrics.ts / server/correlation/runtime.ts
 *
 * Features drawn from existing gauges:
 *   vulnstream_correlation_memory_percent
 *   vulnstream_correlation_workers
 *   vulnstream_correlation_latency (derived from telemetry)
 *   vulnstream_correlation_dead_letters
 *   vulnstream_correlation_pending
 *
 * Auto-trains from the telemetry snapshot history stored by the supervisor.
 * No labels required.
 */
import { IsolationForest } from '../algorithms/isolationForest.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const METRIC_FEATURE_NAMES = [
  'memory_percent',
  'active_workers',
  'concurrency_ratio',
  'latency_ms',
  'dead_letters',
  'pending_claims',
  'items_per_second',
  'pool_waiting',
] as const;

export interface MetricFeatures {
  memoryPercent: number;
  activeWorkers: number;
  concurrencyLimit: number;
  latencyMs: number;
  deadLetters: number;
  pendingClaims: number;
  itemsPerSecond: number;
  poolWaiting: number;
}

export function extractMetricFeatures(raw: MetricFeatures): Record<string, number> {
  return {
    memory_percent: raw.memoryPercent,
    active_workers: raw.activeWorkers,
    concurrency_ratio: raw.concurrencyLimit > 0 ? raw.activeWorkers / raw.concurrencyLimit : 0,
    latency_ms: raw.latencyMs,
    dead_letters: raw.deadLetters,
    pending_claims: raw.pendingClaims,
    items_per_second: raw.itemsPerSecond,
    pool_waiting: raw.poolWaiting,
  };
}

export class MetricAnomalyDetectorModel extends BaseModel {
  private forest: IsolationForest;

  constructor() {
    const metadata: ModelMetadata = {
      id: 'metric-anomaly-detector',
      type: 'isolation_forest',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...METRIC_FEATURE_NAMES],
      description: 'Unsupervised anomaly detection over pipeline health telemetry',
    };
    super(metadata);
    this.forest = new IsolationForest();
  }

  train(samples: TrainingSample[]): void {
    const matrix = samples.map((s) =>
      METRIC_FEATURE_NAMES.map((name) => s.features[name] ?? 0),
    );
    this.forest.train(matrix, [...METRIC_FEATURE_NAMES], 100, 8, 0.1);
    this.trained = true;
  }

  predict(features: Record<string, number>): PredictionResult {
    const vec = METRIC_FEATURE_NAMES.map((name) => features[name] ?? 0);
    return this.forest.predict(vec);
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    const matrix = features.map((f) => METRIC_FEATURE_NAMES.map((name) => f[name] ?? 0));
    return this.forest.predictBatch(matrix);
  }

  isAnomaly(features: Record<string, number>): boolean {
    const vec = METRIC_FEATURE_NAMES.map((name) => features[name] ?? 0);
    return this.forest.isAnomaly(vec);
  }

  getThreshold(): number {
    return this.forest.getThreshold();
  }

  getFeatureNames(): string[] {
    return [...METRIC_FEATURE_NAMES];
  }

  override load(artifact: ModelArtifact): void {
    this.forest = new IsolationForest();
    const weights = artifact.weights as ReturnType<IsolationForest['serialize']>;
    this.forest.load(weights);
    this.metadata = artifact.metadata;
    this.trained = true;
  }

  override serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.forest.serialize(),
    };
  }

  /** Collects rolling telemetry snapshots from the supervisor's history. */
  static collectTrainingData(history: Array<{
    memoryPercent: number;
    activeWorkers: number;
    concurrencyLimit: number;
    latencyMs: number;
    deadLetters: number;
    pendingClaims: number;
    itemsPerSecond: number;
    poolWaiting: number;
  }>): TrainingSample[] {
    return history.map((sample, i) => ({
      id: `metric-${i}`,
      features: extractMetricFeatures({
        memoryPercent: sample.memoryPercent,
        activeWorkers: sample.activeWorkers,
        concurrencyLimit: sample.concurrencyLimit,
        latencyMs: sample.latencyMs,
        deadLetters: sample.deadLetters,
        pendingClaims: sample.pendingClaims,
        itemsPerSecond: sample.itemsPerSecond,
        poolWaiting: sample.poolWaiting,
      }),
      label: 0,
      weight: 1,
      timestamp: new Date().toISOString(),
    }));
  }
}
