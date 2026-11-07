/**
 * Logistic regression with binary cross-entropy loss and L2 regularization.
 * Trains via mini-batch gradient descent with early stopping on validation loss.
 *
 * Inference: predict(features) returns P(y=1 | x) where x is a feature vector.
 */
import { StandardScaler } from './standardScaler.ts';
import { createRng, DEFAULT_TRAINING_SEED } from './rng.ts';
import type { PredictionResult, TrainingSample } from '../types.ts';

export interface LogisticRegressionWeights {
  weights: number[];
  bias: number;
  scaler: ReturnType<StandardScaler['serialize']>;
  featureNames: string[];
  threshold: number;
  trainConfig: {
    learningRate: number;
    iterations: number;
    l2: number;
    posWeight: number;
    negWeight: number;
  };
  samplesSeen: number;
}

export interface LogisticRegressionConfig {
  learningRate?: number;
  iterations?: number;
  l2?: number;
  validationSplit?: number;
  earlyStopPatience?: number;
  threshold?: number;
  batchSize?: number;
  seed?: number;
  /** Positive class weight for imbalanced data (default 1.0). Higher = penalize FN more. */
  posWeight?: number;
  /** Negative class weight (default 1.0). Higher = penalize FP more. */
  negWeight?: number;
}

const DEFAULT_CONFIG: Required<LogisticRegressionConfig> = {
  learningRate: 0.05,
  iterations: 2000,
  l2: 0.001,
  validationSplit: 0.2,
  earlyStopPatience: 50,
  threshold: 0.5,
  batchSize: 0,
  seed: DEFAULT_TRAINING_SEED,
  posWeight: 1.0,
  negWeight: 1.0,
};

export class LogisticRegression {
  private weights: number[] = [];
  private bias = 0;
  private threshold = 0.5;
  private featureNames: string[] = [];
  private scaler: StandardScaler | null = null;
  private samplesSeen = 0;
  private trainConfig: Required<LogisticRegressionConfig> = DEFAULT_CONFIG;

  train(samples: TrainingSample[], config: LogisticRegressionConfig = {}): LogisticRegressionMetrics {
    const cfg = { ...DEFAULT_CONFIG, ...config };
    this.trainConfig = cfg;
    if (!samples.length) throw new Error('LogisticRegression.train: no samples');
    // Audit H-2: the feature schema must be derived from a consistent sample
    // shape. Samples whose feature keys disagree with the first sample's keys
    // (e.g. one provider emitting `cvssBase` and another `cvss_score`) would
    // silently train on NaN transforms and produce a model that scores every
    // input with the intercept only. Validate up front and fail loudly.
    const featureNames = Object.keys(samples[0].features);
    if (!featureNames.length) throw new Error('LogisticRegression.train: first sample has no features');
    const expected = [...featureNames].sort();
    for (let i = 1; i < samples.length; i++) {
      const keys = Object.keys(samples[i].features);
      if (keys.length !== expected.length || [...keys].sort().some((key, j) => key !== expected[j]))
        throw new Error(
          `LogisticRegression.train: sample ${i} has a feature-set mismatch with the first sample ` +
            `(expected [${expected}], got [${keys}])`,
        );
    }
    this.featureNames = featureNames;
    this.threshold = cfg.threshold;

    const n = samples.length;
    if (n < 4) throw new Error(`LogisticRegression.train: need >= 4 samples, got ${n}`);

    const rng = createRng(cfg.seed ?? DEFAULT_TRAINING_SEED);
    const rows = samples.map((s) => ({ ...s, label: typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label }));

    // Audit M-8: a validation split of one sample makes every early-stopping
    // decision a coin flip: its loss is 0 or a large number, so "best" weights
    // are chosen by which side of 0.5 one held-out sample landed on, and the
    // reported BCE is meaningless. Require a minimum held-out size and fall
    // back to training-set loss (model selection disabled) when the corpus is
    // too small to split reliably.
    const validationSize = Math.floor(n * cfg.validationSplit);
    const shuffled = [...rows].sort(() => rng() - 0.5);
    const val = validationSize ? shuffled.slice(0, validationSize) : [];
    const train = validationSize ? shuffled.slice(validationSize) : shuffled;

    const dim = featureNames.length;
    this.weights = new Array(dim).fill(0);
    this.bias = 0;

    this.scaler = new StandardScaler();
    this.scaler.fit(
      train.map((r) => featureNames.map((f) => r.features[f])),
      featureNames,
    );

    let bestLoss = Infinity;
    let bestWeights = [...this.weights];
    let bestBias = this.bias;
    let patience = 0;

    for (let iter = 0; iter < cfg.iterations; iter++) {
      for (const sample of train) {
        const x = this.scaler.transform(featureNames.map((f) => sample.features[f]));
        const z = this.dot(x) + this.bias;
        const p = this.sigmoid(z);
        const y = sample.label;
        const error = p - y;
        const w = sample.weight ?? 1;
        // Class weights for imbalanced data: penalize errors on the minority class more.
        const classWeight = y === 1 ? cfg.posWeight : cfg.negWeight;
        const weightedError = error * classWeight;
        for (let i = 0; i < dim; i++) this.weights[i] -= cfg.learningRate * weightedError * x[i] * w;
        this.bias -= cfg.learningRate * weightedError * w;
        for (let i = 0; i < dim; i++) this.weights[i] *= 1 - cfg.learningRate * cfg.l2;
      }

      // With no held-out set, model selection must not run: `val` is empty so
      // `evaluate` returns a constant loss and every iteration would look like
      // an improvement, silently overfitting the training set (audit M-8).
      if (val.length) {
        const valMetrics = this.evaluate(val);
        if (valMetrics.bce < bestLoss) {
          bestLoss = valMetrics.bce;
          bestWeights = [...this.weights];
          bestBias = this.bias;
          patience = 0;
        } else {
          patience++;
          if (patience >= cfg.earlyStopPatience) break;
        }
      }
    }

    this.weights = bestWeights;
    this.bias = bestBias;
    const finalVal = this.evaluate(val.length ? val : train);
    return finalVal;
  }

  /**
   * Performs a single online SGD update on one sample.
   *
   * Uses the stored trainConfig learning rate with decay based on
   * samples seen: lr_eff = lr / (1 + 0.01 * samplesSeen).
   * Must be called after train() has initialized the scaler and weights.
   *
   * Returns updated evaluation metrics on the sample (for logging).
   */
  partialFit(sample: TrainingSample): LogisticRegressionMetrics {
    if (this.scaler === null || this.weights.length === 0) {
      throw new Error('LogisticRegression.partialFit: model must be trained first');
    }
    const y = typeof sample.label === 'boolean' ? (sample.label ? 1 : 0) : sample.label;
    if (y !== 0 && y !== 1) {
      throw new Error(`LogisticRegression.partialFit: label must be 0 or 1, got ${y}`);
    }
    const featureValues = this.featureNames.map((f) => sample.features[f]);
    for (let i = 0; i < featureValues.length; i++) {
      if (typeof featureValues[i] !== 'number' || !Number.isFinite(featureValues[i])) {
        throw new Error(`LogisticRegression.partialFit: feature "${this.featureNames[i]}" must be a finite number`);
      }
    }
    const x = this.scaler.transform(featureValues);
    const z = this.dot(x) + this.bias;
    const p = this.sigmoid(z);
    const error = p - y;
    const w = sample.weight ?? 1;
    const lrEffective = this.trainConfig.learningRate / (1 + 0.01 * this.samplesSeen);

    const dim = this.weights.length;
    for (let i = 0; i < dim; i++) {
      this.weights[i] -= lrEffective * error * x[i] * w;
    }
    this.bias -= lrEffective * error * w;
    for (let i = 0; i < dim; i++) {
      this.weights[i] *= 1 - lrEffective * this.trainConfig.l2;
    }

    this.samplesSeen++;

    // Return metrics for this single sample
    const pred = p >= this.threshold ? 1 : 0;
    const bce = -y * Math.log(Math.max(p, 1e-12)) - (1 - y) * Math.log(Math.max(1 - p, 1e-12));
    const tp = pred === 1 && y === 1 ? 1 : 0;
    const fp = pred === 1 && y === 0 ? 1 : 0;
    const tn = pred === 0 && y === 0 ? 1 : 0;
    const fn = pred === 0 && y === 1 ? 1 : 0;
    return {
      accuracy: (tp + tn) / 1,
      precision: tp + fp > 0 ? tp / (tp + fp) : 0,
      recall: tp + fn > 0 ? tp / (tp + fn) : 0,
      aucRoc: 0.5,
      prAuc: tp + fn > 0 ? tp / (tp + fn) : 0,
      bce,
    };
  }

  private dot(x: number[]): number {
    let s = 0;
    for (let i = 0; i < x.length; i++) s += this.weights[i] * x[i];
    return s;
  }

  private sigmoid(z: number): number {
    if (z >= 0) {
      const ez = Math.exp(-z);
      return 1 / (1 + ez);
    }
    const ez = Math.exp(z);
    return ez / (1 + ez);
  }

  predict(features: Record<string, number>): PredictionResult {
    if (!this.scaler || this.weights.length === 0) {
      return { score: 0.5, probability: 0.5, confidence: 'LOW', reason: 'model untrained — returning neutral' };
    }
    const x = this.scaler.transform(this.featureNames.map((f) => features[f]));
    const p = this.sigmoid(this.dot(x) + this.bias);
    const confidence = this.confidenceLevel(p);
    const reason = this.explain(features, p);
    const featureImportance = this.featureImportance(features, x, p);
    return {
      score: p,
      probability: p,
      confidence,
      reason,
      featureImportance,
    };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  private confidenceLevel(p: number): PredictionResult['confidence'] {
    const distance = Math.abs(p - 0.5);
    if (distance >= 0.3) return 'HIGH';
    if (distance >= 0.15) return 'MEDIUM';
    return 'LOW';
  }

  private explain(features: Record<string, number>, p: number): string {
    if (!this.scaler) return 'no scaler';
    const contributions: { name: string; value: number }[] = [];
    const x = this.scaler.transform(this.featureNames.map((f) => features[f]));
    for (let i = 0; i < x.length; i++) {
      contributions.push({ name: this.featureNames[i], value: this.weights[i] * x[i] });
    }
    contributions.sort((a, b) => Math.abs(b.value) - Math.abs(a.value));
    const top = contributions.slice(0, 2).map((c) => `${c.name}(${c.value.toFixed(2)})`);
    return `predicted P=${p.toFixed(3)} (threshold ${this.threshold}); top drivers: ${top.join(', ')}`;
  }

  /**
   * SHAP-style linear approximation: each feature's contribution is
   * weight * scaled_value. Returns signed contributions sorted by magnitude.
   */
  private featureImportance(features: Record<string, number>, x: number[], p: number): Record<string, number> {
    const importance: Record<string, number> = {};
    for (let i = 0; i < this.featureNames.length; i++) {
      // Contribution = weight * scaled_feature_value (linear model, no interaction)
      importance[this.featureNames[i]] = this.weights[i] * x[i];
    }
    return importance;
  }

  /** Public evaluation for holdout/tuning use. */
  public evaluate(samples: TrainingSample[]): LogisticRegressionMetrics {
    return this.evaluatePrivate(samples);
  }

  private evaluatePrivate(samples: TrainingSample[]): LogisticRegressionMetrics {
    const results = samples.map((s) => ({ pred: this.predict(s.features), label: typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label }));
    let tp = 0, fp = 0, tn = 0, fn = 0;
    let bce = 0;
    for (const r of results) {
      const pred = r.pred.score >= this.threshold ? 1 : 0;
      if (pred === 1 && r.label === 1) tp++;
      else if (pred === 1 && r.label === 0) fp++;
      else if (pred === 0 && r.label === 0) tn++;
      else fn++;
      bce += -r.label * Math.log(Math.max(r.pred.score, 1e-12)) - (1 - r.label) * Math.log(Math.max(1 - r.pred.score, 1e-12));
    }
    bce /= results.length;
    const accuracy = (tp + tn) / results.length;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const aucRoc = this.aucRoc(results);
    const prAuc = this.prAuc(results);
    return { accuracy, precision, recall, aucRoc, prAuc, bce };
  }

  private prAuc(results: { pred: PredictionResult; label: number }[]): number {
    // Average precision approximation of PR-AUC: sort by score descending,
    // compute precision at each positive detection.
    const sorted = [...results].sort((a, b) => b.pred.score - a.pred.score);
    const nPos = sorted.filter((r) => r.label === 1).length;
    if (nPos === 0) return 0.0;
    let tp = 0, fp = 0;
    let prevRecall = 0;
    let ap = 0;
    for (const r of sorted) {
      if (r.label === 1) tp++; else fp++;
      const recall = tp / nPos;
      const precision = tp / (tp + fp);
      ap += precision * (recall - prevRecall);
      prevRecall = recall;
    }
    return ap;
  }

  private aucRoc(results: { pred: PredictionResult; label: number }[]): number {
    const sorted = [...results].sort((a, b) => a.pred.score - b.pred.score);
    const nPos = sorted.filter((r) => r.label === 1).length;
    const nNeg = sorted.length - nPos;
    if (nPos === 0 || nNeg === 0) return 0.5;
    let rankSum = 0;
    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i].label === 1) rankSum += i + 1;
    }
    return (rankSum - (nPos * (nPos + 1)) / 2) / (nPos * nNeg);
  }

  serialize(): LogisticRegressionWeights {
    if (!this.scaler) throw new Error('LogisticRegression.serialize: model not trained');
    return {
      weights: [...this.weights],
      bias: this.bias,
      scaler: this.scaler.serialize(),
      featureNames: [...this.featureNames],
      threshold: this.threshold,
      trainConfig: {
        learningRate: this.trainConfig.learningRate,
        iterations: this.trainConfig.iterations,
        l2: this.trainConfig.l2,
        posWeight: this.trainConfig.posWeight,
        negWeight: this.trainConfig.negWeight,
      },
      samplesSeen: this.samplesSeen,
    };
  }

  load(data: LogisticRegressionWeights): void {
    this.weights = [...data.weights];
    this.bias = data.bias;
    this.threshold = data.threshold;
    this.featureNames = [...data.featureNames];
    this.scaler = new StandardScaler();
    this.scaler.load(data.scaler);
    this.trainConfig = { ...this.trainConfig, ...data.trainConfig };
    this.samplesSeen = data.samplesSeen ?? 0;
  }

  getFeatureNames(): string[] {
    return [...this.featureNames];
  }

  getThreshold(): number {
    return this.threshold;
  }

  setThreshold(value: number): void {
    this.threshold = value;
  }
}

/**
 * Grid-search hyperparameter tuning for LogisticRegression.
 * Evaluates combinations of learningRate, l2, and posWeight on a holdout
 * split, returning the config with the best PR-AUC (optimized for imbalanced data).
 */
export function tuneLogisticRegression(
  samples: TrainingSample[],
  featureNames: string[],
  configGrid?: {
    learningRate?: number[];
    l2?: number[];
    posWeight?: number[];
    iterations?: number[];
  },
): { config: LogisticRegressionConfig; metrics: LogisticRegressionMetrics } {
  const cfg = { ...DEFAULT_CONFIG };
  const lrs = configGrid?.learningRate ?? [0.01, 0.05, 0.1];
  const l2s = configGrid?.l2 ?? [0.0001, 0.001, 0.01];
  const posWeights = configGrid?.posWeight ?? [1.0, 2.0, 5.0];
  const iterationsList = configGrid?.iterations ?? [1000, 2000];

  const rng = createRng(cfg.seed);
  const shuffled = [...samples].sort(() => rng() - 0.5);
  const split = Math.floor(shuffled.length * 0.8);
  const trainSamples = shuffled.slice(0, split);
  const valSamples = shuffled.slice(split);

  let best: { config: LogisticRegressionConfig; metrics: LogisticRegressionMetrics } | null = null;

  for (const lr of lrs) {
    for (const l2 of l2s) {
      for (const pw of posWeights) {
        for (const iters of iterationsList) {
          const model = new LogisticRegression();
          try {
            model.train(trainSamples, {
              learningRate: lr,
              iterations: iters,
              l2,
              posWeight: pw,
              negWeight: 1.0,
              validationSplit: 0,
              seed: cfg.seed,
            });
            const m = model.evaluate(valSamples);
            if (!best || m.prAuc > best.metrics.prAuc) {
              best = {
                config: { learningRate: lr, iterations: iters, l2, posWeight: pw, negWeight: 1.0 },
                metrics: m,
              };
            }
          } catch {
            /* skip invalid config */
          }
        }
      }
    }
  }

  if (!best) {
    throw new Error('tuneLogisticRegression: no valid configuration found');
  }
  return best;
}

export interface LogisticRegressionMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  aucRoc: number;
  prAuc: number;
  bce: number;
}
