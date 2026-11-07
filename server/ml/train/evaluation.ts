/**
 * Shared evaluation utilities for the ML training subsystem.
 *
 * Pure functions — no side effects, no I/O. Used by quality gates and
 * the training orchestrator to validate trained models against holdout data.
 */
import type { PredictionResult, TrainingSample } from '../types.ts';

export interface ClassificationMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  aucRoc: number;
  bce: number;
  tP: number;
  fP: number;
  tN: number;
  fN: number;
}

export interface CalibrationMetrics {
  ece: number;
  mce: number;
  maxAccuracy: number;
  samplesEvaluated: number;
}

/**
 * Evaluates a binary classifier on labeled holdout samples.
 * Threshold for positive class is 0.5 (or the model's internal threshold).
 */
export function evaluateClassifier(
  samples: TrainingSample[],
  predict: (features: Record<string, number>) => PredictionResult,
  threshold = 0.5,
): ClassificationMetrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  let bceSum = 0;
  const scores: { prob: number; label: number }[] = [];

  for (const s of samples) {
    const rawLabel = typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label;
    const label = rawLabel > 0.5 ? 1 : 0;
    const pred = predict(s.features);
    const score = pred.probability ?? pred.score;
    const predLabel = score >= threshold ? 1 : 0;

    if (predLabel === 1 && label === 1) tp++;
    else if (predLabel === 1 && label === 0) fp++;
    else if (predLabel === 0 && label === 0) tn++;
    else fn++;

    const p = Math.max(Math.min(score, 1 - 1e-12), 1e-12);
    bceSum += -label * Math.log(p) - (1 - label) * Math.log(1 - p);
    scores.push({ prob: score, label });
  }

  const n = samples.length;
  const nPos = scores.filter((r) => r.label === 1).length;
  const nNeg = n - nPos;

  const accuracy = n > 0 ? (tp + tn) / n : 0;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const aucRoc = nPos > 0 && nNeg > 0 ? computeAucRoc(scores) : 0.5;
  const bce = n > 0 ? bceSum / n : 0;

  return { accuracy, precision, recall, f1, aucRoc, bce, tP: tp, fP: fp, tN: tn, fN: fn };
}

/**
 * Computes AUC-ROC via the Mann-Whitney U statistic.
 * Sort ascending by score, sum ranks of positive samples.
 */
function computeAucRoc(results: { prob: number; label: number }[]): number {
  const sorted = [...results].sort((a, b) => a.prob - b.prob);
  const nPos = sorted.filter((r) => r.label === 1).length;
  const nNeg = sorted.length - nPos;
  if (nPos === 0 || nNeg === 0) return 0.5;

  let rankSum = 0;
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i].label === 1) rankSum += i + 1;
  }
  return (rankSum - (nPos * (nPos + 1)) / 2) / (nPos * nNeg);
}

/**
 * Computes Expected Calibration Error (ECE) — the weighted average of
 * |confidence - accuracy| across N equal-width bins on [0, 1].
 */
export function computeEce(predictions: { prob: number; label: number }[], nBins = 10): CalibrationMetrics {
  const binSize = 1 / nBins;
  const bins = new Array<{ count: number; correct: number }>(nBins);
  for (let i = 0; i < nBins; i++) {
    bins[i] = { count: 0, correct: 0 };
  }

  for (const p of predictions) {
    const binIdx = Math.min(Math.floor(p.prob / binSize), nBins - 1);
    bins[binIdx].count++;
    if (p.label === 1) bins[binIdx].correct++;
  }

  const total = predictions.length;
  if (total === 0) return { ece: 0, mce: 0, maxAccuracy: 0, samplesEvaluated: 0 };

  let ece = 0;
  let mce = 0;
  let maxCorrect = 0;

  for (let i = 0; i < nBins; i++) {
    const b = bins[i];
    if (b.count === 0) continue;
    const binCenter = (i + 0.5) * binSize;
    const accuracy = b.correct / b.count;
    const gap = Math.abs(binCenter - accuracy);
    ece += (b.count / total) * gap;
    mce = Math.max(mce, gap);
    maxCorrect = Math.max(maxCorrect, accuracy);
  }

  return { ece, mce, maxAccuracy: maxCorrect, samplesEvaluated: total };
}

/**
 * Splits samples into train/test using a simple interleaved shuffle
 * seeded by a hash of the model ID for reproducibility.
 */
export function splitData<T>(samples: T[], testFraction = 0.2, seed = 0): [T[], T[]] {
  const n = samples.length;
  if (n === 0) return [[], []];

  const rng = mulberry32(seed);
  const indices = [...samples.keys()].sort(() => rng() - 0.5);
  const testSize = Math.max(1, Math.floor(n * testFraction));
  const testIndices = new Set(indices.slice(0, testSize));

  const train: T[] = [];
  const test: T[] = [];
  for (let i = 0; i < n; i++) {
    if (testIndices.has(i)) test.push(samples[i]);
    else train.push(samples[i]);
  }
  return [train, test];
}

/** Mulberry32 — fast, non-cryptographic PRNG for reproducible splits. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 6 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Normalizes a label to a numeric value. */
export function toLabel(v: number | boolean): number {
  return typeof v === 'boolean' ? (v ? 1 : 0) : v;
}
