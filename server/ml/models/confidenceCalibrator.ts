/**
 * Confidence Calibrator — isotonic regression that maps the heuristic
 * `computeCredibilityScore` (feedScore*0.6 + keywordScore*0.4) into a true
 * calibrated probability of a finding being actionable.
 *
 * File target: intelligenceMatcher.ts:46 (computeCredibilityScore)
 *
 * Uses a lightweight isotonic regression (pairwise ordering) that's
 * serializable as a sorted lookup table with interpolation.
 */
import type { ModelMetadata, ModelArtifact, PredictionResult, TrainingSample } from '../types.ts';

interface CalibrationPoint {
  raw: number;
  calibrated: number;
}

interface CalibratorWeights {
  points: CalibrationPoint[];
  featureNames: string[];
}

export class ConfidenceCalibrator {
  private weights: CalibratorWeights | null = null;
  private metadata: ModelMetadata;

  constructor() {
    this.metadata = {
      id: 'confidence-calibrator',
      type: 'calibrator',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: ['credibility_score'],
      description: 'Isotonic calibration of heuristic credibility scores',
    };
  }

  train(samples: TrainingSample[]): void {
    // Group by raw score (rounded to 1 decimal) and compute calibration
    const buckets = new Map<number, { sum: number; count: number }>();
    for (const s of samples) {
      const raw = s.features.credibility_score ?? s.features.credibility ?? 0;
      const key = Math.round(raw * 10) / 10;
      const labelVal = typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label;
      const existing = buckets.get(key) ?? { sum: 0, count: 0 };
      existing.sum += labelVal;
      existing.count += 1;
      buckets.set(key, existing);
    }

    const points: CalibrationPoint[] = [...buckets.entries()]
      .sort(([a], [b]) => a - b)
      .map(([raw, agg]) => ({
        raw,
        calibrated: agg.count > 0 ? agg.sum / agg.count : 0,
      }));

    // Isotonic regression: enforce monotonicity via pool-adjacent-violators
    for (let i = 0; i < points.length; i++) {
      for (let j = i + 1; j < points.length; j++) {
        if (points[j].calibrated < points[i].calibrated) {
          const avg = (points[i].calibrated + points[j].calibrated) / 2;
          points[i].calibrated = avg;
          points[j].calibrated = avg;
        }
      }
    }

    this.weights = { points, featureNames: ['credibility_score'] };
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  predict(features: Record<string, number>): PredictionResult {
    const raw = features.credibility_score ?? features.credibility ?? 0;
    if (!this.weights || this.weights.points.length === 0) {
      return { score: raw, probability: raw / 100, confidence: 'LOW', reason: 'calibrator untrained — passing raw score' };
    }

    const pts = this.weights.points;
    if (raw <= pts[0].raw) {
      return { score: pts[0].calibrated * 100, probability: pts[0].calibrated, confidence: 'HIGH', reason: `clamped to min: raw=${raw.toFixed(1)}` };
    }
    if (raw >= pts[pts.length - 1].raw) {
      return { score: pts[pts.length - 1].calibrated * 100, probability: pts[pts.length - 1].calibrated, confidence: 'HIGH', reason: `clamped to max: raw=${raw.toFixed(1)}` };
    }

    // Binary search + linear interpolation
    let lo = 0;
    let hi = pts.length - 1;
    while (lo < hi - 1) {
      const mid = Math.floor((lo + hi) / 2);
      if (pts[mid].raw <= raw) lo = mid;
      else hi = mid;
    }
    const p0 = pts[lo];
    const p1 = pts[hi];
    const t = (raw - p0.raw) / (p1.raw - p0.raw);
    const calibrated = p0.calibrated * (1 - t) + p1.calibrated * t;

    const confidence: PredictionResult['confidence'] = Math.abs(calibrated - raw / 100) > 0.2 ? 'HIGH' : 'MEDIUM';
    return {
      score: calibrated * 100,
      probability: calibrated,
      confidence,
      reason: `calibrated from raw=${raw.toFixed(1)} (interp between ${p0.raw}→${p0.calibrated.toFixed(3)} and ${p1.raw}→${p1.calibrated.toFixed(3)})`,
    };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.weights ?? { points: [], featureNames: ['credibility_score'] },
    };
  }

  load(artifact: ModelArtifact): void {
    this.weights = artifact.weights as CalibratorWeights;
    this.metadata = artifact.metadata;
  }

  getFeatureNames(): string[] {
    return ['credibility_score'];
  }

  getMetadata(): ModelMetadata {
    return this.metadata;
  }

  isTrained(): boolean {
    return this.weights !== null && this.weights.points.length > 0;
  }
}
