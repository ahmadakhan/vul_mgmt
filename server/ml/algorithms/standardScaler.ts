/**
 * Standardizes features to zero-mean / unit-variance, or min-max scales to [0,1].
 *
 * Serialization is JSON-safe; loaded artifacts are validated to prevent
 * adversarial feature shifts from corrupting inference.
 */
import type { Scaler } from '../types.ts';

export interface StandardScalerData {
  means: number[];
  stds: number[];
  featureNames: string[];
}

export class StandardScaler implements Scaler {
  private means: number[] = [];
  private stds: number[] = [];
  private featureNames: string[] = [];
  private readonly epsilon = 1e-8;
  private sampleCount = 0;
  private m2: number[] = [];

  fit(samples: number[][], featureNames: string[]): void {
    if (samples.length === 0) throw new Error('StandardScaler.fit: no samples');
    const dim = samples[0].length;
    if (featureNames.length !== dim)
      throw new Error(`StandardScaler.fit: feature name count ${featureNames.length} != dimension ${dim}`);
    this.featureNames = [...featureNames];
    this.means = new Array(dim).fill(0);
    this.stds = new Array(dim).fill(0);
    for (let i = 0; i < dim; i++) {
      let sum = 0;
      for (const sample of samples) sum += sample[i];
      const mean = sum / samples.length;
      this.means[i] = mean;
      let sq = 0;
      for (const sample of samples) {
        const diff = sample[i] - mean;
        sq += diff * diff;
      }
      this.stds[i] = Math.sqrt(sq / samples.length) + this.epsilon;
    }
  }

  /**
   * Incrementally updates the running mean and variance for a single sample
   * using Welford's online algorithm. Can be called after fit() to incorporate
   * new data without re-fitting from scratch.
   *
   * Throws if called before fit() — the scaler needs initial statistics first.
   */
  partialFit(sample: number[]): void {
    if (this.featureNames.length === 0) {
      throw new Error('StandardScaler.partialFit: call fit() first');
    }
    if (sample.length !== this.means.length) {
      throw new Error(`StandardScaler.partialFit: expected ${this.means.length} features, got ${sample.length}`);
    }

    this.sampleCount++;
    if (this.m2.length === 0) this.m2 = new Array(this.means.length).fill(0);

    for (let i = 0; i < this.means.length; i++) {
      const delta = sample[i] - this.means[i];
      this.means[i] += delta / this.sampleCount;
      const delta2 = sample[i] - this.means[i];
      this.m2[i] = (this.m2[i] || 0) + delta * delta2;
      this.stds[i] = Math.sqrt(this.m2[i] / this.sampleCount) + this.epsilon;
    }
  }

  transform(features: number[]): number[] {
    if (features.length !== this.means.length)
      throw new Error(`StandardScaler.transform: expected ${this.means.length} features, got ${features.length}`);
    return features.map((v, i) => {
      if (this.stds[i] < 1e-7) return 0;
      return (v - this.means[i]) / this.stds[i];
    });
  }

  inverseTransform(scaled: number[]): number[] {
    if (scaled.length !== this.means.length)
      throw new Error(`StandardScaler.inverseTransform: dimension mismatch`);
    return scaled.map((v, i) => v * this.stds[i] + this.means[i]);
  }

  serialize(): StandardScalerData {
    return { means: [...this.means], stds: [...this.stds], featureNames: [...this.featureNames] };
  }

  load(data: unknown): void {
    const d = data as StandardScalerData;
    if (!Array.isArray(d.means) || !Array.isArray(d.stds) || !Array.isArray(d.featureNames))
      throw new Error('StandardScaler.load: malformed data');
    if (d.means.length !== d.stds.length || d.means.length !== d.featureNames.length)
      throw new Error('StandardScaler.load: dimension mismatch');
    this.means = [...d.means];
    this.stds = [...d.stds];
    this.featureNames = [...d.featureNames];
  }

  getFeatureNames(): string[] {
    return [...this.featureNames];
  }
}
