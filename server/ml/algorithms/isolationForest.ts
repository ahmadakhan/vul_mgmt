/**
 * Isolation Forest for unsupervised anomaly detection.
 *
 * Fits an ensemble of isolation trees on feature vectors. Anomaly score
 * is the average path length compared to the expected path length in a
 * uniformly random tree. No labels are required.
 *
 * Feature scaling is intentionally NOT applied — isolation forests split
 * on raw feature values and the random partitioning handles heterogeneous
 * scales naturally. Applying a scaler would break the path-length invariant
 * because trees are built on raw data but queries would be transformed.
 *
 * Paper: Liu, Fei Tony, et al. "Isolation forest." ICDM 2008.
 */
import type { PredictionResult } from '../types.ts';
import { createRng, DEFAULT_TRAINING_SEED } from './rng.ts';

interface IsolationTreeNode {
  left: IsolationTreeNode | null;
  right: IsolationTreeNode | null;
  splitAttr: number;
  splitValue: number;
  size: number;
}

interface SerializedNode {
  left: SerializedNode | null;
  right: SerializedNode | null;
  splitAttr: number;
  splitValue: number;
  size: number;
}

interface TreeWeights {
  trees: SerializedNode[];
  maxDepth: number;
  contamination: number;
  threshold: number;
  featureNames: string[];
}

function c(i: number): number {
  if (i <= 1) return 0;
  const ll = Math.log(i - 1) + 0.5772156649015329;
  return 2 * ll - 2 * (i - 1) / i;
}

export class IsolationForest {
  private trees: IsolationTreeNode[] = [];
  private maxDepth = 8;
  private contamination = 0.1;
  private threshold = 0.0;
  private featureNames: string[] = [];
  private trainSize = 0;

  train(samples: number[][], featureNames: string[], nTrees = 100, maxDepth = 8, contamination = 0.1, seed = DEFAULT_TRAINING_SEED): void {
    if (samples.length < 10) throw new Error(`IsolationForest.train: need >= 10 samples, got ${samples.length}`);
    const rng = createRng(seed);
    this.maxDepth = maxDepth;
    this.contamination = contamination;
    this.featureNames = [...featureNames];
    this.trainSize = samples.length;

    this.trees = [];
    for (let t = 0; t < nTrees; t++) {
      const tree = this.buildTree(samples, 0, rng);
      if (tree) this.trees.push(tree);
    }

    const scores: number[] = [];
    for (const sample of samples) {
      scores.push(this.anomalyScore(sample));
    }
    scores.sort((a, b) => a - b);
    const thresholdIdx = Math.floor((1 - contamination) * scores.length);
    this.threshold = scores[Math.min(thresholdIdx, scores.length - 1)];
  }

  private buildTree(samples: number[][], depth = 0, rng: () => number): IsolationTreeNode | null {
    if (samples.length === 0) return null;
    const node: IsolationTreeNode = { left: null, right: null, splitAttr: 0, splitValue: 0, size: samples.length };
    if (depth >= this.maxDepth || samples.length <= 1) return node;

    const dim = samples[0].length;
    const candidateAttrs: number[] = [];
    for (let a = 0; a < dim; a++) {
      const vals = new Set(samples.map((s) => s[a]));
      if (vals.size > 1) candidateAttrs.push(a);
    }
    if (candidateAttrs.length === 0) return node;

    const attr = candidateAttrs[Math.floor(rng() * candidateAttrs.length)];
    const values = samples.map((s) => s[attr]).sort((a, b) => a - b);
    const minVal = values[0];
    const maxVal = values[values.length - 1];
    if (minVal === maxVal) return node;

    node.splitAttr = attr;
    node.splitValue = rng() * (maxVal - minVal) + minVal;

    const leftSamples: number[][] = [];
    const rightSamples: number[][] = [];
    for (const s of samples) {
      if (s[attr] < node.splitValue) leftSamples.push(s);
      else rightSamples.push(s);
    }

    node.left = this.buildTree(leftSamples, depth + 1, rng);
    node.right = this.buildTree(rightSamples, depth + 1, rng);
    return node;
  }

  private pathLength(sample: number[], node: IsolationTreeNode, depth = 0): number {
    if (node.left === null && node.right === null) return depth;
    if (node.size <= 1) return depth;
    if (sample[node.splitAttr] < node.splitValue) {
      return node.left ? this.pathLength(sample, node.left, depth + 1) : depth;
    }
    return node.right ? this.pathLength(sample, node.right, depth + 1) : depth;
  }

  anomalyScore(sample: number[]): number {
    if (this.trees.length === 0) return 0.5;
    let total = 0;
    for (const tree of this.trees) {
      total += this.pathLength(sample, tree);
    }
    const avgPath = total / this.trees.length;
    const n = this.trainSize > 1 ? this.trainSize : 1;
    return Math.pow(2, -(avgPath / c(n)));
  }

  predict(sample: number[]): PredictionResult {
    const score = this.anomalyScore(sample);
    const isAnomaly = score >= this.threshold;
    const confidence: PredictionResult['confidence'] = this.confidenceLevel(score);
    return {
      score,
      confidence,
      reason: `anomaly_score=${score.toFixed(3)} threshold=${this.threshold.toFixed(3)} isAnomaly=${isAnomaly}`,
    };
  }

  predictBatch(samples: number[][]): PredictionResult[] {
    return samples.map((s) => this.predict(s));
  }

  private confidenceLevel(score: number): PredictionResult['confidence'] {
    if (score >= 0.8 || score <= 0.2) return 'HIGH';
    if (score >= 0.7 || score <= 0.3) return 'MEDIUM';
    return 'LOW';
  }

  isAnomaly(sample: number[]): boolean {
    return this.anomalyScore(sample) >= this.threshold;
  }

  getThreshold(): number {
    return this.threshold;
  }

  serialize(): TreeWeights {
    if (this.trees.length === 0) throw new Error('IsolationForest.serialize: model not trained');
    return {
      trees: this.trees.map((t) => this.serializeTree(t)),
      maxDepth: this.maxDepth,
      contamination: this.contamination,
      threshold: this.threshold,
      featureNames: [...this.featureNames],
    };
  }

  load(data: TreeWeights): void {
    this.threshold = data.threshold;
    this.contamination = data.contamination;
    this.maxDepth = data.maxDepth;
    this.featureNames = [...data.featureNames];
    this.trainSize = data.trees.length > 0 ? data.trees[0]?.size ?? 10 : 10;
    this.trees = data.trees.map((t) => this.deserializeTree(t)).filter((t): t is IsolationTreeNode => t !== null);
  }

  private serializeTree(node: IsolationTreeNode): SerializedNode {
    return {
      left: node.left ? this.serializeTree(node.left) : null,
      right: node.right ? this.serializeTree(node.right) : null,
      splitAttr: node.splitAttr,
      splitValue: node.splitValue,
      size: node.size,
    };
  }

  private deserializeTree(data: SerializedNode | null): IsolationTreeNode | null {
    if (data === null) return null;
    const left = data.left ? this.deserializeTree(data.left) : null;
    const right = data.right ? this.deserializeTree(data.right) : null;
    return {
      left,
      right,
      splitAttr: data.splitAttr,
      splitValue: data.splitValue,
      size: data.size,
    };
  }

  getFeatureNames(): string[] {
    return [...this.featureNames];
  }
}
