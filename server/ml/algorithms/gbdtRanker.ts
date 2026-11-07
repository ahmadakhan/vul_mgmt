  /**
   * Gradient-boosted decision trees for ranking (GBDT-Rank).
 *
 * Each tree is a regression tree minimizing squared error on the residual.
 * For ranking, the label is the utility (higher = more important to act on).
 * Pairwise ranking: we optimize the order, not the absolute score.
 *
 * This is a simplified LambdaMART-style ranker with L2 regularization on leaf values.
 */
import { StandardScaler } from './standardScaler.ts';
import { createRng, DEFAULT_TRAINING_SEED } from './rng.ts';
import type { PredictionResult, TrainingSample } from '../types.ts';

interface RegressionTreeLeaf {
  value: number;
}

interface RegressionTreeNode {
  left: RegressionTree;
  right: RegressionTree;
  splitAttr: number;
  splitValue: number;
}

type RegressionTree = RegressionTreeNode | RegressionTreeLeaf;

interface SerializedLeaf { leaf: true; value: number }
interface SerializedNode {
  left: SerializedNode | SerializedLeaf | null;
  right: SerializedNode | SerializedLeaf | null;
  splitAttr: number;
  splitValue: number;
}

interface GBDTWeights {
  trees: (SerializedNode | SerializedLeaf)[];
  learningRates: number[];
  scaler: ReturnType<StandardScaler['serialize']>;
  featureNames: string[];
  maxDepth: number;
}

export class GBDTRanker {
  private trees: RegressionTree[] = [];
  private learningRates: number[] = [];
  private scaler: StandardScaler | null = null;
  private featureNames: string[] = [];
  private maxDepth = 4;
  private nTrees = 50;
  private learningRate = 0.1;
  private minSamplesSplit = 5;
  private l2 = 1.0;

  train(
    samples: TrainingSample[],
    featureNames: string[],
    config?: { nTrees?: number; learningRate?: number; maxDepth?: number; minSamplesSplit?: number; l2?: number; seed?: number },
  ): void {
    if (samples.length < 10) throw new Error(`GBDTRanker.train: need >= 10 samples, got ${samples.length}`);
    const rng = createRng(config?.seed ?? DEFAULT_TRAINING_SEED);
    this.nTrees = config?.nTrees ?? this.nTrees;
    this.learningRate = config?.learningRate ?? this.learningRate;
    this.maxDepth = config?.maxDepth ?? this.maxDepth;
    this.minSamplesSplit = config?.minSamplesSplit ?? this.minSamplesSplit;
    this.l2 = config?.l2 ?? this.l2;
    this.featureNames = [...featureNames];

    this.scaler = new StandardScaler();
    this.scaler.fit(
      samples.map((s) => featureNames.map((f) => s.features[f])),
      featureNames,
    );

    const scaler = this.scaler;
    const matrix: { x: number[]; y: number; w: number }[] = samples.map((s) => ({
      x: scaler.transform(featureNames.map((f) => s.features[f])),
      y: typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label,
      w: s.weight ?? 1,
    }));

    let predictions = new Array(samples.length).fill(0);

    for (let t = 0; t < this.nTrees; t++) {
      const residuals = matrix.map((s, i) => s.w * (s.y - predictions[i]));
      const tree = this.buildRegressionTree(matrix, residuals, 0);
      if (!tree) break;

      this.trees.push(tree);
      this.learningRates.push(this.learningRate);

      for (let i = 0; i < samples.length; i++) {
        predictions[i] += this.learningRate * this.predictSingle(matrix[i].x, tree);
      }
    }
  }

  private buildRegressionTree(
    data: { x: number[]; y: number; w: number }[],
    residuals: number[],
    depth: number,
  ): RegressionTree | null {
    if (data.length < this.minSamplesSplit || depth >= this.maxDepth) {
      return { value: this.weightedMean(residuals, data) };
    }

    const dim = data[0].x.length;
    let bestGain = 0;
    let bestSplit = -1;
    let bestValue = 0;

    for (let attr = 0; attr < dim; attr++) {
      const values = [...new Set(data.map((d) => d.x[attr]))].sort((a, b) => a - b);
      for (let vi = 0; vi < values.length - 1; vi++) {
        const threshold = (values[vi] + values[vi + 1]) / 2;
        const leftIdx: number[] = [];
        const rightIdx: number[] = [];
        for (let i = 0; i < data.length; i++) {
          if (data[i].x[attr] < threshold) leftIdx.push(i);
          else rightIdx.push(i);
        }
        if (leftIdx.length === 0 || rightIdx.length === 0) continue;

        const gain = this.splitGain(residuals, leftIdx, rightIdx, data);
        if (gain > bestGain) {
          bestGain = gain;
          bestSplit = attr;
          bestValue = threshold;
        }
      }
    }

    if (bestSplit === -1) {
      return { value: this.weightedMean(residuals, data) };
    }

    const leftData: { x: number[]; y: number; w: number }[] = [];
    const rightData: { x: number[]; y: number; w: number }[] = [];
    for (let i = 0; i < data.length; i++) {
      if (data[i].x[bestSplit] < bestValue) leftData.push(data[i]);
      else rightData.push(data[i]);
    }

    const leftResiduals = new Array(leftData.length).fill(0);
    const rightResiduals = new Array(rightData.length).fill(0);
    for (let i = 0; i < leftData.length; i++) {
      const origIdx = data.indexOf(leftData[i]);
      leftResiduals[i] = residuals[origIdx];
    }
    for (let i = 0; i < rightData.length; i++) {
      const origIdx = data.indexOf(rightData[i]);
      rightResiduals[i] = residuals[origIdx];
    }

    const leftTree = this.buildRegressionTree(leftData, leftResiduals, depth + 1);
    const rightTree = this.buildRegressionTree(rightData, rightResiduals, depth + 1);

    return {
      left: leftTree ?? { value: 0 },
      right: rightTree ?? { value: 0 },
      splitAttr: bestSplit,
      splitValue: bestValue,
    };
  }

  private weightedMean(residuals: number[], data: { x: number[] }[]): number {
    let sum = 0;
    let count = 0;
    for (let i = 0; i < data.length; i++) {
      sum += residuals[i];
      count += 1;
    }
    return count > 0 ? sum / (count + this.l2) : 0;
  }

  private splitGain(residuals: number[], leftIdx: number[], rightIdx: number[], data: { x: number[]; w: number }[]): number {
    const n = data.length;
    const nL = leftIdx.length;
    const nR = rightIdx.length;
    if (nL === 0 || nR === 0) return 0;

    let sumL = 0, sumR = 0;
    for (const i of leftIdx) sumL += residuals[i];
    for (const i of rightIdx) sumR += residuals[i];

    const total = sumL + sumR;
    const lambda = this.l2;
    const gain = 0.5 * (
      (sumL * sumL) / (nL + lambda) +
      (sumR * sumR) / (nR + lambda) -
      (total * total) / (n + lambda)
    );
    return gain;
  }

  private predictSingle(x: number[], tree: RegressionTree): number {
    if ('value' in tree) return tree.value;
    if (x[tree.splitAttr] < tree.splitValue) {
      return this.predictSingle(x, tree.left);
    }
    return this.predictSingle(x, tree.right);
  }

  predict(features: Record<string, number>): PredictionResult {
    if (!this.scaler || this.trees.length === 0) {
      throw new Error('GBDTRanker.predict: model not trained');
    }
    const x = this.scaler.transform(this.featureNames.map((f) => features[f]));
    let score = 0;
    for (let i = 0; i < this.trees.length; i++) {
      score += this.learningRates[i] * this.predictSingle(x, this.trees[i]);
    }
    const normalized = 1 / (1 + Math.exp(-score));
    const confidence: PredictionResult['confidence'] = Math.abs(normalized - 0.5) >= 0.3 ? 'HIGH' : Math.abs(normalized - 0.5) >= 0.15 ? 'MEDIUM' : 'LOW';
    return {
      score,
      probability: normalized,
      confidence,
      reason: `rank_score=${score.toFixed(3)}`,
    };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  serialize(): GBDTWeights {
    if (!this.scaler) throw new Error('GBDTRanker.serialize: model not trained');
    return {
      trees: this.trees.map((t) => this.serializeTree(t)),
      learningRates: [...this.learningRates],
      scaler: this.scaler.serialize(),
      featureNames: [...this.featureNames],
      maxDepth: this.maxDepth,
    };
  }

  load(data: GBDTWeights): void {
    this.trees = data.trees.map((t) => this.deserializeTree(t)).filter((t): t is RegressionTree => t !== null);
    this.learningRates = [...data.learningRates];
    this.scaler = new StandardScaler();
    this.scaler.load(data.scaler);
    this.featureNames = [...data.featureNames];
    this.maxDepth = data.maxDepth;
    this.nTrees = this.trees.length;
  }

  private serializeTree(tree: RegressionTree): SerializedNode | SerializedLeaf {
    if ('value' in tree) {
      return { leaf: true, value: tree.value };
    }
    const leftSer = this.serializeTree(tree.left);
    const rightSer = this.serializeTree(tree.right);
    return {
      left: leftSer,
      right: rightSer,
      splitAttr: tree.splitAttr,
      splitValue: tree.splitValue,
    };
  }

  private deserializeTree(data: SerializedNode | SerializedLeaf | null): RegressionTree | null {
    if (data === null) return null;
    if ('leaf' in data) {
      return { value: data.value };
    }
    const left = this.deserializeTree(data.left);
    const right = this.deserializeTree(data.right);
    if (!left || !right) return null;
    return { left, right, splitAttr: data.splitAttr, splitValue: data.splitValue };
  }

  getFeatureNames(): string[] {
    return [...this.featureNames];
  }

  /**
   * Online learning is not supported for tree-based models — requires
   * a full retraining. Returns a clear error if called.
   */
  partialFit(_sample: TrainingSample): never {
    throw new Error('GBDTRanker.partialFit: not supported — tree-based models require full retraining');
  }
}
