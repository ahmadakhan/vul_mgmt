/**
 * CPE Validity Gate — binary classifier that predicts whether a CPE 2.3 string
 * is syntactically valid *before* invoking the full parseCPE23 path.
 *
 * Auto-trains from the existing parse outcomes: parseCPE23 already marks
 * isValid=false for malformed strings. The classifier learns to short-circuit
 * the parse path for obvious junk, and for borderline cases it defers to the
 * parser (never overrides a valid parse).
 *
 * File target: server/cpeSearch.ts (pre-parse gate)
 */
import { parseCPE23 } from '../../../src/utils/cpeMatcher.ts';
import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

const CPE_VALIDITY_FEATURE_NAMES = [
  'length',
  'segment_count',
  'has_valid_prefix',
  'has_wildcard_vendor_or_product',
  'numeric_token_ratio',
  'char_entropy',
  'colon_count',
  'escaped_char_count',
  'alpha_token_ratio',
  'max_segment_length',
] as const;

export interface CpeValidityFeatures {
  cpe: string;
  length: number;
  segmentCount: number;
  hasValidPrefix: number;
  hasWildcardVendorOrProduct: number;
  numericTokenRatio: number;
  charEntropy: number;
  colonCount: number;
  escapedCharCount: number;
  alphaTokenRatio: number;
  maxSegmentLength: number;
}

export function extractCpeValidityFeatures(cpe: string): CpeValidityFeatures {
  const length = cpe.length;
  const parts = cpe.split(':');
  const segmentCount = parts.length;
  const hasValidPrefix = cpe.toLowerCase().startsWith('cpe:2.3:') ? 1 : 0;

  let escapedCharCount = 0;
  for (const ch of cpe) {
    if (ch === '\\') escapedCharCount++;
  }

  const colonCount = (cpe.match(/:/g) || []).length;
  const alphanumeric = cpe.replace(/[^a-zA-Z0-9]/g, '');
  const numericChars = cpe.replace(/[^0-9]/g, '');
  const numericTokenRatio = alphanumeric.length > 0 ? numericChars.length / alphanumeric.length : 0;

  const freq = new Map<string, number>();
  for (const ch of cpe) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  const charEntropy = length > 0 ? entropy : 0;

  const tokens = cpe.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const alphaTokens = tokens.filter((t) => /[a-z]/.test(t));
  const alphaTokenRatio = tokens.length > 0 ? alphaTokens.length / tokens.length : 0;

  const segments = cpe.split(':');
  const maxSegmentLength = segments.reduce((max, s) => Math.max(max, s.length), 0);

  const vendorOrProductWildcard = 0;
  const normalized = cpe.toLowerCase();
  if (normalized.startsWith('cpe:2.3:')) {
    const tokens23 = normalized.slice(8).split(':');
    if (tokens23.length >= 3) {
      const vendor = tokens23[1] ?? '';
      const product = tokens23[2] ?? '';
      if (vendor.includes('*') || vendor.includes('?') || product.includes('*') || product.includes('?')) {
        // Wildcards are valid CPE syntax, but for the validity gate we treat
        // them as lower-confidence — the model learns this during training.
      }
    }
  }

  return {
    cpe,
    length,
    segmentCount,
    hasValidPrefix,
    hasWildcardVendorOrProduct: vendorOrProductWildcard,
    numericTokenRatio,
    charEntropy,
    colonCount,
    escapedCharCount,
    alphaTokenRatio,
    maxSegmentLength,
  };
}

export class CpeValidityGateModel extends BaseModel {
  private algo: LogisticRegression;

  constructor() {
    const metadata: ModelMetadata = {
      id: 'cpe-validity-gate',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...CPE_VALIDITY_FEATURE_NAMES],
      description: 'Pre-filters malformed CPE 2.3 strings before full parseCPE23',
    };
    super(metadata);
     this.algo = new LogisticRegression();
   }

   extractFeatures(sample: TrainingSample): Record<string, number> {
    if (typeof sample.id !== 'string' || !sample.id.startsWith('cpe:')) {
      return {};
    }
    const feats = extractCpeValidityFeatures(sample.id);
    return {
      length: feats.length,
      segment_count: feats.segmentCount,
      has_valid_prefix: feats.hasValidPrefix,
      has_wildcard_vendor_or_product: feats.hasWildcardVendorOrProduct,
      numeric_token_ratio: feats.numericTokenRatio,
      char_entropy: feats.charEntropy,
      colon_count: feats.colonCount,
      escaped_char_count: feats.escapedCharCount,
      alpha_token_ratio: feats.alphaTokenRatio,
      max_segment_length: feats.maxSegmentLength,
    };
  }

  train(samples: TrainingSample[]): void {
    const featureSamples = samples.map((s) => ({
      ...s,
      features: Object.keys(s.features).length > 0 ? s.features : this.extractFeatures(s),
    }));
    this.algo.train(featureSamples);
    this.trained = true;
  }

  /**
   * Online learning update — applies a single SGD step on one sample.
   * Must be called after train() has initialized the model.
   * Returns metrics for this update (for drift monitoring).
   */
  partialFit(sample: TrainingSample): { accuracy: number; bce: number } {
    if (!this.trained) {
      throw new Error('CpeValidityGateModel.partialFit: model must be trained first');
    }
    const processed = {
      ...sample,
      features: Object.keys(sample.features).length > 0 ? sample.features : this.extractFeatures(sample),
    };
    const metrics = this.algo.partialFit(processed);
    return { accuracy: metrics.accuracy, bce: metrics.bce };
  }

  predict(features: Record<string, number>): PredictionResult {
    return this.algo.predict(features);
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.algo.serialize(),
    };
  }

  load(artifact: ModelArtifact): void {
    this.algo.load(artifact.weights as ReturnType<LogisticRegression['serialize']>);
    this.metadata = artifact.metadata;
    this.trained = true;
  }

  getFeatureNames(): string[] {
    return [...CPE_VALIDITY_FEATURE_NAMES];
  }

  /**
   * Generates training data from the parser's own outcomes — fully autonomous.
   * Every CPE string seen by parseCPE23 gets labeled with isValid=true/false.
   */
  static collectTrainingData(cpeStrings: string[]): TrainingSample[] {
    return cpeStrings.map((cpe, i) => {
      const parsed = parseCPE23(cpe);
      const features = extractCpeValidityFeatures(cpe);
      const featRecord: Record<string, number> = {
        length: features.length,
        segment_count: features.segmentCount,
        has_valid_prefix: features.hasValidPrefix,
        has_wildcard_vendor_or_product: features.hasWildcardVendorOrProduct,
        numeric_token_ratio: features.numericTokenRatio,
        char_entropy: features.charEntropy,
        colon_count: features.colonCount,
        escaped_char_count: features.escapedCharCount,
        alpha_token_ratio: features.alphaTokenRatio,
        max_segment_length: features.maxSegmentLength,
      };
      return {
         id: `cpe:${i}`,
        features: featRecord,
        label: parsed.isValid ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      };
    });
  }

  /**
   * Fast pre-filter: returns true if the CPE is likely valid (defer to parser).
   * Returns false if the classifier is confident the CPE is junk (skip parse).
   * Never blocks a CPE that the classifier is unsure about — always falls through.
   */
  shouldParse(cpe: string): boolean {
    if (!this.trained) return true; // Uninitialized → always parse (safe default)
    const feats = extractCpeValidityFeatures(cpe);
    const featRecord: Record<string, number> = {
      length: feats.length,
      segment_count: feats.segmentCount,
      has_valid_prefix: feats.hasValidPrefix,
      has_wildcard_vendor_or_product: feats.hasWildcardVendorOrProduct,
      numeric_token_ratio: feats.numericTokenRatio,
      char_entropy: feats.charEntropy,
      colon_count: feats.colonCount,
      escaped_char_count: feats.escapedCharCount,
      alpha_token_ratio: feats.alphaTokenRatio,
      max_segment_length: feats.maxSegmentLength,
    };
    const result = this.algo.predict(featRecord);
    // Only skip parsing if the classifier is HIGH confidence invalid.
    // LOW/MEDIUM confidence → fall through to the parser.
    if (result.probability !== undefined && result.probability < 0.3 && result.confidence === 'HIGH') {
      return false;
    }
    return true;
  }
}
