/**
 * Alias Confidence Model — binary classifier that predicts whether a finding
 * derived from an alias-based (looser) match is a confirmed true positive,
 * replacing the hardcoded `isConfirmedFinding()` boolean gate in
 * aliasLifecycle.ts:277.
 *
 * File target: src/utils/aliasLifecycle.ts:277 (isConfirmedFinding)
 *
 * The current logic uses a fixed set of status checks:
 *   FALSE_POSITIVE -> not confirmed
 *   NOT_APPLICABLE / SUPPRESSED_VEX_NOT_AFFECTED -> not confirmed
 *   RESOLVED / PATCH_APPLIED -> confirmed
 *   autoDispatchedAt set -> confirmed
 *   AUTO_DISPATCHED / DELIVERED -> confirmed
 *
 * This model learns P(alias_match_is_confirmed) from finding features, so
 * that the alias promotion threshold can be tuned based on historical
 * true-positive rates rather than a fixed boolean.
 *
 * Uses LogisticRegression. Training data comes from correlation_matches
 * where alias-derived findings have known confirmation outcomes.
 */
import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const ALIAS_CONFIDENCE_FEATURE_NAMES = [
  'match_confidence',
  'cvss_score',
  'epss_score',
  'cisa_kev',
  'exploit_status',
  'days_since_published',
  'source_feed_weight',
  'has_version_evidence',
  'match_method_alias',
  'match_method_fallback',
  'match_method_keyword',
] as const;

export interface AliasConfidenceFeatures {
  matchConfidence: number;
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: number;
  daysSincePublished: number;
  sourceFeedWeight: number;
  hasVersionEvidence: boolean;
  matchMethod: string;
}

export function extractAliasConfidenceFeatures(f: AliasConfidenceFeatures): Record<string, number> {
  return {
    match_confidence: f.matchConfidence,
    cvss_score: f.cvssScore,
    epss_score: f.epssScore,
    cisa_kev: f.cisaKev ? 1 : 0,
    exploit_status: f.exploitStatus,
    days_since_published: f.daysSincePublished,
    source_feed_weight: f.sourceFeedWeight,
    has_version_evidence: f.hasVersionEvidence ? 1 : 0,
    match_method_alias: f.matchMethod === 'VENDOR_PRODUCT_ALIAS' ? 1 : 0,
    match_method_fallback: f.matchMethod === 'VENDOR_PRODUCT_FALLBACK' ? 1 : 0,
    match_method_keyword: f.matchMethod === 'KEYWORD' ? 1 : 0,
  };
}

export class AliasConfidenceModel extends BaseModel {
  private readonly algo: LogisticRegression;

  constructor() {
    const metadata: ModelMetadata = {
      id: 'alias-confidence-model',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...ALIAS_CONFIDENCE_FEATURE_NAMES],
      description: 'Predicts confirmation probability for alias-derived findings',
    };
    super(metadata);
    this.algo = new LogisticRegression();
  }

  train(samples: TrainingSample[]): void {
    this.algo.train(samples, { threshold: 0.5, iterations: 1000 });
    this.trained = true;
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  predict(features: Record<string, number>): PredictionResult {
    return this.algo.predict(features);
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return this.algo.predictBatch(features);
  }

  predictConfirmationProbability(f: AliasConfidenceFeatures): number {
    const feats = extractAliasConfidenceFeatures(f);
    const result = this.predict(feats);
    return result.probability ?? result.score;
  }

  isConfirmed(f: AliasConfidenceFeatures, threshold = 0.5): boolean {
    if (!this.trained) {
      return this.hardcodedCheck(f);
    }
    const prob = this.predictConfirmationProbability(f);
    return prob >= threshold;
  }

  /**
   * Online learning update — one SGD step on a single confirmed/not-confirmed
   * sample. Lets the drift checker absorb gradual label drift without a full
   * retrain. Must be called after train() has initialized the model.
   */
  partialFit(sample: TrainingSample): { accuracy: number; bce: number } {
    if (!this.trained) {
      throw new Error('AliasConfidenceModel.partialFit: model must be trained first');
    }
    const metrics = this.algo.partialFit(sample);
    return { accuracy: metrics.accuracy, bce: metrics.bce };
  }

  private hardcodedCheck(f: AliasConfidenceFeatures): boolean {
    if (f.matchConfidence === 0) return false;
    if (f.cisaKev) return true;
    if (f.epssScore >= 0.4) return true;
    if (f.exploitStatus > 0) return true;
    return f.matchConfidence >= 70;
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
    return [...ALIAS_CONFIDENCE_FEATURE_NAMES];
  }

  static collectTrainingData(samples: Array<{
    features: AliasConfidenceFeatures;
    isConfirmed: boolean;
  }>): TrainingSample[] {
    return samples.map((s, i) => ({
      id: `alias-${i}`,
      features: extractAliasConfidenceFeatures(s.features),
      label: s.isConfirmed ? 1 : 0,
      weight: 1,
      timestamp: new Date().toISOString(),
    }));
  }
}
