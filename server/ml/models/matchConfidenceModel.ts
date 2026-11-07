/**
 * Match Confidence Model — learns the true confidence of a CPE/version match,
 * replacing the hardcoded per-method confidence values in cpeMatcher.ts
 * (100/95/90/85/70/0) and cpeSimulation.ts.
 *
 * File target: src/utils/cpeMatcher.ts (match confidence assignment)
 *              src/utils/cpeSimulation.ts (confidence tier computation)
 *
 * Uses a single LogisticRegression to predict P(match_is_true_positive)
 * from match-method features, version evidence, and CVE indicators.
 * The predicted probability * 100 becomes the new confidence score.
 *
 * Training data: correlation_matches with match method, version evidence,
 * and observed outcome (PATCHED/RESOLVED/DELIVERED = true positive).
 */
import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const MATCH_CONFIDENCE_FEATURE_NAMES = [
  'match_method_strict_cpe',
  'match_method_strict_cpe_interval',
  'match_method_purl_exact',
  'match_method_vendor_alias',
  'match_method_vendor_fallback',
  'match_method_keyword',
  'match_method_fallback',
  'has_version_evidence',
  'version_verified_in_range',
  'cvss_score',
  'epss_score',
  'cisa_kev',
  'source_feed_weight',
  'days_since_published',
  'negated',
] as const;

export interface MatchConfidenceFeatures {
  matchMethod: string;
  hasVersionEvidence: boolean;
  versionVerifiedInRange: boolean;
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  sourceFeedWeight: number;
  daysSincePublished: number;
  negated: boolean;
}

export function extractMatchConfidenceFeatures(f: MatchConfidenceFeatures): Record<string, number> {
  const methodStrict = f.matchMethod === 'STRICT_CPE' || f.matchMethod === 'STRICT_CPE_INTERVAL' ? 1 : 0;
  const methodPurl = f.matchMethod === 'PURL_EXACT' ? 1 : 0;
  const methodAlias = f.matchMethod === 'VENDOR_PRODUCT_ALIAS' ? 1 : 0;
  const methodFallback = f.matchMethod === 'VENDOR_PRODUCT_FALLBACK' ? 1 : 0;
  const methodKeyword = f.matchMethod === 'KEYWORD' ? 1 : 0;
  const methodUnknownFallback = f.matchMethod === 'UNKNOWN' || f.matchMethod === '' ? 1 : 0;

  return {
    match_method_strict_cpe: methodStrict,
    match_method_strict_cpe_interval: f.matchMethod === 'STRICT_CPE_INTERVAL' ? 1 : 0,
    match_method_purl_exact: methodPurl,
    match_method_vendor_alias: methodAlias,
    match_method_vendor_fallback: methodFallback,
    match_method_keyword: methodKeyword,
    match_method_fallback: methodUnknownFallback,
    has_version_evidence: f.hasVersionEvidence ? 1 : 0,
    version_verified_in_range: f.versionVerifiedInRange ? 1 : 0,
    cvss_score: f.cvssScore,
    epss_score: f.epssScore,
    cisa_kev: f.cisaKev ? 1 : 0,
    source_feed_weight: f.sourceFeedWeight,
    days_since_published: f.daysSincePublished,
    negated: f.negated ? 1 : 0,
  };
}

export class MatchConfidenceModel extends BaseModel {
  private readonly algo: LogisticRegression;

  constructor() {
    const metadata: ModelMetadata = {
      id: 'match-confidence-model',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...MATCH_CONFIDENCE_FEATURE_NAMES],
      description: 'Predicts true confidence score for CPE/version matches',
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

  predictConfidence(f: MatchConfidenceFeatures): number {
    const feats = extractMatchConfidenceFeatures(f);
    const result = this.predict(feats);
    return Math.round(result.probability! * 100);
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
    return [...MATCH_CONFIDENCE_FEATURE_NAMES];
  }

  static collectTrainingData(samples: Array<{
    features: MatchConfidenceFeatures;
    isTruePositive: boolean;
  }>): TrainingSample[] {
    return samples.map((s, i) => ({
      id: `match-${i}`,
      features: extractMatchConfidenceFeatures(s.features),
      label: s.isTruePositive ? 1 : 0,
      weight: 1,
      timestamp: new Date().toISOString(),
    }));
  }
}
