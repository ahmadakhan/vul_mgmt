/**
 * Review-Queue Ranker — GBDT ranking model that orders REVIEW_REQUIRED findings
 * so the most actionable items surface first in notification batches.
 *
 * File target: pipelineEngine.ts:397-401 (finding push to REVIEW_REQUIRED)
 *
 * Features:
 *   match_confidence, cvss_score, epss_score, cisa_kev, exploit_status,
 *   cwe_risk_level, signal_density, match_method, source_feed_weight,
 *   asset_exposure, has_version_evidence
 *
 * Learns from: finding timeline transitions (REVIEW_REQUIRED → DELIVERED/PATCHED/RESOLVED
 * vs. REVIEW_REQUIRED → FALSE_POSITIVE/never_actioned).
 */
import { GBDTRanker } from '../algorithms/gbdtRanker.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const REVIEW_RANKER_FEATURES = [
  'match_confidence',
  'cvss_score',
  'epss_score',
  'cisa_kev',
  'exploit_status',
  'cwe_risk_level',
  'signal_density',
  'match_method_strict_cpe',
  'match_method_purl_exact',
  'match_method_alias',
  'match_method_fallback',
  'source_feed_weight',
  'asset_criticality',
  'has_version_evidence',
  'days_since_published',
  'negated',
] as const;

export interface FindingFeatures {
  matchConfidence: number;
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: number; // 0=None, 1=Reported In Wild, 2=POC, 3=Weaponized
  cweRiskLevel: number; // 0=low-risk CWE, 1=medium, 2=high
  signalDensity: number;
  matchMethod: string;
  sourceFeedWeight: number;
  assetCriticality: number;
  hasVersionEvidence: boolean;
  daysSincePublished: number;
  negated: boolean;
}

export function extractFindingFeatures(f: FindingFeatures): Record<string, number> {
  const methodStrict = f.matchMethod === 'STRICT_CPE' || f.matchMethod === 'STRICT_CPE_INTERVAL' ? 1 : 0;
  const methodPurl = f.matchMethod === 'PURL_EXACT' ? 1 : 0;
  const methodAlias = f.matchMethod === 'VENDOR_PRODUCT_ALIAS' ? 1 : 0;
  const methodFallback = f.matchMethod === 'VENDOR_PRODUCT_FALLBACK' ? 1 : 0;

  return {
    match_confidence: f.matchConfidence,
    cvss_score: f.cvssScore,
    epss_score: f.epssScore,
    cisa_kev: f.cisaKev ? 1 : 0,
    exploit_status: f.exploitStatus,
    cwe_risk_level: f.cweRiskLevel,
    signal_density: f.signalDensity,
    match_method_strict_cpe: methodStrict,
    match_method_purl_exact: methodPurl,
    match_method_alias: methodAlias,
    match_method_fallback: methodFallback,
    source_feed_weight: f.sourceFeedWeight,
    asset_criticality: f.assetCriticality,
    has_version_evidence: f.hasVersionEvidence ? 1 : 0,
    days_since_published: f.daysSincePublished,
    negated: f.negated ? 1 : 0,
  };
}

export class ReviewRankerModel extends BaseModel {
  private gbdt: GBDTRanker;

  constructor() {
    const metadata: ModelMetadata = {
      id: 'review-ranker',
      type: 'gbdt_ranker',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...REVIEW_RANKER_FEATURES],
      description: 'Ranks REVIEW_REQUIRED findings by true-positive probability',
    };
    super(metadata);
    this.gbdt = new GBDTRanker();
  }

  extractFeatures(sample: TrainingSample): Record<string, number> {
    return sample.features;
  }

  train(samples: TrainingSample[]): void {
    this.gbdt.train(samples, [...REVIEW_RANKER_FEATURES]);
    this.trained = true;
  }

  predict(features: Record<string, number>): PredictionResult {
    return this.gbdt.predict(features);
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return this.gbdt.predictBatch(features);
  }

  getFeatureNames(): string[] {
    return [...REVIEW_RANKER_FEATURES];
  }

  override load(artifact: ModelArtifact): void {
    this.gbdt = new GBDTRanker();
    const weights = artifact.weights as ReturnType<GBDTRanker['serialize']>;
    this.gbdt.load(weights);
    this.metadata = artifact.metadata;
    this.trained = true;
  }

  override serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.gbdt.serialize(),
    };
  }

  /** Collects training data from finding outcome history. */
  static collectTrainingData(findings: Array<{
    features: FindingFeatures;
    statusAfterReview: 'FALSE_POSITIVE' | 'PATCHED' | 'RESOLVED' | 'DELIVERED' | 'EXPIRED';
    daysToAction: number;
  }>): TrainingSample[] {
    return findings.map((f, i) => {
      const isPositive = f.statusAfterReview === 'PATCHED' || f.statusAfterReview === 'RESOLVED' || f.statusAfterReview === 'DELIVERED';
      const label = isPositive ? 1 + (1 / (f.daysToAction + 1)) : 0; // higher = more actionable
      return {
        id: `finding-${i}`,
        features: extractFindingFeatures(f.features),
        label,
        weight: 1,
        timestamp: new Date().toISOString(),
      };
    });
  }
}
