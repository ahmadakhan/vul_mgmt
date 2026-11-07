/**
 * Finding Importance Ranker — GBDT ranking model that orders findings within
 * severity buckets in the daily digest, replacing the arbitrary
 * `slice(0, 25)` truncation and recency-only sort in findingSort.ts:13
 * and templateCompiler.ts:652.
 *
 * File target: src/utils/findingSort.ts:13 (compareFindingsByRecency)
 *              src/utils/templateCompiler.ts:652 (items.slice(0, 25))
 *              server/dailyDigest.ts:464 (finding filtering)
 *
 * Features:
 *   cvss_score, epss_score, cisa_kev, exploit_status,
 *   cwe_risk_level, days_since_published, source_feed_weight,
 *   credibility_score, has_version_evidence, asset_criticality
 *
 * Learns from finding outcome history: PATCHED/RESOLVED/DELIVERED = positive,
 * FALSE_POSITIVE/never_actioned = negative. The label encodes both actionability
 * and urgency (1 + 1/(days_to_action + 1)).
 */
import { GBDTRanker } from '../algorithms/gbdtRanker.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const FINDING_IMPORTANCE_FEATURES = [
  'cvss_score',
  'epss_score',
  'cisa_kev',
  'exploit_status',
  'cwe_risk_level',
  'days_since_published',
  'source_feed_weight',
  'credibility_score',
  'has_version_evidence',
  'asset_criticality',
] as const;

export interface FindingImportanceFeatures {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: number;
  cweRiskLevel: number;
  daysSincePublished: number;
  sourceFeedWeight: number;
  credibilityScore: number;
  hasVersionEvidence: boolean;
  assetCriticality: number;
}

export function extractFindingImportanceFeatures(f: FindingImportanceFeatures): Record<string, number> {
  return {
    cvss_score: f.cvssScore,
    epss_score: f.epssScore,
    cisa_kev: f.cisaKev ? 1 : 0,
    exploit_status: f.exploitStatus,
    cwe_risk_level: f.cweRiskLevel,
    days_since_published: f.daysSincePublished,
    source_feed_weight: f.sourceFeedWeight,
    credibility_score: f.credibilityScore,
    has_version_evidence: f.hasVersionEvidence ? 1 : 0,
    asset_criticality: f.assetCriticality,
  };
}

export class FindingImportanceRanker extends BaseModel {
  private gbdt: GBDTRanker;

  constructor() {
    const metadata: ModelMetadata = {
      id: 'finding-importance-ranker',
      type: 'gbdt_ranker',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...FINDING_IMPORTANCE_FEATURES],
      description: 'Ranks findings by importance for digest display',
    };
    super(metadata);
    this.gbdt = new GBDTRanker();
  }

  extractFeatures(sample: TrainingSample): Record<string, number> {
    return sample.features;
  }

  train(samples: TrainingSample[]): void {
    this.gbdt.train(samples, [...FINDING_IMPORTANCE_FEATURES]);
    this.trained = true;
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  predict(features: Record<string, number>): PredictionResult {
    return this.gbdt.predict(features);
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return this.gbdt.predictBatch(features);
  }

  rank(findings: FindingImportanceFeatures[]): number[] {
    const features = findings.map(extractFindingImportanceFeatures);
    const predictions = this.predictBatch(features);
    return predictions.map((p) => p.score);
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.gbdt.serialize(),
    };
  }

  load(artifact: ModelArtifact): void {
    this.gbdt = new GBDTRanker();
    const weights = artifact.weights as ReturnType<GBDTRanker['serialize']>;
    this.gbdt.load(weights);
    this.metadata = artifact.metadata;
    this.trained = true;
  }

  getFeatureNames(): string[] {
    return [...FINDING_IMPORTANCE_FEATURES];
  }

  static collectTrainingData(samples: Array<{
    features: FindingImportanceFeatures;
    wasActionable: boolean;
    daysToAction: number;
  }>): TrainingSample[] {
    return samples.map((s, i) => {
      const label = s.wasActionable ? 1 + 1 / (s.daysToAction + 1) : 0;
      return {
        id: `importance-${i}`,
        features: extractFindingImportanceFeatures(s.features),
        label,
        weight: 1,
        timestamp: new Date().toISOString(),
      };
    });
  }
}
