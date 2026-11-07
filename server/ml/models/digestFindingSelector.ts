/**
 * Digest Finding Selector — binary classifier that predicts whether a finding
 * should be included in a recipient's daily digest, replacing the
 * subscription-only filtering in dailyDigest.ts:464.
 *
 * File target: server/dailyDigest.ts:464 (findings.filter(recipientAllows))
 *
 * Beyond the existing subscription-gate (must have access), this model ranks
 * findings by relevance to the recipient's subscription tier and historical
 * engagement, so that only the most relevant findings surface in the digest.
 *
 * Uses LogisticRegression to predict P(finding_is_relevant_to_recipient) from
 * finding features and recipient subscription tier.
 *
 * Training data: historical findings delivered to recipients with known
 * outcomes (PATCHED/RESOLVED/DELIVERED within 30 days = relevant).
 */
import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const DIGEST_SELECTION_FEATURE_NAMES = [
  'cvss_score',
  'epss_score',
  'cisa_kev',
  'exploit_status',
  'days_since_published',
  'source_feed_weight',
  'credibility_score',
  'asset_criticality',
  'recipient_tier_all',
  'recipient_tier_critical',
  'recipient_tier_subscribed',
  'finding_in_digest',
  'time_in_digest_minutes',
] as const;

export interface DigestSelectionFeatures {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: number;
  daysSincePublished: number;
  sourceFeedWeight: number;
  credibilityScore: number;
  assetCriticality: number;
  recipientTier: 'ALL' | 'CRITICAL_ONLY' | 'SUBSCRIBED_ONLY';
  findingInDigest: boolean;
  timeInDigestMinutes: number;
}

export function extractDigestSelectionFeatures(f: DigestSelectionFeatures): Record<string, number> {
  return {
    cvss_score: f.cvssScore,
    epss_score: f.epssScore,
    cisa_kev: f.cisaKev ? 1 : 0,
    exploit_status: f.exploitStatus,
    days_since_published: f.daysSincePublished,
    source_feed_weight: f.sourceFeedWeight,
    credibility_score: f.credibilityScore,
    asset_criticality: f.assetCriticality,
    recipient_tier_all: f.recipientTier === 'ALL' ? 1 : 0,
    recipient_tier_critical: f.recipientTier === 'CRITICAL_ONLY' ? 1 : 0,
    recipient_tier_subscribed: f.recipientTier === 'SUBSCRIBED_ONLY' ? 1 : 0,
    finding_in_digest: f.findingInDigest ? 1 : 0,
    time_in_digest_minutes: f.timeInDigestMinutes,
  };
}

export class DigestFindingSelector extends BaseModel {
  private readonly algo: LogisticRegression;

  constructor() {
    const metadata: ModelMetadata = {
      id: 'digest-finding-selector',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...DIGEST_SELECTION_FEATURE_NAMES],
      description: 'Selects the most relevant findings for digest delivery per recipient',
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

  selectForDigest(f: DigestSelectionFeatures): number {
    const feats = extractDigestSelectionFeatures(f);
    const result = this.predict(feats);
    return result.probability ?? result.score;
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
    return [...DIGEST_SELECTION_FEATURE_NAMES];
  }

  static collectTrainingData(samples: Array<{
    features: DigestSelectionFeatures;
    isRelevant: boolean;
  }>): TrainingSample[] {
    return samples.map((s, i) => ({
      id: `digest-${i}`,
      features: extractDigestSelectionFeatures(s.features),
      label: s.isRelevant ? 1 : 0,
      weight: 1,
      timestamp: new Date().toISOString(),
    }));
  }
}