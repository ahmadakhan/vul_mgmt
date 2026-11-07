/**
 * Severity Tier Model — multi-class classifier that predicts the severity
 * tier for a finding, replacing the hardcoded weighted scoring with fixed
 * weights and thresholds in severityClassifier.ts.
 *
 * File target: src/utils/severityClassifier.ts (classifySeverity / classifyTier)
 *
 * Uses one LogisticRegression per tier (one-vs-all), following the same
 * multi-output pattern as AdvisoryRemediationHelper and ExploitRiskModel.
 * The tier with the highest predicted probability wins.
 *
 * Replaced hardcoded logic:
 *   score = cvss * 0.6 + exploit_weight + cisa_kev_weight + epss_weight + cwe_weights
 *   tier thresholds: >=90 CRITICAL, >=70 HIGH, >=40 MEDIUM, >=10 LOW, else INFORMATIONAL
 *
 * Training data: correlation_matches with cvss_score, epss_score, cisa_kev,
 * exploit_status, cwe_risk_level, source_feed_weight, and observed tier.
 */
import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const SEVERITY_TIERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'] as const;

export type SeverityTier = (typeof SEVERITY_TIERS)[number];

export const SEVERITY_TIER_FEATURE_NAMES = [
  'cvss_score',
  'epss_score',
  'cisa_kev',
  'exploit_status',
  'cwe_risk_level',
  'days_since_published',
  'source_feed_weight',
] as const;

export interface SeverityTierFeatures {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: string;
  cweRiskLevel: number;
  daysSincePublished: number;
  sourceFeedWeight: number;
}

export function extractSeverityTierFeatures(f: SeverityTierFeatures): Record<string, number> {
  const statusMap: Record<string, number> = {
    'Active Weaponized': 3,
    'Reported In Wild': 2,
    'POC Available': 1,
    None: 0,
  };

  return {
    cvss_score: f.cvssScore,
    epss_score: f.epssScore,
    cisa_kev: f.cisaKev ? 1 : 0,
    exploit_status: statusMap[f.exploitStatus] ?? 0,
    cwe_risk_level: f.cweRiskLevel,
    days_since_published: f.daysSincePublished,
    source_feed_weight: f.sourceFeedWeight,
  };
}

export class SeverityTierModel extends BaseModel {
  private readonly models: Map<string, LogisticRegression> = new Map();
  private readonly featureNames = [...SEVERITY_TIER_FEATURE_NAMES];

  constructor() {
    const metadata: ModelMetadata = {
      id: 'severity-tier-model',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...SEVERITY_TIER_FEATURE_NAMES],
      description: 'Predicts severity tier (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)',
    };
    super(metadata);
  }

  train(samples: TrainingSample[]): void {
    const tierSets = new Map<string, TrainingSample[]>();
    for (const tier of SEVERITY_TIERS) {
      tierSets.set(tier, []);
    }

    for (const s of samples) {
      const tier = typeof s.label === 'number'
        ? SEVERITY_TIERS[Math.floor(s.label)]
        : SEVERITY_TIERS[s.label ? 0 : 4];

      if (!tier) continue;
      const existing = tierSets.get(tier) ?? [];
      existing.push({ ...s, label: 1 });
      tierSets.set(tier, existing);

      for (const otherTier of SEVERITY_TIERS) {
        if (otherTier === tier) continue;
        const others = tierSets.get(otherTier) ?? [];
        others.push({ ...s, label: 0 });
        tierSets.set(otherTier, others);
      }
    }

    for (const [tier, tierSamples] of tierSets) {
      const positives = tierSamples.filter((s) => s.label === 1).length;
      const negatives = tierSamples.filter((s) => s.label === 0).length;
      if (positives >= 4 && negatives >= 4) {
        const lr = new LogisticRegression();
        lr.train(tierSamples, { threshold: 0.5, iterations: 1000 });
        this.models.set(tier, lr);
      }
    }
    this.trained = this.models.size > 0;
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  predict(features: Record<string, number>): PredictionResult {
    if (!this.trained || this.models.size === 0) {
      return { score: 0, probability: 0, confidence: 'LOW', reason: 'model untrained — using hardcoded tier thresholds' };
    }

    let bestTier = 'INFORMATIONAL';
    let bestProb = 0;
    const allProbs: Record<string, number> = {};

    for (const tier of SEVERITY_TIERS) {
      const lr = this.models.get(tier);
      if (!lr) {
        allProbs[tier] = 0;
        continue;
      }
      const pred = lr.predict(features);
      allProbs[tier] = pred.score;
      if (pred.score > bestProb) {
        bestProb = pred.score;
        bestTier = tier;
      }
    }

    const ranked = SEVERITY_TIERS.filter((t) => this.models.has(t)).sort((a, b) => allProbs[b] - allProbs[a]);
    const confidence: PredictionResult['confidence'] = ranked.length >= 2 && bestProb - allProbs[ranked[1]] > 0.15 ? 'HIGH' : bestProb > 0.7 ? 'HIGH' : bestProb > 0.4 ? 'MEDIUM' : 'LOW';

    const probsStr = SEVERITY_TIERS.map((t) => `${t}=${allProbs[t]?.toFixed(2) ?? 'n/a'}`).join(', ');
    return {
      score: SEVERITY_TIERS.indexOf(bestTier as SeverityTier),
      probability: bestProb,
      confidence,
      reason: `predicted ${bestTier} (P=${bestProb.toFixed(3)}); ${probsStr}`,
    };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  predictTier(f: SeverityTierFeatures): SeverityTier {
    if (!this.trained) return 'INFORMATIONAL';
    const feats = extractSeverityTierFeatures(f);
    const result = this.predict(feats);
    return SEVERITY_TIERS[result.score] ?? 'INFORMATIONAL';
  }

  serialize(): ModelArtifact {
    const serialized: Record<string, unknown> = {};
    for (const [tier, lr] of this.models) {
      serialized[tier] = lr.serialize();
    }
    return {
      metadata: this.metadata,
      weights: {
        models: serialized,
        featureNames: [...this.featureNames],
      },
    };
  }

  load(artifact: ModelArtifact): void {
    const data = artifact.weights as { models: Record<string, unknown>; featureNames: string[] };
    this.models.clear();
    for (const [tier, weights] of Object.entries(data.models)) {
      const lr = new LogisticRegression();
      lr.load(weights as ReturnType<LogisticRegression['serialize']>);
      this.models.set(tier, lr);
    }
    this.metadata = artifact.metadata;
    this.trained = this.models.size > 0;
  }

  getFeatureNames(): string[] {
    return [...this.featureNames];
  }

  getTiers(): SeverityTier[] {
    return [...SEVERITY_TIERS];
  }

  static collectTrainingData(samples: Array<{
    features: SeverityTierFeatures;
    tier: SeverityTier;
  }>): TrainingSample[] {
    return samples.map((s, i) => ({
      id: `severity-${i}`,
      features: extractSeverityTierFeatures(s.features),
      label: SEVERITY_TIERS.indexOf(s.tier),
      weight: 1,
      timestamp: new Date().toISOString(),
    }));
  }
}
