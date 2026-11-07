/**
 * Advisory Remediation Helper — predicts the completeness of a finding's
 * RemediationPlaybook and generates fallback remediation content when
 * vendor data is sparse.
 *
 * File target: src/utils/templateCompiler.ts:249-292 (remediation template fields)
 *              src/types/index.ts:186 (RemediationPlaybook)
 *
 * Uses a lightweight logistic regression per field to predict the probability
 * that each remediation field (patchUrl, vendorAdvisoryRef, immediateActions,
 * workarounds, rollbackPlan, stepByStep) is available and useful.
 *
 * Features are derived from finding metadata: cvss_score, cisa_kev, days_since_published,
 * source_feed_weight, has_version_evidence, cwe_risk_level, epss_score.
 *
 * Training data comes from historical findings where remediation completeness
 * was observed (either vendor-provided or previously reviewed by operators).
 */
import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import type { PredictionResult, TrainingSample, ModelArtifact, ModelMetadata } from '../types.ts';
import type { RemediationPlaybook } from '../../../src/types/index.ts';

export const REMEDIATION_FIELD_NAMES = [
  'has_patch_url',
  'has_vendor_advisory',
  'has_immediate_actions',
  'has_workarounds',
  'has_rollback_plan',
  'has_step_by_step',
] as const;

export interface RemediationFeatures {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  daysSincePublished: number;
  sourceFeedWeight: number;
  hasVersionEvidence: boolean;
  cweRiskLevel: number;
  exploitStatus: number;
}

export interface RemediationPrediction {
  patchUrl: number;
  vendorAdvisory: number;
  immediateActions: number;
  workarounds: number;
  rollbackPlan: number;
  stepByStep: number;
  overall: number;
  recommendation: 'complete' | 'partial' | 'sparse';
  generatedContent: Partial<RemediationPlaybook>;
}

export function extractRemediationFeatures(f: RemediationFeatures): Record<string, number> {
  return {
    cvss_score: f.cvssScore,
    epss_score: f.epssScore,
    cisa_kev: f.cisaKev ? 1 : 0,
    days_since_published: f.daysSincePublished,
    source_feed_weight: f.sourceFeedWeight,
    has_version_evidence: f.hasVersionEvidence ? 1 : 0,
    cwe_risk_level: f.cweRiskLevel,
    exploit_status: f.exploitStatus,
  };
}

const FIELD_TO_PLAYBOOK_KEY: Record<string, keyof Partial<RemediationPlaybook>> = {
  has_patch_url: 'patchUrl',
  has_vendor_advisory: 'vendorAdvisoryRef',
  has_immediate_actions: 'immediateActions',
  has_workarounds: 'workarounds',
  has_rollback_plan: 'rollbackPlan',
  has_step_by_step: 'stepByStep',
};

export class AdvisoryRemediationHelper {
  private models: Map<string, LogisticRegression> = new Map();
  private metadata: ModelMetadata;
  private trained = false;

  constructor() {
    this.metadata = {
      id: 'advisory-remediation-helper',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...REMEDIATION_FIELD_NAMES],
      description: 'Predicts remediation playbook completeness and generates fallback content',
    };
  }

  /**
   * Trains one logistic regression per remediation field.
   * Each TrainingSample represents a finding with features and a label
   * indicating which field was present (label=1) or missing (label=0).
   * The sample id encodes the field name: `field:hash`.
   */
  train(samples: TrainingSample[]): void {
    const fieldSamples = new Map<string, TrainingSample[]>();
    for (const field of REMEDIATION_FIELD_NAMES) {
      fieldSamples.set(field, []);
    }

    for (const s of samples) {
      const fieldName = s.id.split(':')[0] ?? '';
      if (fieldName && fieldSamples.has(fieldName)) {
        fieldSamples.get(fieldName)!.push(s);
      }
    }

    for (const [field, fieldSamplesList] of fieldSamples) {
      if (fieldSamplesList.length >= 4) {
        const lr = new LogisticRegression();
        lr.train(fieldSamplesList, { threshold: 0.5, iterations: 500 });
        this.models.set(field, lr);
      }
    }
    this.trained = true;
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  /**
   * Online learning update — applies a single SGD step to the LR model
   * for the field specified in sample.id (format: "fieldName:timestamp").
   * Must be called after train() has initialized all models.
   * Returns metrics for this update (for drift monitoring).
   */
  partialFit(sample: TrainingSample): { accuracy: number; bce: number; field: string } {
    if (!this.trained) {
      throw new Error('AdvisoryRemediationHelper.partialFit: model must be trained first');
    }
    const fieldName = sample.id.split(':')[0] ?? '';
    const lr = this.models.get(fieldName);
    if (!lr) {
      throw new Error(`AdvisoryRemediationHelper.partialFit: no model for field "${fieldName}"`);
    }
    const metrics = lr.partialFit(sample);
    return { accuracy: metrics.accuracy, bce: metrics.bce, field: fieldName };
  }

  /**
   * Predicts the probability of each remediation field being available
   * and generates fallback content for missing fields.
   */
  predictRemediation(f: RemediationFeatures, actualPlaybook?: Partial<RemediationPlaybook>): RemediationPrediction {
    const feats = extractRemediationFeatures(f);

    const probs: Record<string, number> = {};
    for (const field of REMEDIATION_FIELD_NAMES) {
      const lr = this.models.get(field);
      if (lr) {
        probs[field] = lr.predict(feats).score;
      } else {
        probs[field] = this.defaultProbability(field, feats);
      }
    }

    const overall = (probs.has_patch_url * 0.3 +
      probs.has_vendor_advisory * 0.2 +
      probs.has_immediate_actions * 0.2 +
      probs.has_workarounds * 0.15 +
      probs.has_rollback_plan * 0.1 +
      probs.has_step_by_step * 0.25) / 1.2;

    let recommendation: RemediationPrediction['recommendation'];
    if (overall >= 0.7) recommendation = 'complete';
    else if (overall >= 0.4) recommendation = 'partial';
    else recommendation = 'sparse';

    const generatedContent = this.generateFallback(f, actualPlaybook);

    return {
      patchUrl: probs.has_patch_url,
      vendorAdvisory: probs.has_vendor_advisory,
      immediateActions: probs.has_immediate_actions,
      workarounds: probs.has_workarounds,
      rollbackPlan: probs.has_rollback_plan,
      stepByStep: probs.has_step_by_step,
      overall,
      recommendation,
      generatedContent,
    };
  }

  private defaultProbability(field: string, feats: Record<string, number>): number {
    switch (field) {
      case 'has_patch_url':
        return feats.cvss_score > 7 ? 0.3 : feats.cvss_score > 4 ? 0.4 : 0.2;
      case 'has_vendor_advisory':
        return feats.cisa_kev > 0.5 ? 0.8 : feats.source_feed_weight > 20 ? 0.6 : 0.3;
      case 'has_immediate_actions':
        return feats.exploit_status > 2 ? 0.7 : feats.exploit_status > 1 ? 0.5 : 0.3;
      case 'has_workarounds':
        return feats.epss_score > 0.5 ? 0.4 : 0.6;
      case 'has_rollback_plan':
        return feats.cvss_score > 8 ? 0.6 : feats.cvss_score > 4 ? 0.4 : 0.2;
      case 'has_step_by_step':
        return feats.has_version_evidence > 0.5 ? 0.7 : 0.4;
      default:
        return 0.5;
    }
  }

  private generateFallback(
    f: RemediationFeatures,
    actual?: Partial<RemediationPlaybook>,
  ): Partial<RemediationPlaybook> {
    const content: Partial<RemediationPlaybook> = { ...actual };

    if (!content.vendorAdvisoryRef) {
      if (f.cisaKev) {
        content.vendorAdvisoryRef = `https://www.cisa.gov/news-events/known-exploited-vulnerabilities-catalog`;
      }
    }
    if (!content.immediateActions || content.immediateActions.length === 0) {
      content.immediateActions = [
        'Confirm applicability and review vendor guidance through the approved change process.',
      ];
    }
    if (!content.workarounds || content.workarounds.length === 0) {
      content.workarounds = [
        'No verified vendor workaround is available. Consult the vendor before changing system configuration.',
      ];
    }
    if (!content.stepByStep || content.stepByStep.length === 0) {
      content.stepByStep = [
        'Confirm the affected component and version.',
        'Obtain vendor-approved remediation and assess operational impact.',
        'Test the proposed change and rollback procedure before production deployment.',
      ];
    }
    if (!content.rollbackPlan) {
      content.rollbackPlan = 'Use the approved, tested backup and rollback procedure for the affected system.';
    }

    return content;
  }

  predict(features: Record<string, number>): PredictionResult {
    let score: number;
    if (this.trained) {
      let sum = 0;
      let count = 0;
      for (const field of REMEDIATION_FIELD_NAMES) {
        const lr = this.models.get(field);
        if (lr) {
          const result = lr.predict(features);
          sum += result.score;
          count++;
        }
      }
      score = count > 0 ? sum / count : this.defaultProbability('has_patch_url', features);
    } else {
      score = this.defaultProbability('has_patch_url', features);
    }
    const confidence: PredictionResult['confidence'] = Math.abs(score - 0.5) > 0.3 ? 'HIGH' : 'MEDIUM';
    return { score, confidence, reason: `remediation completeness estimate=${score.toFixed(3)}` };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  serialize(): ModelArtifact {
    const serializedModels: Record<string, unknown> = {};
    for (const [field, lr] of this.models) {
      serializedModels[field] = lr.serialize();
    }
    return {
      metadata: this.metadata,
      weights: {
        models: serializedModels,
        featureNames: [...REMEDIATION_FIELD_NAMES],
      },
    };
  }

  load(artifact: ModelArtifact): void {
    const data = artifact.weights as { models: Record<string, Record<string, unknown>>; featureNames: string[] };
    this.models.clear();
    for (const [field, weights] of Object.entries(data.models)) {
      const lr = new LogisticRegression();
      lr.load(weights as unknown as ReturnType<LogisticRegression['serialize']>);
      this.models.set(field, lr);
    }
    this.metadata = artifact.metadata;
    this.trained = this.models.size > 0;
  }

  getFeatureNames(): string[] {
    return [...REMEDIATION_FIELD_NAMES];
  }

  getMetadata(): ModelMetadata {
    return this.metadata;
  }

  isTrained(): boolean {
    return this.trained;
  }

  /** Generates training data from findings with observed remediation completeness. */
  static collectTrainingData(findings: Array<{
    features: RemediationFeatures;
    playbook: Partial<RemediationPlaybook>;
  }>): TrainingSample[] {
    return findings.flatMap((f, i) => {
      const feats = extractRemediationFeatures(f.features);
      return REMEDIATION_FIELD_NAMES.map((field) => ({
        id: `${field}:${i}`,
        features: feats,
        label: f.playbook[FIELD_TO_PLAYBOOK_KEY[field]] ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      }));
    });
  }
}
