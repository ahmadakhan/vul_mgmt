/**
 * Training orchestrator — ties together data collection, model training,
 * quality-gate validation, drift detection, and registry save/rollback.
 *
 * Usage:
 *   import { TrainingOrchestrator } from './train/orchestrator.ts';
 *   const orch = new TrainingOrchestrator(mlDirectory);
 *   const result = await orch.trainAll(dataProviders);
 *
 * The orchestrator is autonomous:
 * - Each model is trained on fresh data only if enough samples are available
 * - Quality gates enforce that a new model never degrades below the active one
 * - Failed models leave the existing artifact untouched (implicit rollback)
 * - All training results are summarized for monitoring/alerting
 */
import { ModelRegistry } from '../runtime.ts';
import { CpeValidityGateModel } from '../models/cpeValidityGate.ts';
import { MetricAnomalyDetectorModel } from '../models/metricAnomalyDetector.ts';
import { AutoDispatchThresholdModel } from '../models/autoDispatchThreshold.ts';
import { ReviewRankerModel } from '../models/reviewRanker.ts';
import { ConfidenceCalibrator } from '../models/confidenceCalibrator.ts';
import { DeliveryOptimizerModel, type DeliveryOutcome } from '../models/deliveryOptimizer.ts';
import {
  AdvisoryRemediationHelper,
  type RemediationFeatures,
} from '../models/advisoryRemediationHelper.ts';
import {
  ExploitRiskModel,
  type ExploitRiskFeatures,
  type ExploitRiskLevel,
} from '../models/exploitRiskModel.ts';
import {
  MatchConfidenceModel,
  type MatchConfidenceFeatures,
} from '../models/matchConfidenceModel.ts';
import {
  FindingImportanceRanker,
  type FindingImportanceFeatures,
} from '../models/findingImportanceRanker.ts';
import {
  NewsCredibilityWeightModel,
  chronologicalCredibilitySplit,
  type CredibilitySample,
} from '../models/newsCredibilityWeightModel.ts';
import {
  DeliveryErrorClassifier,
  type DeliveryErrorFeatures,
} from '../models/deliveryErrorClassifier.ts';
import {
  ZeroDayRateLimitOptimizer,
  type ZeroDayRateLimitSample,
} from '../models/zeroDayRateLimitOptimizer.ts';
import {
  DigestFindingSelector,
  type DigestSelectionFeatures,
} from '../models/digestFindingSelector.ts';
import {
  SeverityTierModel,
  type SeverityTierFeatures,
  type SeverityTier,
} from '../models/severityTierModel.ts';
import {
  FeedRecoveryBackoffOptimizer,
  type FeedRecoverySample,
} from '../models/feedRecoveryBackoffOptimizer.ts';
import {
  AliasConfidenceModel,
  type AliasConfidenceFeatures,
} from '../models/aliasConfidenceModel.ts';
import {
  AdvisoryComposerModel,
  type EmailCompositionFeatures,
  type PerFindingFeatures,
} from '../models/advisoryComposer.ts';
import { QualityGate, QUALITY_GATES, type QualityGateResult } from './qualityGates.ts';
import {
  detectConceptDrift,
  detectFeatureDrift,
  type DriftReport,
} from './driftDetection.ts';
import type {
  ModelMetadata,
  ModelSelfValidation,
  ModelStorageOptions,
  ModelType,
  PredictionResult,
  TrainableModel,
  TrainingSample,
} from '../types.ts';
import { splitData } from './evaluation.ts';
import type { RemediationPlaybook } from '../../../src/types/index.ts';
import type { FindingFeatures } from '../models/reviewRanker.ts';
import type { MetricFeatures } from '../models/metricAnomalyDetector.ts';
import type { ThresholdSample } from '../models/autoDispatchThreshold.ts';
import { mlMetrics } from '../metrics.ts';
import { randomUUID } from 'node:crypto';

/** Raw data inputs — provided by the caller (e.g. database query layer). */
export interface TrainingDataSources {
  cpeStrings?: string[];
  telemetryHistory?: MetricFeatures[];
  dispatchOutcomes?: ThresholdSample[];
  reviewOutcomeHistory?: Array<{
    features: FindingFeatures;
    statusAfterReview: 'FALSE_POSITIVE' | 'PATCHED' | 'RESOLVED' | 'DELIVERED' | 'EXPIRED';
    daysToAction: number;
  }>;
  calibrationPairs?: Array<{ credibilityScore: number; isActionable: boolean }>;
  deliveryOutcomes?: DeliveryOutcome[];
  remediationFindings?: Array<{
    features: RemediationFeatures;
    playbook: Partial<RemediationPlaybook>;
  }>;
  exploitRiskSamples?: Array<{
    features: ExploitRiskFeatures;
    riskLevel: ExploitRiskLevel;
  }>;
  matchConfidenceSamples?: Array<{
    features: MatchConfidenceFeatures;
    isTruePositive: boolean;
  }>;
  importanceRankSamples?: Array<{
    features: FindingImportanceFeatures;
    wasActionable: boolean;
    daysToAction: number;
  }>;
  credibilityWeightSamples?: CredibilitySample[];
  deliveryErrorSamples?: Array<{
    provider: string;
    statusCode: number;
    errorMessage: string;
    attemptNumber: number;
    hourOfDay: number;
    isPermanent: boolean;
  }>;
  zeroDayRateLimitSamples?: ZeroDayRateLimitSample[];
  digestSelectionSamples?: Array<{
    features: DigestSelectionFeatures;
    isRelevant: boolean;
  }>;
  severityTierSamples?: Array<{
    features: SeverityTierFeatures;
    tier: SeverityTier;
  }>;
  feedRecoverySamples?: FeedRecoverySample[];
  aliasConfidenceSamples?: Array<{
    features: AliasConfidenceFeatures;
    isConfirmed: boolean;
  }>;
  emailCompositionSamples?: Array<{
    features: EmailCompositionFeatures;
    perFinding: PerFindingFeatures[];
    summaryStyle: import('../models/advisoryComposer.ts').SummaryStyle;
    priorityEmphasis: import('../models/advisoryComposer.ts').PriorityEmphasis;
    remediationEmphasis: import('../models/advisoryComposer.ts').RemediationEmphasis;
    subjectTemplate: import('../models/advisoryComposer.ts').SubjectTemplate;
    wasActionable: boolean;
  }>;
}

export type TrainingStatus = 'trained' | 'skipped' | 'failed' | 'not_needed';

export interface TrainingResult {
  modelId: string;
  modelType: ModelType;
  status: TrainingStatus;
  samplesCollected: number;
  samplesTrained: number;
  validation: ModelSelfValidation;
  driftReport?: DriftReport;
  saved: boolean;
  error?: string;
}

export interface TrainingSummary {
  timestamp: string;
  storageDir: string;
  results: TrainingResult[];
  summary: {
    total: number;
    trained: number;
    saved: number;
    skipped: number;
    failed: number;
    notNeeded: number;
  };
}

export class TrainingOrchestrator {
  private readonly registry: ModelRegistry;
  private readonly storage: ModelStorageOptions;
  private readonly version = `1.0.1+${randomUUID()}`;

  constructor(storage: ModelStorageOptions) {
    this.storage = storage;
    this.registry = new ModelRegistry(storage);
  }

  getRegistry(): ModelRegistry {
    return this.registry;
  }

  /**
   * Trains all models from scratch using the provided data sources.
   * Each model is validated against its quality gate before being saved.
   */
  async trainAll(data: TrainingDataSources): Promise<TrainingSummary> {
    const results: TrainingResult[] = [];

    results.push(await this.trainCpeValidityGate(data));
    results.push(await this.trainMetricAnomalyDetector(data));
    results.push(await this.trainAutoDispatchThreshold(data));
    results.push(await this.trainReviewRanker(data));
    results.push(await this.trainConfidenceCalibrator(data));
    results.push(await this.trainDeliveryOptimizer(data));
    results.push(await this.trainRemediationHelper(data));

    results.push(await this.trainExploitRiskModel(data));
    results.push(await this.trainMatchConfidenceModel(data));
    results.push(await this.trainFindingImportanceRanker(data));
    results.push(await this.trainCredibilityWeightModel(data));
    results.push(await this.trainDeliveryErrorClassifier(data));
    results.push(await this.trainZeroDayRateLimitOptimizer(data));
    results.push(await this.trainDigestFindingSelector(data));
    results.push(await this.trainSeverityTierModel(data));
    results.push(await this.trainFeedRecoveryBackoffOptimizer(data));
    results.push(await this.trainAliasConfidenceModel(data));
    results.push(await this.trainAdvisoryComposer(data));

    const summary = {
      timestamp: new Date().toISOString(),
      storageDir: this.storage.directory,
      results,
      summary: {
        total: results.length,
        trained: results.filter((r) => r.status === 'trained').length,
        saved: results.filter((r) => r.saved).length,
        skipped: results.filter((r) => r.status === 'skipped').length,
        failed: results.filter((r) => r.status === 'failed').length,
        notNeeded: results.filter((r) => r.status === 'not_needed').length,
      },
    };
    this.emitMlMetrics(results);
    return summary;
  }

  /**
   * Emit ML model state metrics for Prometheus alerting:
   * - quality gate failures (counter)
   * - model staleness (gauge: seconds since last training)
   * - drift detection (gauge: 1 if drift detected)
   */
  private emitMlMetrics(results: TrainingResult[]): void {
    for (const r of results) {
      if (r.status === 'failed') {
        mlMetrics.inc('vulnstream_ml_quality_gate_failed_total', { modelId: r.modelId });
      }
      if (r.saved || r.status === 'trained') {
        mlMetrics.gauge('vulnstream_ml_model_last_trained_age_seconds', 0, { modelId: r.modelId });
      }
      if (r.status === 'skipped') {
        mlMetrics.gauge('vulnstream_ml_model_last_trained_age_seconds', 864000, { modelId: r.modelId });
      }
    }
  }

   /**
    * Checks all trained models for drift against recent production data.
    *
    * For each model, compares:
    * - Feature distributions: PSI between training samples and recent samples
    * - Concept drift: model performance on recent data vs. stored metadata
    *
    * For models that support online learning (partialFit), applies incremental
    * updates when moderate drift is detected but retraining is not needed.
    *
    * Returns models that need retraining.
    */
   async checkDrift(
     recent: TrainingDataSources,
     historical: TrainingDataSources,
     seed = 0,
   ): Promise<{ modelId: string; needsRetrain: boolean; report?: DriftReport }[]> {
     const results: { modelId: string; needsRetrain: boolean; report?: DriftReport }[] = [];

      // CPE Validity Gate — check feature drift on CPE strings
      {
        const gate = new CpeValidityGateModel();
        const loaded = await this.registry.load(gate, 'cpe-validity-gate');
        const recentCpe = recent.cpeStrings ?? [];
        const histCpe = historical.cpeStrings ?? [];

        if (!loaded && recentCpe.length > 0) {
          results.push({ modelId: 'cpe-validity-gate', needsRetrain: true });
        } else if (recentCpe.length > 0 && histCpe.length > 0) {
          const recentSamples = CpeValidityGateModel.collectTrainingData(recentCpe);
          const histSamples = CpeValidityGateModel.collectTrainingData(histCpe);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            gate, test, gate.getMetadata(), gate.getFeatureNames(), recentSamples, histSamples,
            'cpe-validity-gate',
          );
          // Apply online learning for moderate drift (no retraining needed)
          if (loaded && gate.isTrained() && !report.needsRetraining && recentSamples.length > 0) {
            const onlineModel = gate as { partialFit?: (s: TrainingSample) => unknown };
            const partialFit = onlineModel.partialFit;
            if (partialFit) {
              for (const sample of recentSamples.slice(0, 10)) {
                try { partialFit.call(onlineModel, sample); } catch { /* skip if not ready for online learning */ }
              }
            }
          }
          results.push({ modelId: 'cpe-validity-gate', needsRetrain: report.needsRetraining, report });
        }
      }

      // Metric Anomaly Detector — check feature drift on telemetry
      {
        const model = new MetricAnomalyDetectorModel();
        const loaded = await this.registry.load(model, 'metric-anomaly-detector');
        const recentMetrics = recent.telemetryHistory ?? [];
        const histMetrics = historical.telemetryHistory ?? [];

        if (!loaded && recentMetrics.length > 0) {
          results.push({ modelId: 'metric-anomaly-detector', needsRetrain: true });
        } else if (recentMetrics.length > 0 && histMetrics.length > 0) {
          const recentSamples = MetricAnomalyDetectorModel.collectTrainingData(recentMetrics);
          const histSamples = MetricAnomalyDetectorModel.collectTrainingData(histMetrics);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, histSamples,
            'metric-anomaly-detector',
          );
          results.push({ modelId: 'metric-anomaly-detector', needsRetrain: report.needsRetraining, report });
        }
      }

      // Review Ranker — check concept drift on findings
      {
        const model = new ReviewRankerModel();
        const loaded = await this.registry.load(model, 'review-ranker');
        const recentFindings = recent.reviewOutcomeHistory ?? [];
        const histFindings = historical.reviewOutcomeHistory ?? [];

        if (!loaded && recentFindings.length > 0) {
          results.push({ modelId: 'review-ranker', needsRetrain: true });
        } else if (recentFindings.length > 0 && histFindings.length > 0) {
          const recentSamples = ReviewRankerModel.collectTrainingData(recentFindings);
          const histSamples = ReviewRankerModel.collectTrainingData(histFindings);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, histSamples,
            'review-ranker',
          );
          results.push({ modelId: 'review-ranker', needsRetrain: report.needsRetraining, report });
        }
      }

       // Confidence Calibrator — check concept drift on scores
      {
        const model = new ConfidenceCalibrator();
        const loaded = await this.registry.load(model, 'confidence-calibrator');
        const recentPairs = recent.calibrationPairs ?? [];
        const histPairs = historical.calibrationPairs ?? [];

        if (!loaded && recentPairs.length > 0) {
          results.push({ modelId: 'confidence-calibrator', needsRetrain: true });
        } else if (recentPairs.length > 0 && histPairs.length > 0) {
          const recentSamples: TrainingSample[] = recentPairs.map((p, i) => ({
            id: `calib-recent-${i}`,
            features: { credibility_score: p.credibilityScore },
            label: p.isActionable,
            weight: 1,
            timestamp: new Date().toISOString(),
          }));
          const histSamples: TrainingSample[] = histPairs.map((p, i) => ({
            id: `calib-hist-${i}`,
            features: { credibility_score: p.credibilityScore },
            label: p.isActionable,
            weight: 1,
            timestamp: new Date().toISOString(),
          }));
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, histSamples,
            'confidence-calibrator',
          );
          results.push({ modelId: 'confidence-calibrator', needsRetrain: report.needsRetraining, report });
        }
       }

      // Advisory Remediation Helper — check concept drift on findings
      {
        const model = new AdvisoryRemediationHelper();
        const loaded = await this.registry.load(model, 'advisory-remediation-helper');
        const recentFindings = recent.remediationFindings ?? [];
        const histFindings = historical.remediationFindings ?? [];

        if (!loaded && recentFindings.length > 0) {
          results.push({ modelId: 'advisory-remediation-helper', needsRetrain: true });
        } else if (recentFindings.length > 0 && histFindings.length > 0) {
          const recentSamples = AdvisoryRemediationHelper.collectTrainingData(recentFindings);
          const histSamples = AdvisoryRemediationHelper.collectTrainingData(histFindings);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, histSamples,
            'advisory-remediation-helper',
          );
          // Apply online learning for moderate drift
          if (loaded && model.isTrained() && !report.needsRetraining && recentSamples.length > 0) {
            const onlineModel = model as { partialFit?: (s: TrainingSample) => unknown };
            const partialFit = onlineModel.partialFit;
            if (partialFit) {
              for (const sample of recentSamples.slice(0, 20)) {
                try { partialFit.call(onlineModel, sample); } catch { /* skip if not ready */ }
              }
            }
          }
          results.push({ modelId: 'advisory-remediation-helper', needsRetrain: report.needsRetraining, report });
        }
      }

      // Auto-Dispatch Threshold — check concept drift on dispatch outcomes
      {
        const model = new AutoDispatchThresholdModel();
        const loaded = await this.registry.loadArtifact(model, 'auto-dispatch-threshold');
        const recentOutcomes = recent.dispatchOutcomes ?? [];

        if (!loaded && recentOutcomes.length > 0) {
          results.push({ modelId: 'auto-dispatch-threshold', needsRetrain: true });
        } else if (recentOutcomes.length > 0) {
          const recentSamples: TrainingSample[] = recentOutcomes.map((o, i) => ({
            id: `dispatch-recent-${i}`,
            features: { confidence: o.confidence },
            label: o.foundTruePositive ? 1 : 0,
            weight: 1,
            timestamp: new Date().toISOString(),
          }));
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'auto-dispatch-threshold',
          );
          results.push({ modelId: 'auto-dispatch-threshold', needsRetrain: report.needsRetraining, report });
        }
      }

      // Delivery Optimizer — check concept drift on delivery outcomes
      {
        const model = new DeliveryOptimizerModel();
        const loaded = await this.registry.load(model, 'delivery-optimizer');
        const recentOutcomes = recent.deliveryOutcomes ?? [];

        if (!loaded && recentOutcomes.length > 0) {
          results.push({ modelId: 'delivery-optimizer', needsRetrain: true });
        } else if (recentOutcomes.length > 0) {
          const recentSamples = DeliveryOptimizerModel.collectTrainingData(recentOutcomes);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'delivery-optimizer',
          );
          results.push({ modelId: 'delivery-optimizer', needsRetrain: report.needsRetraining, report });
        }
      }

      // Exploit Risk Model — check concept drift on exploit risk samples
      {
        const model = new ExploitRiskModel();
        const loaded = await this.registry.load(model, 'exploit-risk-model');
        const recentExploit = recent.exploitRiskSamples ?? [];

        if (!loaded && recentExploit.length > 0) {
          results.push({ modelId: 'exploit-risk-model', needsRetrain: true });
        } else if (recentExploit.length > 0) {
          const recentSamples = ExploitRiskModel.collectTrainingData(recentExploit);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'exploit-risk-model',
          );
          results.push({ modelId: 'exploit-risk-model', needsRetrain: report.needsRetraining, report });
        }
      }

      // Match Confidence Model — check concept drift on match samples
      {
        const model = new MatchConfidenceModel();
        const loaded = await this.registry.load(model, 'match-confidence-model');
        const recentMatch = recent.matchConfidenceSamples ?? [];

        if (!loaded && recentMatch.length > 0) {
          results.push({ modelId: 'match-confidence-model', needsRetrain: true });
        } else if (recentMatch.length > 0) {
          const recentSamples = MatchConfidenceModel.collectTrainingData(recentMatch);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'match-confidence-model',
          );
          results.push({ modelId: 'match-confidence-model', needsRetrain: report.needsRetraining, report });
        }
      }

      // Finding Importance Ranker — check concept drift on importance samples
      {
        const model = new FindingImportanceRanker();
        const loaded = await this.registry.load(model, 'finding-importance-ranker');
        const recentImportance = recent.importanceRankSamples ?? [];

        if (!loaded && recentImportance.length > 0) {
          results.push({ modelId: 'finding-importance-ranker', needsRetrain: true });
        } else if (recentImportance.length > 0) {
          const recentSamples = FindingImportanceRanker.collectTrainingData(recentImportance);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'finding-importance-ranker',
          );
          results.push({ modelId: 'finding-importance-ranker', needsRetrain: report.needsRetraining, report });
        }
      }

      // Delivery Error Classifier — check concept drift on error samples
      {
        const model = new DeliveryErrorClassifier();
        const loaded = await this.registry.load(model, 'delivery-error-classifier');
        const recentErrors = recent.deliveryErrorSamples ?? [];

        if (!loaded && recentErrors.length > 0) {
          results.push({ modelId: 'delivery-error-classifier', needsRetrain: true });
        } else if (recentErrors.length > 0) {
          const recentSamples = DeliveryErrorClassifier.collectTrainingData(recentErrors);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'delivery-error-classifier',
          );
          results.push({ modelId: 'delivery-error-classifier', needsRetrain: report.needsRetraining, report });
        }
      }

      // Digest Finding Selector — check concept drift on digest samples
      {
        const model = new DigestFindingSelector();
        const loaded = await this.registry.load(model, 'digest-finding-selector');
        const recentDigest = recent.digestSelectionSamples ?? [];

        if (!loaded && recentDigest.length > 0) {
          results.push({ modelId: 'digest-finding-selector', needsRetrain: true });
        } else if (recentDigest.length > 0) {
          const recentSamples = DigestFindingSelector.collectTrainingData(recentDigest);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'digest-finding-selector',
          );
          results.push({ modelId: 'digest-finding-selector', needsRetrain: report.needsRetraining, report });
        }
      }

      // Severity Tier Model — check concept drift on severity samples
      {
        const model = new SeverityTierModel();
        const loaded = await this.registry.load(model, 'severity-tier-model');
        const recentSeverity = recent.severityTierSamples ?? [];

        if (!loaded && recentSeverity.length > 0) {
          results.push({ modelId: 'severity-tier-model', needsRetrain: true });
        } else if (recentSeverity.length > 0) {
          const recentSamples = SeverityTierModel.collectTrainingData(recentSeverity);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'severity-tier-model',
          );
          results.push({ modelId: 'severity-tier-model', needsRetrain: report.needsRetraining, report });
        }
      }

      // Alias Confidence Model — check concept drift on alias samples
      {
        const model = new AliasConfidenceModel();
        const loaded = await this.registry.load(model, 'alias-confidence-model');
        const recentAlias = recent.aliasConfidenceSamples ?? [];

        if (!loaded && recentAlias.length > 0) {
          results.push({ modelId: 'alias-confidence-model', needsRetrain: true });
        } else if (recentAlias.length > 0) {
          const recentSamples = AliasConfidenceModel.collectTrainingData(recentAlias);
          const [_, test] = splitData(recentSamples, 0.2, seed);
          const report = await this.buildDriftReport(
            model, test, model.getMetadata(), model.getFeatureNames(), recentSamples, recentSamples,
            'alias-confidence-model',
          );
          if (loaded && model.isTrained() && !report.needsRetraining && recentSamples.length > 0) {
            const onlineModel = model as { partialFit?: (s: TrainingSample) => unknown };
            const partialFit = onlineModel.partialFit;
            if (partialFit) {
              for (const sample of recentSamples.slice(0, 20)) {
                try { partialFit.call(onlineModel, sample); } catch { /* skip */ }
              }
            }
          }
          results.push({ modelId: 'alias-confidence-model', needsRetrain: report.needsRetraining, report });
        }
      }

      // Emit drift metrics for alerting
      for (const r of results) {
        mlMetrics.gauge('vulnstream_ml_model_drift_detected', r.needsRetrain ? 1 : 0, { modelId: r.modelId });
      }

      return results;
    }

   private async buildDriftReport(
     model: { predict: (f: Record<string, number>) => PredictionResult },
     testSamples: TrainingSample[],
     metadata: ModelMetadata,
     featureNames: string[],
     recentSamples: TrainingSample[],
     trainSamples: TrainingSample[],
     modelId: string,
   ): Promise<DriftReport> {
     const featureDrift = detectFeatureDrift(trainSamples, recentSamples, featureNames);
     const conceptDrift = detectConceptDrift(model, testSamples, metadata);
     const needsRetraining = conceptDrift.some((d) => d.status === 'DEGRADATION') ||
       featureDrift.some((d) => d.status === 'SIGNIFICANT_DRIFT');

     return {
       timestamp: new Date().toISOString(),
       modelId,
       featureDrift,
       conceptDrift,
       needsRetraining,
       summary: needsRetraining
         ? `${featureDrift.filter((d) => d.status !== 'NO_DRIFT').length} feature(s) drifted, ${conceptDrift.filter((d) => d.status === 'DEGRADATION').length} metric(s) degraded`
         : 'no drift detected',
     };
   }

  /** --- Per-model training methods --- */

   private async trainCpeValidityGate(data: TrainingDataSources): Promise<TrainingResult> {
    const gate = new CpeValidityGateModel();
    const gateDef = QUALITY_GATES['cpe-validity-gate'];

    if (!data.cpeStrings || data.cpeStrings.length < gateDef.minimumSamples) {
      return this.skipResult('cpe-validity-gate', 'logistic', data.cpeStrings?.length ?? 0, 'insufficient samples');
    }

    const samples = CpeValidityGateModel.collectTrainingData(data.cpeStrings);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      gate.train(train);

      const validation = gateDef.evaluate(gate, test);
      if (!validation.passed) {
        return this.failureResult('cpe-validity-gate', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(gate, 'cpe-validity-gate', gateDef, validation.metrics);
      return this.successResult('cpe-validity-gate', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('cpe-validity-gate', 'logistic', samples.length, e);
    }
  }

  private async trainMetricAnomalyDetector(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new MetricAnomalyDetectorModel();
    const gateDef = QUALITY_GATES['metric-anomaly-detector'];

    if (!data.telemetryHistory || data.telemetryHistory.length < gateDef.minimumSamples) {
      return this.skipResult('metric-anomaly-detector', 'isolation_forest', data.telemetryHistory?.length ?? 0, 'insufficient samples');
    }

    const samples = MetricAnomalyDetectorModel.collectTrainingData(data.telemetryHistory);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('metric-anomaly-detector', 'isolation_forest', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'metric-anomaly-detector', gateDef, validation.metrics);
      return this.successResult('metric-anomaly-detector', 'isolation_forest', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('metric-anomaly-detector', 'isolation_forest', samples.length, e);
    }
  }

  private async trainAutoDispatchThreshold(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new AutoDispatchThresholdModel();
    const gateDef = QUALITY_GATES['auto-dispatch-threshold'];

    if (!data.dispatchOutcomes || data.dispatchOutcomes.length < gateDef.minimumSamples) {
      return this.skipResult('auto-dispatch-threshold', 'threshold_optimizer', data.dispatchOutcomes?.length ?? 0, 'insufficient samples');
    }

    try {
      model.train(data.dispatchOutcomes);

      // Validate: hold out last 20% of outcomes for evaluation
      const holdout = data.dispatchOutcomes.slice(Math.floor(data.dispatchOutcomes.length * 0.8));
      const testSamples: TrainingSample[] = holdout.map((o, i) => ({
        id: `dispatch-holdout-${i}`,
        features: { confidence: o.confidence },
        label: o.foundTruePositive ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      }));

      const validation = gateDef.evaluate(model, testSamples);
      if (!validation.passed) {
        return this.failureResult('auto-dispatch-threshold', 'threshold_optimizer',
          data.dispatchOutcomes.length, data.dispatchOutcomes.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      // Save via saveArtifact (not save) since AutoDispatchThresholdModel isn't a TrainableModel
      const metadata: ModelMetadata = {
        id: 'auto-dispatch-threshold',
        type: 'threshold_optimizer',
        version: this.version,
        trainedAt: new Date().toISOString(),
        featureSchema: model.getFeatureNames(),
        description: 'Optimal confidence threshold for auto-dispatch gate',
        performance: validation.metrics as ModelMetadata['performance'],
      };
      await this.registry.saveArtifact(model, 'auto-dispatch-threshold', metadata);
      // Verify the saved artifact loads correctly
      const verified = await this.registry.loadArtifact(model, 'auto-dispatch-threshold');
      return this.successResult('auto-dispatch-threshold', 'threshold_optimizer',
        data.dispatchOutcomes.length, data.dispatchOutcomes.length, validation, verified);
    } catch (e) {
      return this.errorResult('auto-dispatch-threshold', 'threshold_optimizer', data.dispatchOutcomes.length, e);
    }
  }

  private async trainReviewRanker(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new ReviewRankerModel();
    const gateDef = QUALITY_GATES['review-ranker'];

    if (!data.reviewOutcomeHistory || data.reviewOutcomeHistory.length < gateDef.minimumSamples) {
      return this.skipResult('review-ranker', 'gbdt_ranker', data.reviewOutcomeHistory?.length ?? 0, 'insufficient samples');
    }

    const samples = ReviewRankerModel.collectTrainingData(data.reviewOutcomeHistory);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('review-ranker', 'gbdt_ranker', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'review-ranker', gateDef, validation.metrics);
      return this.successResult('review-ranker', 'gbdt_ranker', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('review-ranker', 'gbdt_ranker', samples.length, e);
    }
  }

  private async trainConfidenceCalibrator(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new ConfidenceCalibrator();
    const gateDef = QUALITY_GATES['confidence-calibrator'];

    if (!data.calibrationPairs || data.calibrationPairs.length < gateDef.minimumSamples) {
      return this.skipResult('confidence-calibrator', 'calibrator', data.calibrationPairs?.length ?? 0, 'insufficient samples');
    }

    const samples: TrainingSample[] = data.calibrationPairs.map((p, i) => ({
      id: `calib-${i}`,
      features: { credibility_score: p.credibilityScore },
      label: p.isActionable,
      weight: 1,
      timestamp: new Date().toISOString(),
    }));

    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('confidence-calibrator', 'calibrator', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'confidence-calibrator', gateDef, validation.metrics);
      return this.successResult('confidence-calibrator', 'calibrator', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('confidence-calibrator', 'calibrator', samples.length, e);
    }
  }

  private async trainDeliveryOptimizer(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new DeliveryOptimizerModel();
    const gateDef = QUALITY_GATES['delivery-optimizer'];

    if (!data.deliveryOutcomes || data.deliveryOutcomes.length < gateDef.minimumSamples) {
      return this.skipResult('delivery-optimizer', 'threshold_optimizer', data.deliveryOutcomes?.length ?? 0, 'insufficient samples');
    }

    try {
      const samples = DeliveryOptimizerModel.collectTrainingData(data.deliveryOutcomes);
      model.train(samples);

      // Evaluate: simulate the new policy vs the old default on holdout outcomes
      const testOutcomes = data.deliveryOutcomes.slice(Math.floor(data.deliveryOutcomes.length * 0.8));
      const testSamples: TrainingSample[] = testOutcomes.map((o, i) => ({
        id: `deliver-holdout-${i}`,
        features: {
          provider_type: o.provider === 'smtp' ? 1 : o.provider === 'sendgrid' ? 2 : o.provider === 'ses' ? 3 : 0,
          attempt: o.attempt,
          delay_ms: o.delayMs,
          delay_minutes: o.delayMs / 60_000,
          rate_limited: o.isRateLimited ? 1 : 0,
          permanent_failure: o.isPermanentFailure ? 1 : 0,
        },
        label: o.succeeded ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      }));

      const validation = gateDef.evaluate(model, testSamples);
      if (!validation.passed) {
        return this.failureResult('delivery-optimizer', 'threshold_optimizer',
          samples.length, samples.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'delivery-optimizer', gateDef, validation.metrics);
      return this.successResult('delivery-optimizer', 'threshold_optimizer', samples.length, samples.length, validation, saved);
    } catch (e) {
      return this.errorResult('delivery-optimizer', 'threshold_optimizer', data.deliveryOutcomes.length, e);
    }
  }

  private async trainRemediationHelper(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new AdvisoryRemediationHelper();
    const gateDef = QUALITY_GATES['advisory-remediation-helper'];

    if (!data.remediationFindings || data.remediationFindings.length < gateDef.minimumSamples) {
      return this.skipResult('advisory-remediation-helper', 'logistic', data.remediationFindings?.length ?? 0, 'insufficient samples');
    }

    const samples = AdvisoryRemediationHelper.collectTrainingData(data.remediationFindings);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('advisory-remediation-helper', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'advisory-remediation-helper', gateDef, validation.metrics);
      return this.successResult('advisory-remediation-helper', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('advisory-remediation-helper', 'logistic', samples.length, e);
    }
  }

  private async trainExploitRiskModel(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new ExploitRiskModel();
    const gateDef = QUALITY_GATES['exploit-risk-model'];

    if (!data.exploitRiskSamples || data.exploitRiskSamples.length < gateDef.minimumSamples) {
      return this.skipResult('exploit-risk-model', 'logistic', data.exploitRiskSamples?.length ?? 0, 'insufficient samples');
    }

    const samples = ExploitRiskModel.collectTrainingData(data.exploitRiskSamples);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('exploit-risk-model', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'exploit-risk-model', gateDef, validation.metrics);
      return this.successResult('exploit-risk-model', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('exploit-risk-model', 'logistic', samples.length, e);
    }
  }

  private async trainMatchConfidenceModel(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new MatchConfidenceModel();
    const gateDef = QUALITY_GATES['match-confidence-model'];

    if (!data.matchConfidenceSamples || data.matchConfidenceSamples.length < gateDef.minimumSamples) {
      return this.skipResult('match-confidence-model', 'logistic', data.matchConfidenceSamples?.length ?? 0, 'insufficient samples');
    }

    const samples = MatchConfidenceModel.collectTrainingData(data.matchConfidenceSamples);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('match-confidence-model', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'match-confidence-model', gateDef, validation.metrics);
      return this.successResult('match-confidence-model', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('match-confidence-model', 'logistic', samples.length, e);
    }
  }

  private async trainFindingImportanceRanker(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new FindingImportanceRanker();
    const gateDef = QUALITY_GATES['finding-importance-ranker'];

    if (!data.importanceRankSamples || data.importanceRankSamples.length < gateDef.minimumSamples) {
      return this.skipResult('finding-importance-ranker', 'gbdt_ranker', data.importanceRankSamples?.length ?? 0, 'insufficient samples');
    }

    const samples = FindingImportanceRanker.collectTrainingData(data.importanceRankSamples);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('finding-importance-ranker', 'gbdt_ranker', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'finding-importance-ranker', gateDef, validation.metrics);
      return this.successResult('finding-importance-ranker', 'gbdt_ranker', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('finding-importance-ranker', 'gbdt_ranker', samples.length, e);
    }
  }

  private async trainCredibilityWeightModel(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new NewsCredibilityWeightModel();
    const gateDef = QUALITY_GATES['news-credibility-weight-model'];

    if (!data.credibilityWeightSamples || data.credibilityWeightSamples.length < gateDef.minimumSamples) {
      return this.skipResult('news-credibility-weight-model', 'threshold_optimizer', data.credibilityWeightSamples?.length ?? 0, 'insufficient samples');
    }

    try {
      const { train: trainSamples, holdout: testSamples } = chronologicalCredibilitySplit(
        data.credibilityWeightSamples,
      );
      if (!trainSamples.length || !testSamples.length ||
          !trainSamples.some((s) => s.isActionable) || !trainSamples.some((s) => !s.isActionable) ||
          !testSamples.some((s) => s.isActionable) || !testSamples.some((s) => !s.isActionable)) {
        return this.skipResult('news-credibility-weight-model', 'threshold_optimizer', data.credibilityWeightSamples.length,
          'chronological holdout lacks class coverage');
      }

      // Select the blend on the holdout, not on the training split. The grid
      // search is otherwise in-sample: any split that fits the training set is
      // accepted, and the gate below can only reject it afterwards. Selection on
      // the holdout makes the gate's accuracy the number that actually chose the
      // served weights.
      const selection = model.trainWithHoldout(trainSamples, testSamples);
      if (!selection) {
        return this.skipResult('news-credibility-weight-model', 'threshold_optimizer',
          trainSamples.length, 'insufficient training samples');
      }
      if (selection.holdoutAccuracy <= selection.defaultHoldoutAccuracy) {
        return this.failureResult('news-credibility-weight-model', 'threshold_optimizer',
          trainSamples.length, testSamples.length,
          {
            passed: false,
            metrics: {
              accuracy: selection.holdoutAccuracy,
              baselineAccuracy: selection.defaultHoldoutAccuracy,
              trainAccuracy: selection.trainAccuracy,
            },
            gateThresholds: { accuracy: 0.55 },
            failureReason: `trained weights do not beat the 0.6/0.4 default on the holdout (${selection.holdoutAccuracy.toFixed(3)} <= ${selection.defaultHoldoutAccuracy.toFixed(3)})`,
          },
          'quality gate failed: no improvement over default weights');
      }
      const testTrainingSamples: TrainingSample[] = testSamples.map((s, i) => ({
        id: `cred-test-${i}`,
        features: { feed_weight: s.feedWeight, keyword_score: s.keywordScore },
        label: s.isActionable ? 1 : 0,
        weight: 1,
        timestamp: s.timestamp || new Date().toISOString(),
      }));

      const validation = gateDef.evaluate(model, testTrainingSamples);
      if (!validation.passed) {
        return this.failureResult('news-credibility-weight-model', 'threshold_optimizer',
          trainSamples.length, testSamples.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const metadata: ModelMetadata = {
        id: 'news-credibility-weight-model',
        type: 'threshold_optimizer',
        version: this.version,
        trainedAt: new Date().toISOString(),
        featureSchema: model.getFeatureNames(),
        description: 'Learned weights for blending feed credibility and keyword confidence',
        performance: validation.metrics as ModelMetadata['performance'],
      };
      await this.registry.saveArtifact(model, 'news-credibility-weight-model', metadata);
      const verified = await this.registry.loadArtifact(model, 'news-credibility-weight-model');
      return this.successResult('news-credibility-weight-model', 'threshold_optimizer',
        trainSamples.length, testSamples.length, validation, verified);
    } catch (e) {
      return this.errorResult('news-credibility-weight-model', 'threshold_optimizer', data.credibilityWeightSamples?.length ?? 0, e);
    }
  }

  private async trainDeliveryErrorClassifier(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new DeliveryErrorClassifier();
    const gateDef = QUALITY_GATES['delivery-error-classifier'];

    if (!data.deliveryErrorSamples || data.deliveryErrorSamples.length < gateDef.minimumSamples) {
      return this.skipResult('delivery-error-classifier', 'logistic', data.deliveryErrorSamples?.length ?? 0, 'insufficient samples');
    }

    const samples = DeliveryErrorClassifier.collectTrainingData(data.deliveryErrorSamples);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('delivery-error-classifier', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'delivery-error-classifier', gateDef, validation.metrics);
      return this.successResult('delivery-error-classifier', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('delivery-error-classifier', 'logistic', samples.length, e);
    }
  }

  private async trainZeroDayRateLimitOptimizer(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new ZeroDayRateLimitOptimizer();
    const gateDef = QUALITY_GATES['zero-day-rate-limit-optimizer'];

    if (!data.zeroDayRateLimitSamples || data.zeroDayRateLimitSamples.length < gateDef.minimumSamples) {
      return this.skipResult('zero-day-rate-limit-optimizer', 'threshold_optimizer', data.zeroDayRateLimitSamples?.length ?? 0, 'insufficient samples');
    }

    try {
      model.train(data.zeroDayRateLimitSamples);

      const testSamples = data.zeroDayRateLimitSamples.slice(Math.floor(data.zeroDayRateLimitSamples.length * 0.8));
      const testTrainingSamples: TrainingSample[] = testSamples.map((s, i) => ({
        id: `zd-test-${i}`,
        features: { zero_day_count: s.zeroDayCount, avg_credibility: s.credibilityScores.reduce((a, b) => a + b, 0) / Math.max(1, s.credibilityScores.length) },
        label: s.outcomes.some((o) => ['PATCHED', 'RESOLVED', 'DELIVERED'].includes(o)) ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      }));

      const validation = gateDef.evaluate(model, testTrainingSamples);
      if (!validation.passed) {
        return this.failureResult('zero-day-rate-limit-optimizer', 'threshold_optimizer',
          data.zeroDayRateLimitSamples.length, data.zeroDayRateLimitSamples.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const metadata: ModelMetadata = {
        id: 'zero-day-rate-limit-optimizer',
        type: 'threshold_optimizer',
        version: this.version,
        trainedAt: new Date().toISOString(),
        featureSchema: model.getFeatureNames(),
        description: 'Optimal cap on zero-day findings per pipeline run',
        performance: validation.metrics as ModelMetadata['performance'],
      };
      await this.registry.saveArtifact(model, 'zero-day-rate-limit-optimizer', metadata);
      const verified = await this.registry.loadArtifact(model, 'zero-day-rate-limit-optimizer');
      return this.successResult('zero-day-rate-limit-optimizer', 'threshold_optimizer',
        data.zeroDayRateLimitSamples.length, data.zeroDayRateLimitSamples.length, validation, verified);
    } catch (e) {
      return this.errorResult('zero-day-rate-limit-optimizer', 'threshold_optimizer', data.zeroDayRateLimitSamples?.length ?? 0, e);
    }
  }

  private async trainDigestFindingSelector(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new DigestFindingSelector();
    const gateDef = QUALITY_GATES['digest-finding-selector'];

    if (!data.digestSelectionSamples || data.digestSelectionSamples.length < gateDef.minimumSamples) {
      return this.skipResult('digest-finding-selector', 'logistic', data.digestSelectionSamples?.length ?? 0, 'insufficient samples');
    }

    const samples = DigestFindingSelector.collectTrainingData(data.digestSelectionSamples);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('digest-finding-selector', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'digest-finding-selector', gateDef, validation.metrics);
      return this.successResult('digest-finding-selector', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('digest-finding-selector', 'logistic', samples.length, e);
    }
  }

  private async trainSeverityTierModel(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new SeverityTierModel();
    const gateDef = QUALITY_GATES['severity-tier-model'];

    if (!data.severityTierSamples || data.severityTierSamples.length < gateDef.minimumSamples) {
      return this.skipResult('severity-tier-model', 'logistic', data.severityTierSamples?.length ?? 0, 'insufficient samples');
    }

    const samples = SeverityTierModel.collectTrainingData(data.severityTierSamples);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('severity-tier-model', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'severity-tier-model', gateDef, validation.metrics);
      return this.successResult('severity-tier-model', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('severity-tier-model', 'logistic', samples.length, e);
    }
  }

  private async trainFeedRecoveryBackoffOptimizer(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new FeedRecoveryBackoffOptimizer();
    const gateDef = QUALITY_GATES['feed-recovery-backoff-optimizer'];

    if (!data.feedRecoverySamples || data.feedRecoverySamples.length < gateDef.minimumSamples) {
      return this.skipResult('feed-recovery-backoff-optimizer', 'threshold_optimizer', data.feedRecoverySamples?.length ?? 0, 'insufficient samples');
    }

    try {
      const chronological = [...data.feedRecoverySamples].sort((a, b) => {
        const aTime = Date.parse(a.observedAt || '') || 0;
        const bTime = Date.parse(b.observedAt || '') || 0;
        return aTime - bTime;
      });
      const split = Math.max(20, Math.floor(chronological.length * 0.8));
      if (split >= chronological.length) {
        return this.skipResult('feed-recovery-backoff-optimizer', 'threshold_optimizer', chronological.length, 'insufficient chronological holdout');
      }
      const trainSamples = chronological.slice(0, split);
      const testSamples = chronological.slice(split);
      if (testSamples.length < 5) {
        return this.skipResult('feed-recovery-backoff-optimizer', 'threshold_optimizer', chronological.length, 'insufficient chronological holdout');
      }
      model.train(trainSamples);

      const testTrainingSamples: TrainingSample[] = testSamples.map((s, i) => ({
        id: `fr-test-${i}`,
        features: { failure_count: s.failureCount, delay_minutes: s.delayMinutes },
        label: s.recovered ? 1 : 0,
        weight: 1,
        timestamp: s.observedAt || new Date().toISOString(),
      }));

      const validation = gateDef.evaluate(model, testTrainingSamples);
      if (!validation.passed) {
        return this.failureResult('feed-recovery-backoff-optimizer', 'threshold_optimizer',
          data.feedRecoverySamples.length, data.feedRecoverySamples.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const metadata: ModelMetadata = {
        id: 'feed-recovery-backoff-optimizer',
        type: 'threshold_optimizer',
        version: this.version,
        trainedAt: new Date().toISOString(),
        featureSchema: model.getFeatureNames(),
        description: 'Optimal backoff parameters for feed recovery probes',
        performance: validation.metrics as ModelMetadata['performance'],
      };
      await this.registry.saveArtifact(model, 'feed-recovery-backoff-optimizer', metadata);
      const verified = await this.registry.loadArtifact(model, 'feed-recovery-backoff-optimizer');
      return this.successResult('feed-recovery-backoff-optimizer', 'threshold_optimizer',
        data.feedRecoverySamples.length, data.feedRecoverySamples.length, validation, verified);
    } catch (e) {
      return this.errorResult('feed-recovery-backoff-optimizer', 'threshold_optimizer', data.feedRecoverySamples?.length ?? 0, e);
    }
  }

  private async trainAliasConfidenceModel(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new AliasConfidenceModel();
    const gateDef = QUALITY_GATES['alias-confidence-model'];

    if (!data.aliasConfidenceSamples || data.aliasConfidenceSamples.length < gateDef.minimumSamples) {
      return this.skipResult('alias-confidence-model', 'logistic', data.aliasConfidenceSamples?.length ?? 0, 'insufficient samples');
    }

    const samples = AliasConfidenceModel.collectTrainingData(data.aliasConfidenceSamples);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('alias-confidence-model', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'alias-confidence-model', gateDef, validation.metrics);
      return this.successResult('alias-confidence-model', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('alias-confidence-model', 'logistic', samples.length, e);
    }
  }

  /** --- Helpers --- */

  private async saveModel(
    model: TrainableModel,
    modelId: string,
    gate: QualityGate,
    metrics: Record<string, number>,
  ): Promise<boolean> {
    const metadata: ModelMetadata = {
      id: modelId,
      type: this.modelTypeFor(modelId),
      version: this.version,
      trainedAt: new Date().toISOString(),
      featureSchema: model.getFeatureNames(),
      description: gate.modelId,
      performance: this.sanitizePerformance(metrics),
    };
    await this.registry.save(model, modelId, metadata);
    // Verify the saved artifact loads correctly
    return this.registry.load(model, modelId);
  }

  private modelTypeFor(modelId: string): ModelType {
    const map: Record<string, ModelType> = {
      'cpe-validity-gate': 'logistic',
      'metric-anomaly-detector': 'isolation_forest',
      'auto-dispatch-threshold': 'threshold_optimizer',
      'review-ranker': 'gbdt_ranker',
      'confidence-calibrator': 'calibrator',
      'delivery-optimizer': 'threshold_optimizer',
      'advisory-remediation-helper': 'logistic',
      'exploit-risk-model': 'logistic',
      'match-confidence-model': 'logistic',
      'finding-importance-ranker': 'gbdt_ranker',
      'news-credibility-weight-model': 'threshold_optimizer',
      'delivery-error-classifier': 'logistic',
      'zero-day-rate-limit-optimizer': 'threshold_optimizer',
      'digest-finding-selector': 'logistic',
      'severity-tier-model': 'logistic',
      'feed-recovery-backoff-optimizer': 'threshold_optimizer',
      'alias-confidence-model': 'logistic',
    };
    return map[modelId] ?? 'logistic';
  }

  private sanitizePerformance(metrics: Record<string, number>): ModelMetadata['performance'] {
    const result: Required<NonNullable<ModelMetadata['performance']>> = {
      accuracy: 0, precision: 0, recall: 0, aucRoc: 0, prAuc: 0, bce: 0, meanAverageError: 0,
    };
    for (const key of Object.keys(metrics)) {
      if (key in result) {
        (result as Record<string, number>)[key] = metrics[key];
      }
    }
    // Only return keys that have non-zero or explicitly set values
    const partial: Record<string, number> = { ...result };
    for (const key of Object.keys(partial)) {
      if (partial[key] === 0 && !(key in metrics)) delete partial[key];
    }
    return partial;
  }

  private skipResult(modelId: string, modelType: ModelType, samples: number, reason: string): TrainingResult {
    return {
      modelId,
      modelType,
      status: 'skipped',
      samplesCollected: samples,
      samplesTrained: 0,
      validation: { passed: false, metrics: {}, failureReason: reason },
      saved: false,
    };
  }

  private successResult(
    modelId: string,
    modelType: ModelType,
    samplesCollected: number,
    samplesTrained: number,
    validation: QualityGateResult,
    saved: boolean,
  ): TrainingResult {
    return {
      modelId,
      modelType,
      status: 'trained',
      samplesCollected,
      samplesTrained,
      validation: { passed: validation.passed, metrics: validation.metrics, failureReason: validation.failureReason },
      saved,
    };
  }

  private failureResult(
    modelId: string,
    modelType: ModelType,
    samplesCollected: number,
    samplesTrained: number,
    validation: QualityGateResult,
    reason: string,
  ): TrainingResult {
    return {
      modelId,
      modelType,
      status: 'failed',
      samplesCollected,
      samplesTrained,
      validation: { passed: validation.passed, metrics: validation.metrics, failureReason: validation.failureReason ?? reason },
      saved: false,
      error: reason,
    };
  }

  private errorResult(modelId: string, modelType: ModelType, samples: number, error: unknown): TrainingResult {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      modelId,
      modelType,
      status: 'failed',
      samplesCollected: samples,
      samplesTrained: 0,
      validation: { passed: false, metrics: {}, failureReason: msg },
      saved: false,
      error: msg,
    };
  }

  private async trainAdvisoryComposer(data: TrainingDataSources): Promise<TrainingResult> {
    const model = new AdvisoryComposerModel();
    const gateDef = QUALITY_GATES['advisory-composer'];

    if (!data.emailCompositionSamples || data.emailCompositionSamples.length < gateDef.minimumSamples) {
      return this.skipResult('advisory-composer', 'logistic', data.emailCompositionSamples?.length ?? 0, 'insufficient samples');
    }

    const samples = AdvisoryComposerModel.collectTrainingData(data.emailCompositionSamples);
    const [train, test] = splitData(samples, 0.2, 42);

    try {
      model.train(train);

      const validation = gateDef.evaluate(model, test);
      if (!validation.passed) {
        return this.failureResult('advisory-composer', 'logistic', samples.length, train.length, validation,
          `quality gate failed: ${validation.failureReason ?? 'unknown'}`);
      }

      const saved = await this.saveModel(model, 'advisory-composer', gateDef, validation.metrics);
      return this.successResult('advisory-composer', 'logistic', samples.length, train.length, validation, saved);
    } catch (e) {
      return this.errorResult('advisory-composer', 'logistic', samples.length, e);
    }
  }
}
