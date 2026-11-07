/**
 * ML subsystem factory — creates, registers, and wires all autonomous ML
 * models into the VulnStream-Enterprise pipeline.
 *
 * Usage:
 *   import { createMlRuntime } from './ml/factory.ts';
 *   const runtime = createMlRuntime(config.mlDirectory);
 *
 * The factory instantiates every model, loads persisted artifacts from disk
 * (with automatic rollback on failure), and exposes typed access to each
 * model for integration into existing pipeline code.
 *
 * Integration points:
 *   - CPE Validity Gate     → cpeMatcher.ts:55 (parseCPE23 pre-filter)
 *   - Metric Anomaly Detector → supervisor.ts + metrics.ts (telemetry)
 *   - Auto-Dispatch Threshold → pipelineEngine.ts:497 (90% auto-dispatch gate)
 *   - Review Queue Ranker  → pipelineEngine.ts:397 (REVIEW_REQUIRED sorting)
 *   - Confidence Calibrator → intelligenceMatcher.ts:49 (credibility scoring)
 *   - Delivery Optimizer   → delivery.ts:183 (emailRetryDelayMs/backoff)
 *   - Remediation Helper   → templateCompiler.ts:249 (remediation template fields)
 */
import { ModelRegistry } from './runtime.ts';
import { CpeValidityGateModel } from './models/cpeValidityGate.ts';
import { MetricAnomalyDetectorModel } from './models/metricAnomalyDetector.ts';
import { AutoDispatchThresholdModel } from './models/autoDispatchThreshold.ts';
import { ReviewRankerModel } from './models/reviewRanker.ts';
import { ConfidenceCalibrator } from './models/confidenceCalibrator.ts';
import { DeliveryOptimizerModel } from './models/deliveryOptimizer.ts';
import { AdvisoryRemediationHelper } from './models/advisoryRemediationHelper.ts';
import { ExploitRiskModel } from './models/exploitRiskModel.ts';
import { MatchConfidenceModel } from './models/matchConfidenceModel.ts';
import { FindingImportanceRanker } from './models/findingImportanceRanker.ts';
import { NewsCredibilityWeightModel } from './models/newsCredibilityWeightModel.ts';
import { DeliveryErrorClassifier } from './models/deliveryErrorClassifier.ts';
import { ZeroDayRateLimitOptimizer } from './models/zeroDayRateLimitOptimizer.ts';
import { DigestFindingSelector } from './models/digestFindingSelector.ts';
import { SeverityTierModel } from './models/severityTierModel.ts';
import { FeedRecoveryBackoffOptimizer } from './models/feedRecoveryBackoffOptimizer.ts';
import { AliasConfidenceModel } from './models/aliasConfidenceModel.ts';
import { AdvisoryComposerModel } from './models/advisoryComposer.ts';
import type { ModelStorageOptions } from './types.ts';

export interface MlRuntime {
  registry: ModelRegistry;
  cpeValidityGate: CpeValidityGateModel;
  metricAnomalyDetector: MetricAnomalyDetectorModel;
  autoDispatchThreshold: AutoDispatchThresholdModel;
  reviewRanker: ReviewRankerModel;
  confidenceCalibrator: ConfidenceCalibrator;
  deliveryOptimizer: DeliveryOptimizerModel;
  remediationHelper: AdvisoryRemediationHelper;
  exploitRisk: ExploitRiskModel;
  matchConfidence: MatchConfidenceModel;
  findingImportance: FindingImportanceRanker;
  credibilityWeights: NewsCredibilityWeightModel;
  deliveryErrorClassifier: DeliveryErrorClassifier;
  zeroDayRateLimit: ZeroDayRateLimitOptimizer;
  digestSelector: DigestFindingSelector;
  severityTier: SeverityTierModel;
  feedRecoveryBackoff: FeedRecoveryBackoffOptimizer;
  aliasConfidence: AliasConfidenceModel;
  advisoryComposer: AdvisoryComposerModel;
}

export async function createMlRuntime(options: ModelStorageOptions): Promise<MlRuntime> {
  const registry = new ModelRegistry(options);

  const cpeValidityGate = new CpeValidityGateModel();
  const metricAnomalyDetector = new MetricAnomalyDetectorModel();
  const autoDispatchThreshold = new AutoDispatchThresholdModel();
  const reviewRanker = new ReviewRankerModel();
  const confidenceCalibrator = new ConfidenceCalibrator();
  const deliveryOptimizer = new DeliveryOptimizerModel();
  const remediationHelper = new AdvisoryRemediationHelper();

  const exploitRisk = new ExploitRiskModel();
  const matchConfidence = new MatchConfidenceModel();
  const findingImportance = new FindingImportanceRanker();
  const credibilityWeights = new NewsCredibilityWeightModel();
  const deliveryErrorClassifier = new DeliveryErrorClassifier();
  const zeroDayRateLimit = new ZeroDayRateLimitOptimizer();
  const digestSelector = new DigestFindingSelector();
  const severityTier = new SeverityTierModel();
  const feedRecoveryBackoff = new FeedRecoveryBackoffOptimizer();
  const aliasConfidence = new AliasConfidenceModel();
  const advisoryComposer = new AdvisoryComposerModel();

   // autoDispatchThreshold uses a 1-D optimizer (not a TrainableModel), so it is
   // loaded via saveArtifact/loadArtifact rather than the standard TrainableModel path.
   await registry.loadArtifact(autoDispatchThreshold, 'auto-dispatch-threshold');

  await registry.load(cpeValidityGate, 'cpe-validity-gate');
  await registry.load(metricAnomalyDetector, 'metric-anomaly-detector');
  await registry.load(reviewRanker, 'review-ranker');
  await registry.load(confidenceCalibrator, 'confidence-calibrator');
  await registry.load(deliveryOptimizer, 'delivery-optimizer');
  await registry.load(remediationHelper, 'advisory-remediation-helper');
  await registry.load(exploitRisk, 'exploit-risk-model');
  await registry.load(matchConfidence, 'match-confidence-model');
  await registry.load(findingImportance, 'finding-importance-ranker');
  await registry.loadArtifact(credibilityWeights, 'news-credibility-weight-model');
  await registry.load(deliveryErrorClassifier, 'delivery-error-classifier');
  await registry.loadArtifact(zeroDayRateLimit, 'zero-day-rate-limit-optimizer');
  await registry.load(digestSelector, 'digest-finding-selector');
  await registry.load(severityTier, 'severity-tier-model');
  await registry.loadArtifact(feedRecoveryBackoff, 'feed-recovery-backoff-optimizer');
  await registry.load(aliasConfidence, 'alias-confidence-model');
  await registry.load(advisoryComposer, 'advisory-composer');
  
  /**
   * ML quality gate validation for feed recovery optimization.
   * 
   * Audit QG-1: ML quality gates ensure recovery effectiveness before using ML models.
   * This validates that the feed recovery model has sufficient recovery rate (0.6+) before
   * it can be used in production. If the model quality gate fails, it falls back to
   * hardcoded parameters and logs the quality issue for operator attention.
   */
  const qualityGate = feedRecoveryBackoff.isTrained() ? feedRecoveryBackoff : null;
  let mlRecoveryDisabled = false;
  if (qualityGate && qualityGate.getRecoveryRate() < 0.6) {
    const recoveryRate = qualityGate.getRecoveryRate();
    console.error(JSON.stringify({
      level: 'ERROR',
      event: 'ml.quality_gate_failed',
      model: 'feed-recovery-backoff-optimizer',
      recoveryRate: recoveryRate,
      threshold: 0.6,
      version: qualityGate.serialize().metadata.version,
      message: 'ML feed recovery model below quality threshold; disabling ML-backed recovery'
    }));
    // Disable ML-backed recovery: revert to hardcoded parameters when quality gate fails.
    // This prevents a suboptimal model from degrading feed recovery behavior.
    feedRecoveryBackoff.getPolicy = () => ({
      initialDelayMinutes: 5,
      backoffMultiplier: 2,
      maxDelayMinutes: 1440,
      maxSteps: 6,
      maxAttempts: 5,
    });
    mlRecoveryDisabled = true;
  }
  if (mlRecoveryDisabled) {
    console.error(JSON.stringify({
      level: 'ERROR',
      event: 'ml.recovery_disabled',
      model: 'feed-recovery-backoff-optimizer',
      message: 'ML feed recovery disabled due to quality gate failure; using hardcoded default parameters'
    }));
  }
  return {
    registry,
    cpeValidityGate,
    metricAnomalyDetector,
    autoDispatchThreshold,
    reviewRanker,
    confidenceCalibrator,
    deliveryOptimizer,
    remediationHelper,
    exploitRisk,
    matchConfidence,
    findingImportance,
    credibilityWeights,
    deliveryErrorClassifier,
    zeroDayRateLimit,
    digestSelector,
    severityTier,
    feedRecoveryBackoff,
    aliasConfidence,
    advisoryComposer,
  };
}
