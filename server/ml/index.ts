export { BaseModel } from './baseModel.ts';
export {
  CpeValidityGateModel,
  extractCpeValidityFeatures,
  type CpeValidityFeatures,
} from './models/cpeValidityGate.ts';
export {
  MetricAnomalyDetectorModel,
  extractMetricFeatures,
  type MetricFeatures,
  METRIC_FEATURE_NAMES,
} from './models/metricAnomalyDetector.ts';
export { AutoDispatchThresholdModel, type ThresholdSample } from './models/autoDispatchThreshold.ts';
export {
  ReviewRankerModel,
  extractFindingFeatures,
  type FindingFeatures,
  REVIEW_RANKER_FEATURES,
} from './models/reviewRanker.ts';
export { ConfidenceCalibrator } from './models/confidenceCalibrator.ts';
export { DeliveryOptimizerModel, type DeliveryOutcome } from './models/deliveryOptimizer.ts';
export {
  AdvisoryRemediationHelper,
  extractRemediationFeatures,
  type RemediationFeatures,
  type RemediationPrediction,
  REMEDIATION_FIELD_NAMES,
} from './models/advisoryRemediationHelper.ts';
export {
  ExploitRiskModel,
  extractExploitRiskFeatures,
  type ExploitRiskFeatures,
  type ExploitRiskLevel,
  EXPLOIT_RISK_LEVELS,
  EXPLOIT_RISK_FEATURE_NAMES,
} from './models/exploitRiskModel.ts';
export {
  MatchConfidenceModel,
  extractMatchConfidenceFeatures,
  type MatchConfidenceFeatures,
  MATCH_CONFIDENCE_FEATURE_NAMES,
} from './models/matchConfidenceModel.ts';
export {
  FindingImportanceRanker,
  extractFindingImportanceFeatures,
  type FindingImportanceFeatures,
  FINDING_IMPORTANCE_FEATURES,
} from './models/findingImportanceRanker.ts';
export {
  NewsCredibilityWeightModel,
  chronologicalCredibilitySplit,
  type CredibilitySample,
  CREDIBILITY_FEATURE_NAMES,
} from './models/newsCredibilityWeightModel.ts';
export {
  DeliveryErrorClassifier,
  extractDeliveryErrorFeatures,
  type DeliveryErrorFeatures,
  DELIVERY_ERROR_FEATURE_NAMES,
} from './models/deliveryErrorClassifier.ts';
export {
  ZeroDayRateLimitOptimizer,
  type ZeroDayRateLimitSample,
  ZERO_DAY_RATE_LIMIT_FEATURE_NAMES,
} from './models/zeroDayRateLimitOptimizer.ts';
export {
  DigestFindingSelector,
  extractDigestSelectionFeatures,
  type DigestSelectionFeatures,
  DIGEST_SELECTION_FEATURE_NAMES,
} from './models/digestFindingSelector.ts';
export {
  SeverityTierModel,
  extractSeverityTierFeatures,
  type SeverityTierFeatures,
  type SeverityTier,
  SEVERITY_TIERS,
  SEVERITY_TIER_FEATURE_NAMES,
} from './models/severityTierModel.ts';
export {
  FeedRecoveryBackoffOptimizer,
  type FeedRecoverySample,
  FEED_RECOVERY_FEATURE_NAMES,
} from './models/feedRecoveryBackoffOptimizer.ts';
export {
  AliasConfidenceModel,
  extractAliasConfidenceFeatures,
  type AliasConfidenceFeatures,
  ALIAS_CONFIDENCE_FEATURE_NAMES,
} from './models/aliasConfidenceModel.ts';
export {
  AdvisoryComposerModel,
  type EmailCompositionFeatures,
  type PerFindingFeatures,
  type EmailCompositionPrediction,
  type SummaryStyle,
  type PriorityEmphasis,
  type RemediationEmphasis,
  type SubjectTemplate,
  SUMMARY_STYLES,
  PRIORITY_EMPHASES,
  REMEDIATION_EMPHASES,
  SUBJECT_TEMPLATES,
  ADVISORY_COMPOSER_FEATURE_NAMES,
} from './models/advisoryComposer.ts';
export { ModelRegistry } from './runtime.ts';
export { createMlRuntime, type MlRuntime } from './factory.ts';

export {
  initMlRuntime,
  getMlRuntime,
  cpePreFilter,
  calibrateCredibilityScore,
  shouldAutoDispatch,
  rankReviewFindings,
  isTelemetryAnomaly,
  computeRetryDelay,
  predictRemediation,
  predictExploitRisk,
  predictMatchConfidence,
  rankFindingsByImportance,
  predictCredibilityWeights,
  classifyDeliveryError,
  getZeroDayCap,
  shouldSelectForDigest,
  predictSeverityTier,
  computeFeedRecoveryDelay,
  predictAliasConfidence,
  mlComposeAdvisoryEmail,
  mlPredictAdvisoryComposition,
  mlOrderFindingsByImportance,
} from './integration.ts';
export {
  DEFAULT_AUTO_DISPATCH_THRESHOLD,
  DEFAULT_EMAIL_RETRY_INITIAL_DELAY_MINUTES,
  DEFAULT_EMAIL_RETRY_MULTIPLIER,
  DEFAULT_EMAIL_RETRY_MAX_DELAY_MINUTES,
  DEFAULT_EMAIL_RETRY_MAX_ATTEMPTS,
  DEFAULT_MAX_ZERO_DAYS_PER_RUN,
  DEFAULT_FEED_RECOVERY_INITIAL_DELAY_MINUTES,
  DEFAULT_FEED_RECOVERY_MAX_DELAY_MINUTES,
  DEFAULT_FEED_RECOVERY_BACKOFF_MULTIPLIER,
  DEFAULT_FEED_RECOVERY_MAX_STEPS,
  DEFAULT_EPSS_HIGH_THRESHOLD,
  DEFAULT_FEED_CREDIBILITY_WEIGHT,
  DEFAULT_KEYWORD_CREDIBILITY_WEIGHT,
  DEFAULT_DIGEST_FINDINGS_PER_SEVERITY,
  DEFAULT_ALIAS_CONFIRMED_THRESHOLD,
} from './defaults.ts';
export { TrainingOrchestrator, type TrainingDataSources, type TrainingResult, type TrainingSummary } from './train/orchestrator.ts';
export { QUALITY_GATES, type QualityGate, type QualityGateResult } from './train/qualityGates.ts';
export {
  computePsi,
  detectFeatureDrift,
  detectConceptDrift,
  shouldRetrain,
  type DriftReport,
  type FeatureDriftReport,
  type ConceptDriftReport,
  PSI_THRESHOLDS,
  CONCEPT_DRIFT_THRESHOLDS,
} from './train/driftDetection.ts';
export { evaluateClassifier, computeEce, splitData, toLabel } from './train/evaluation.ts';
export { createRng, DEFAULT_TRAINING_SEED } from './algorithms/rng.ts';
export { LogisticRegression } from './algorithms/logisticRegression.ts';
export { IsolationForest } from './algorithms/isolationForest.ts';
export { GBDTRanker } from './algorithms/gbdtRanker.ts';
export { StandardScaler } from './algorithms/standardScaler.ts';
export { MetricsRegistry, mlMetrics } from './metrics.ts';
export type {
  ModelMetadata,
  ModelArtifact,
  ModelRegistryEntry,
  PredictionResult,
  TrainableModel,
  TrainingSample,
  Scaler,
  ModelStorageOptions,
  ModelSelfValidation,
  ModelType,
  FeedbackSignal,
} from './types.ts';
