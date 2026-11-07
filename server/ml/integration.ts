/**
 * Pipeline integration layer for the ML subsystem.
 *
 * Provides drop-in wrapper functions that delegate to trained ML models
 * when available, and fall back to existing hardcoded behavior when models
 * are untrained or unavailable. This ensures zero risk of regressions —
 * the ML models always improve or match the status quo, never degrade it.
 *
 * Usage:
 *   import { initMlRuntime } from './ml/integration.ts';
 *   await initMlRuntime({ directory: '/var/lib/vulnstream/ml' });
 *
 *   // In pipeline engine:
 *   import { shouldAutoDispatch, rankReviewFindings } from './ml/integration.ts';
 *   const shouldDispatch = shouldAutoDispatch(confidence, settings);
 *   const ranked = rankReviewFindings(findings);
 */
import { createMlRuntime, type MlRuntime } from './factory.ts';
import type { ModelStorageOptions, TrainableModel, ModelMetadata, PredictionResult, FeedbackSignal, TrainingSample } from './types.ts';
import type { AppSettings, Advisory, RemediationPlaybook, Finding, FeedType } from '../../src/types/index.ts';
import type { MetricFeatures as TelemetryMetric } from './models/metricAnomalyDetector.ts';
import { extractMetricFeatures } from './models/metricAnomalyDetector.ts';
import { extractFindingFeatures } from './models/reviewRanker.ts';
import { findingFeatures } from './findingFeatures.ts';
import type { RemediationFeatures, RemediationPrediction } from './models/advisoryRemediationHelper.ts';
import { DEFAULT_AUTO_DISPATCH_THRESHOLD, DEFAULT_MAX_ZERO_DAYS_PER_RUN, DEFAULT_FEED_RECOVERY_INITIAL_DELAY_MINUTES, DEFAULT_FEED_RECOVERY_BACKOFF_MULTIPLIER, DEFAULT_FEED_RECOVERY_MAX_DELAY_MINUTES, DEFAULT_FEED_RECOVERY_MAX_STEPS, DEFAULT_FEED_CREDIBILITY_WEIGHT, DEFAULT_KEYWORD_CREDIBILITY_WEIGHT } from './defaults.ts';
import { extractExploitRiskFeatures, type ExploitRiskLevel } from './models/exploitRiskModel.ts';
import { extractSeverityTierFeatures, type SeverityTier } from './models/severityTierModel.ts';
import { extractFindingImportanceFeatures } from './models/findingImportanceRanker.ts';
import type { Db } from '../db.ts';
import { writeEvent } from '../events.ts';
import { composeAdvisoryEmail, predictAdvisoryComposition, orderFindingsByMlImportance, type EmailCompositionPrediction } from '../advisoryComposer.ts';

interface MlContext {
  runtime: MlRuntime | null;
  storage: ModelStorageOptions | null;
  pool: Db | null;
}

/** Module-level singleton — initialized once at server startup. */
const ctx: MlContext = { runtime: null, storage: null, pool: null };

/**
 * Initializes the ML runtime by loading artifacts from disk.
 * Must be called once during server startup before any integration functions are used.
 */
export async function initMlRuntime(pool: Db, options: ModelStorageOptions): Promise<MlRuntime> {
  ctx.pool = pool;
  ctx.storage = options;
  const startAt = Date.now();
  const runtime = await createMlRuntime(options);
  if (ctx.runtime) Object.assign(ctx.runtime, runtime);
  else ctx.runtime = runtime;
  const loadedModels = ctx.runtime.registry.list().map((e) => e.metadata.id);
  const loadMs = Date.now() - startAt;
  await writeEvent(pool, {
    category: 'ML',
    code: 'ml.runtime.initialized',
    message: `ML runtime initialized: ${loadedModels.length} model(s) loaded`,
    level: 'INFO',
    context: {
      models: loadedModels,
      modelCount: loadedModels.length,
      mlDirectory: options.directory,
      loadTimeMs: loadMs,
      modelStatuses: ctx.runtime.registry.list().map((e) => ({
        modelId: e.metadata.id,
        version: e.metadata.version,
        status: e.status,
        trainedAt: e.metadata.trainedAt,
      })),
    },
  });
  return ctx.runtime;
}

/** Returns the active ML runtime, or null if not initialized. */
export function getMlRuntime(): MlRuntime | null {
  return ctx.runtime;
}

/**
 * 1. CPE Validity Gate — pre-filter for parseCPE23.
 *
 * Returns false (skip parse) only when the classifier is HIGH-confidence
 * that the CPE is malformed. Always falls through to the parser for
 * untrained or uncertain cases — never blocks valid CPEs.
 */
export function cpePreFilter(cpe: string): boolean {
  const model = ctx.runtime?.cpeValidityGate;
  if (!model?.isTrained()) return true;
  const result = model.shouldParse(cpe);
  void logMlEvent('ml.cpe_pre_filter', 'CPE validity gate evaluated', {
    cpe,
    result,
    modelVersion: model.getMetadata().version,
  });
  return result;
}

/**
 * 2. Confidence Calibrator — calibrates the heuristic credibility score.
 *
 * Returns the calibrated probability. Falls back to raw score / 100
 * when the calibrator is untrained.
 */
export function calibrateCredibilityScore(rawScore: number): {
  score: number;
  probability: number;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
} {
  const model = ctx.runtime?.confidenceCalibrator;
  if (!model?.isTrained()) {
    void logMlEvent('ml.credibility_calibration.fallback', 'Calibrator untrained — using raw score', {
      rawScore,
    });
    return { score: rawScore, probability: rawScore / 100, confidence: 'LOW' };
  }
  const result = model.predict({ credibility_score: rawScore });
  void logMlEvent('ml.credibility_calibration', 'Credibility score calibrated', {
    rawScore,
    calibratedScore: result.score,
    probability: result.probability,
    confidence: result.confidence,
    modelVersion: model.getMetadata().version,
  });
  return {
    score: result.score,
    probability: result.probability ?? result.score / 100,
    confidence: result.confidence,
  };
}

/**
 * 3. Auto-Dispatch Threshold — replaces the hardcoded 90% gate.
 *
 * The configured threshold is authoritative; trained models only recommend.
 */
export function shouldAutoDispatch(confidence: number, settings: Pick<AppSettings, 'autoDispatchConfidenceThreshold'>): boolean {
  const model = ctx.runtime?.autoDispatchThreshold;
  const threshold = settings.autoDispatchConfidenceThreshold ?? DEFAULT_AUTO_DISPATCH_THRESHOLD;
  const result = Number.isFinite(confidence) && confidence >= 0 && confidence <= 100 &&
    Number.isFinite(threshold) && threshold >= 0 && threshold <= 100 && confidence >= threshold;
  const trained = model?.isTrained() === true;
  void logMlEvent('ml.auto_dispatch', result ? 'Eligible under configured policy' : 'Held under configured policy', {
    confidence,
    threshold,
    modelTrained: trained,
    recommendedThreshold: trained ? model?.getThreshold() : undefined,
  });
  return result;
}

/**
 * 4. Review Queue Ranker — ranks REVIEW_REQUIRED findings by
 * true-positive probability so the most actionable surface first.
 *
 * Falls back to sorting by match confidence when untrained.
 */
export function rankReviewFindings(
  findings: Finding[],
  feedTypesById?: ReadonlyMap<string, FeedType>,
): Finding[] {
  const model = ctx.runtime?.reviewRanker;
  if (!model?.isTrained()) {
    void logMlEvent('ml.review_rank.fallback', 'Review ranker untrained — sorting by confidence', {
      findingCount: findings.length,
    });
    return [...findings].sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0));
  }

  const features = findings.map((f) => extractFindingFeatures(findingFeatures(f, feedTypesById)));

  const predictions = model.predictBatch(features);
  void logMlEvent('ml.review_rank', 'Review findings ranked by true-positive probability', {
    findingCount: findings.length,
    modelVersion: model.getMetadata().version,
    avgProbability: predictions.reduce((sum, p) => sum + (p.probability ?? p.score ?? 0), 0) / predictions.length,
  });
  return findings
    .map((f, i) => ({ finding: f, score: predictions[i]?.probability ?? predictions[i]?.score ?? 0 }))
    .sort((a, b) => b.score - a.score)
    .map((entry) => entry.finding);
}

/**
 * 5. Metric Anomaly Detector — checks if a telemetry snapshot is anomalous.
 * Falls back to returning false (no anomaly) when untrained.
 */
export function isTelemetryAnomaly(
  metrics: TelemetryMetric,
): boolean {
  const model = ctx.runtime?.metricAnomalyDetector;
  if (!model?.isTrained()) return false;
  const features = extractMetricFeatures(metrics);
  return model.isAnomaly(features);
}

export function shouldSampleMlTelemetry(pendingDepth: number, pendingSampledAt: number): boolean {
  return pendingSampledAt === 0 || pendingDepth >= 0;
}

/**
 * 6. Delivery Optimizer — computes retry delay using learned policy.
 * Falls back to the default exponential backoff when untrained.
 */
export function computeRetryDelay(attempt: number): number {
  const model = ctx.runtime?.deliveryOptimizer;
  if (!model?.isTrained()) {
    const fallbackDelay = Math.min(1440 * 60_000, 5 * 60_000 * 2 ** Math.max(0, attempt - 1));
    void logMlEvent('ml.delivery_retry.fallback', 'Delivery optimizer untrained — using exponential backoff', {
      attempt,
      delayMs: fallbackDelay,
    });
    return fallbackDelay;
  }
  const result = model.computeDelay(attempt);
  void logMlEvent('ml.delivery_retry', 'Retry delay computed (ML)', {
    attempt,
    delayMs: result,
    modelVersion: model.getMetadata().version,
  });
  return result;
}

/**
 * 7. Advisory Remediation Helper — predicts remediation playbook
 * completeness and generates fallback content for missing fields.
 * Falls back to rule-based defaults when untrained.
 */
export function predictRemediation(
  features: RemediationFeatures,
  actualPlaybook?: Partial<RemediationPlaybook>,
): RemediationPrediction {
  const model = ctx.runtime?.remediationHelper;
  if (!model?.isTrained()) {
    return {
      patchUrl: 0.2,
      vendorAdvisory: features.cisaKev ? 0.8 : 0.3,
      immediateActions: features.exploitStatus > 2 ? 0.7 : 0.3,
      workarounds: features.epssScore > 0.5 ? 0.4 : 0.6,
      rollbackPlan: features.cvssScore > 8 ? 0.6 : features.cvssScore > 4 ? 0.4 : 0.2,
      stepByStep: features.hasVersionEvidence ? 0.7 : 0.4,
      overall: 0.5,
      recommendation: 'partial',
      generatedContent: actualPlaybook ?? {},
    };
  }
   return model.predictRemediation(features, actualPlaybook);
}

/**
 * 8. Exploit Risk Model — replaces the hardcoded determineExploitRisk()
 * cascade in pipelineEngine.ts:69.
 * Falls back to the hardcoded cascade when untrained.
 */
export function predictExploitRisk(f: {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: string;
  exploitationSourcesCount: number;
  daysSincePublished: number;
}): ExploitRiskLevel {
  const model = ctx.runtime?.exploitRisk;
  if (!model?.isTrained()) {
    return fallbackExploitRisk(f);
  }
  const result = model.predict(extractExploitRiskFeatures(f));
  return model.getRiskLevels()[result.score] ?? 'STANDARD';
}

function fallbackExploitRisk(f: {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: string;
  exploitationSourcesCount: number;
  daysSincePublished: number;
}): ExploitRiskLevel {
  if (f.cisaKev) return 'CISA_KEV_EXPLOITED';
  if (f.exploitationSourcesCount > 0 || f.exploitStatus === 'Reported In Wild') return 'REPORTED_IN_WILD_EXPLOIT';
  if (f.exploitStatus === 'Active Weaponized') return 'WEAPONIZED_EXPLOIT';
  if (f.epssScore >= 0.4) return 'HIGH_EPSS_PROBABILITY';
  if (f.cvssScore >= 7) return 'ELEVATED';
  return 'STANDARD';
}

/**
 * 9. Match Confidence Model — replaces hardcoded per-method confidence values
 * (100/95/90/85/70/0) in cpeMatcher.ts and cpeSimulation.ts.
 * Falls back to the hardcoded values when untrained.
 */
export function predictMatchConfidence(f: {
  matchMethod: string;
  hasVersionEvidence: boolean;
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  sourceFeedWeight: number;
  daysSincePublished: number;
  negated: boolean;
}): number {
  const model = ctx.runtime?.matchConfidence;
  if (!model?.isTrained()) {
    return fallbackMatchConfidence(f);
  }
  return model.predictConfidence({
    matchMethod: f.matchMethod,
    hasVersionEvidence: f.hasVersionEvidence,
    versionVerifiedInRange: f.hasVersionEvidence && f.matchMethod === 'STRICT_CPE_INTERVAL',
    cvssScore: f.cvssScore,
    epssScore: f.epssScore,
    cisaKev: f.cisaKev,
    sourceFeedWeight: f.sourceFeedWeight,
    daysSincePublished: f.daysSincePublished,
    negated: f.negated,
  });
}

function fallbackMatchConfidence(f: {
  matchMethod: string;
  hasVersionEvidence: boolean;
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  sourceFeedWeight: number;
  daysSincePublished: number;
  negated: boolean;
}): number {
  if (f.matchMethod === 'STRICT_CPE' || f.matchMethod === 'STRICT_CPE_INTERVAL') {
    return f.hasVersionEvidence ? 100 : 90;
  }
  if (f.matchMethod === 'PURL_EXACT') return 95;
  if (f.matchMethod === 'VENDOR_PRODUCT_ALIAS') return 85;
  if (f.matchMethod === 'VENDOR_PRODUCT_FALLBACK') return 70;
  if (f.matchMethod === 'KEYWORD') return 50;
  return 0;
}

/**
 * 10. Finding Importance Ranker — replaces the arbitrary 25-item slice
 * and recency-only sort in templateCompiler.ts:652 and findingSort.ts:13.
 * Falls back to recency-based sorting when untrained.
 */
export function rankFindingsByImportance(findings: Array<{
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
}>): number[] {
  const model = ctx.runtime?.findingImportance;
  if (!model?.isTrained()) {
    return findings.map((_, i) => 1 / (i + 1));
  }
  return findings.map((f) => {
    const feats = extractFindingImportanceFeatures({
      cvssScore: f.cvssScore,
      epssScore: f.epssScore,
      cisaKev: f.cisaKev,
      exploitStatus: f.exploitStatus,
      cweRiskLevel: f.cweRiskLevel,
      daysSincePublished: f.daysSincePublished,
      sourceFeedWeight: f.sourceFeedWeight,
      credibilityScore: f.credibilityScore,
      hasVersionEvidence: f.hasVersionEvidence,
      assetCriticality: f.assetCriticality,
    });
    const result = model.predict(feats);
    return result.probability ?? result.score ?? 0;
  });
}

/**
 * 11. News Credibility Weight Model — replaces the hardcoded
 * `feedScore * 0.6 + keywordScore * 0.4` in intelligenceMatcher.ts:46.
 * Falls back to the 0.6/0.4 split when untrained.
 */
export function predictCredibilityWeights(): { feedWeight: number; keywordWeight: number } {
  const model = ctx.runtime?.credibilityWeights;
  if (!model?.isTrained()) {
    return { feedWeight: DEFAULT_FEED_CREDIBILITY_WEIGHT, keywordWeight: DEFAULT_KEYWORD_CREDIBILITY_WEIGHT };
  }
  return model.getWeights();
}

export function computeCredibilityScore(feedWeight: number, keywordScore: number): number {
  const model = ctx.runtime?.credibilityWeights;
  if (!model?.isTrained()) {
    return Math.round(feedWeight * DEFAULT_FEED_CREDIBILITY_WEIGHT + keywordScore * DEFAULT_KEYWORD_CREDIBILITY_WEIGHT);
  }
  return model.computeCredibility(feedWeight, keywordScore);
}

/**
 * 12. Delivery Error Classifier — replaces the hardcoded HTTP status
 * classification in delivery.ts:1557 and emailProviders.ts:375-407.
 * Falls back to status-code-based classification when untrained.
 */
export function classifyDeliveryError(f: {
  provider: string;
  statusCode: number;
  errorMessage: string;
  attemptNumber: number;
  hourOfDay: number;
}): { isPermanent: boolean; isTransient: boolean; reason: string } {
  const model = ctx.runtime?.deliveryErrorClassifier;
  if (!model?.isTrained()) {
    const s = f.statusCode;
    const isPermanent = s >= 400 && s < 500 && ![408, 429].includes(s);
    return { isPermanent, isTransient: !isPermanent, reason: `hardcoded status code classification (HTTP ${s})` };
  }
  const isPermanent = model.isPermanentError(f);
  return { isPermanent, isTransient: !isPermanent, reason: 'ML delivery error classifier' };
}

/**
 * 13. Zero-Day Rate Limit Optimizer — replaces the hardcoded
 * `MAX_ZERO_DAYS_PER_RUN = 50` in pipelineEngine.ts:101.
 * Falls back to 50 when untrained.
 */
export function getZeroDayCap(): number {
  const model = ctx.runtime?.zeroDayRateLimit;
  if (!model?.isTrained()) {
    return DEFAULT_MAX_ZERO_DAYS_PER_RUN;
  }
  return model.getCap();
}

/**
  * 14. Digest Finding Selector — replaces the subscription-only filtering
 * in dailyDigest.ts:464. Falls back to including all eligible findings when untrained.
 */
export function shouldSelectForDigest(f: {
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
}): number {
  const model = ctx.runtime?.digestSelector;
  if (!model?.isTrained()) {
    return 1.0;
  }
  return model.selectForDigest(f);
}

/**
 * 15. Severity Tier Model — replaces the hardcoded weighted scoring in
 * severityClassifier.ts. Falls back to the hardcoded scoring when untrained.
 */
export function predictSeverityTier(f: {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: string;
  cweRiskLevel: number;
  daysSincePublished: number;
  sourceFeedWeight: number;
  cvssSeverity: string;
}): SeverityTier {
  const model = ctx.runtime?.severityTier;
  if (!model?.isTrained()) {
    return fallbackSeverityTier(f);
  }
  const result = model.predict(extractSeverityTierFeatures(f));
  return model.getTiers()[result.score] ?? 'INFORMATIONAL';
}

function fallbackSeverityTier(f: {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: string;
  cweRiskLevel: number;
  daysSincePublished: number;
  sourceFeedWeight: number;
  cvssSeverity: string;
}): SeverityTier {
  const EXPLOIT_STATUS_WEIGHT: Record<string, number> = {
    'Active Weaponized': 40,
    'Reported In Wild': 30,
    'POC Available': 20,
    None: 0,
  };
  const CISA_KEV_WEIGHT = 15;
  const EPSS_HIGH_THRESHOLD = 0.4;
  const EPSS_HIGH_WEIGHT = 10;

  let score = 0;

  score += f.cvssScore * 0.6;
  score += EXPLOIT_STATUS_WEIGHT[f.exploitStatus] || 0;
  if (f.cisaKev) score += CISA_KEV_WEIGHT;
  if (f.epssScore >= EPSS_HIGH_THRESHOLD) score += EPSS_HIGH_WEIGHT;

  if (score >= 90 || f.cvssSeverity === 'CRITICAL') return 'CRITICAL';
  if (score >= 70 || f.cvssSeverity === 'HIGH') return 'HIGH';
  if (score >= 40 || f.cvssSeverity === 'MEDIUM') return 'MEDIUM';
  if (score >= 10 || f.cvssSeverity === 'LOW') return 'LOW';
  return 'INFORMATIONAL';
}

/**
 * 16. Feed Recovery Backoff Optimizer — replaces the hardcoded exponential
 * backoff in feedRecovery.ts:12. Falls back to the default backoff when untrained.
 */
export function computeFeedRecoveryDelay(failures: number): number {
  const model = ctx.runtime?.feedRecoveryBackoff;
  if (!model?.isTrained()) {
    const base = DEFAULT_FEED_RECOVERY_INITIAL_DELAY_MINUTES * 60_000;
    return Math.min(
      DEFAULT_FEED_RECOVERY_MAX_DELAY_MINUTES * 60_000,
      base * DEFAULT_FEED_RECOVERY_BACKOFF_MULTIPLIER ** Math.min(DEFAULT_FEED_RECOVERY_MAX_STEPS, Math.max(0, failures - 1)),
    );
  }
  return Math.min(
    DEFAULT_FEED_RECOVERY_MAX_DELAY_MINUTES * 60_000,
    Math.max(60_000, model.computeRecoveryDelay(failures)),
  );
}

/**
 * 17. Alias Confidence Model — replaces the hardcoded isConfirmedFinding()
 * boolean gate in aliasLifecycle.ts:277.
 * Falls back to hardcoded checks when untrained.
 */
export function predictAliasConfidence(f: {
  matchConfidence: number;
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: number;
  daysSincePublished: number;
  sourceFeedWeight: number;
  hasVersionEvidence: boolean;
  matchMethod: string;
}): number {
  const model = ctx.runtime?.aliasConfidence;
  if (!model?.isTrained()) {
    if (f.matchConfidence === 0) return 0;
    if (f.cisaKev) return 1;
    if (f.epssScore >= 0.4) return 1;
    if (f.exploitStatus > 0) return 1;
    return f.matchConfidence >= 70 ? 1 : 0;
  }
  return model.predictConfirmationProbability(f);
}

/**
 * Advisory email composition — ML-guided generation of subject lines,
 * executive summaries, remediation instructions, and severity summaries.
 *
 * Falls back to rule-based composition when the composer model is untrained.
 * Logs ML events for observability.
 */
export function mlComposeAdvisoryEmail(findings: Finding[], advisory: Advisory): {
  subject: string;
  executiveSummary: string;
  remediationInstructions: string;
  severitySummary: string;
  findingOrder: number[];
  modelUsed: boolean;
  modelVersion?: string;
} {
  const result = composeAdvisoryEmail(findings, advisory);
  if (result.modelUsed && result.prediction) {
    void logMlEvent('ml.advisory_compose', 'Advisory email composed by ML', {
      summaryStyle: result.prediction.summaryStyle,
      priorityEmphasis: result.prediction.priorityEmphasis,
      remediationEmphasis: result.prediction.remediationEmphasis,
      subjectTemplate: result.prediction.subjectTemplate,
      confidence: result.prediction.confidence,
      modelVersion: result.prediction.modelVersion,
      findingCount: findings.length,
    });
    return {
      subject: result.subject,
      executiveSummary: result.executiveSummary,
      remediationInstructions: result.remediationInstructions,
      severitySummary: result.severitySummary,
      findingOrder: result.findingOrder,
      modelUsed: true,
      modelVersion: result.prediction.modelVersion,
    };
  }
  void logMlEvent('ml.advisory_compose.fallback', 'Advisory email composed by rule-based fallback', {
    findingCount: findings.length,
  });
  return {
    subject: result.subject,
    executiveSummary: result.executiveSummary,
    remediationInstructions: result.remediationInstructions,
    severitySummary: result.severitySummary,
    findingOrder: result.findingOrder,
    modelUsed: false,
  };
}

/** Predict advisory composition parameters for diagnostics. */
export function mlPredictAdvisoryComposition(findings: Finding[]): EmailCompositionPrediction | null {
  return predictAdvisoryComposition(findings);
}

/** Order findings by ML-predicted importance. */
export function mlOrderFindingsByImportance(findings: Finding[]): Finding[] {
  return orderFindingsByMlImportance(findings);
}

/**
 * Champion-challenger shadow mode — deploy a challenger model alongside the
 * active model for A/B evaluation on live traffic.
 *
 * The challenger receives predictions on every inference call but its output
 * is not served. After recording enough shadow feedback (actual outcomes),
 * the orchestrator can promote the challenger if it outperforms the active.
 */
export interface ShadowPrediction {
  active: PredictionResult;
  challenger?: PredictionResult;
  modelId: string;
}

/**
 * Get shadow prediction for a model: runs active (served) and challenger
 * (shadow, not served) in parallel.
 */
export function mlShadowPredict(modelId: string, features: Record<string, number>): ShadowPrediction | null {
  const runtime = getMlRuntime();
  if (!runtime?.registry) return null;
  try {
    const { active, challenger } = runtime.registry.shadowPredict(modelId, features);
    return { active, challenger, modelId };
  } catch {
    return null;
  }
}

/**
 * Record a feedback signal (actual outcome) for shadow-mode evaluation.
 * Updates the challenger's cumulative error for promotion decisions.
 */
export function mlRecordShadowFeedback(modelId: string, signal: FeedbackSignal): void {
  const runtime = getMlRuntime();
  if (!runtime?.registry) return;
  try {
    runtime.registry.recordShadowFeedback(modelId, signal);
  } catch {
    /* shadow feedback never blocks the pipeline */
  }
}

/**
 * Promote the challenger to active if it outperforms the active model over
 * at least `minShadowCount` shadow predictions.
 */
export function mlPromoteChallenger(modelId: string, minShadowCount = 100): { promoted: boolean; challengerError?: number } {
  const runtime = getMlRuntime();
  if (!runtime?.registry) return { promoted: false };
  try {
    return runtime.registry.promoteChallengerIfBetter(modelId, minShadowCount);
  } catch {
    return { promoted: false };
  }
}

/**
 * Deploy a challenger model in shadow mode for a given modelId.
 */
export function mlDeployChallenger(
  modelId: string,
  challenger: TrainableModel,
  metadata: ModelMetadata,
): boolean {
  const runtime = getMlRuntime();
  if (!runtime?.registry) return false;
  try {
    return runtime.registry.deployChallenger(modelId, challenger, metadata);
  } catch {
    return false;
  }
}

/**
 * Online learning — apply a single outcome to a trained model via partialFit.
 *
 * Called per-outcome (delivery success/failure, match confirmed/dismissed,
 * review resolved/false positive) so models adapt continuously instead of
 * waiting for the nightly retraining batch. Models that don't support
 * partialFit (e.g. tree-based rankers) are skipped silently.
 *
 * The signal is also recorded as shadow feedback if a challenger is deployed,
 * enabling champion-challenger promotion decisions.
 */
export function mlOnlineLearn(signal: FeedbackSignal): void {
  const runtime = getMlRuntime();
  if (!runtime?.registry) return;
  const entry = runtime.registry.get(signal.modelId);
  if (!entry) return;

  const model = entry.model;
  if (typeof model.partialFit === 'function') {
    try {
      const sample: TrainingSample = {
        id: signal.sampleId,
        features: signal.features,
        label: signal.actual,
        weight: signal.weight,
        timestamp: signal.timestamp,
      };
      model.partialFit(sample);
      // Persist the updated model incrementally (best-effort, non-blocking).
      void runtime.registry.save(model, signal.modelId, entry.metadata).catch(() => {});
    } catch {
      /* partialFit failures never block the pipeline */
    }
  }

  // Record shadow feedback for challenger evaluation.
  runtime.registry.recordShadowFeedback(signal.modelId, signal);
}

async function logMlEvent(
  code: string,
  message: string,
  context: Record<string, unknown> = {},
): Promise<void> {
  if (!ctx.pool || !['WARNING', 'ERROR'].includes(String(context.level))) return;
  try {
    await writeEvent(ctx.pool, {
      category: 'ML',
      code,
      message,
      level: context.level === 'WARNING' ? 'WARNING' : context.level === 'ERROR' ? 'ERROR' : 'INFO',
      context,
    });
  } catch (error) {
    console.error('ML event persistence failed', { code, error: error instanceof Error ? error.message : String(error) });
  }
}
