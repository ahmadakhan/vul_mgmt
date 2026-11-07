import { z } from 'zod';
import type { TrainingDataSources } from './train/orchestrator.ts';
import { EXPLOIT_RISK_LEVELS } from './models/exploitRiskModel.ts';
import { SEVERITY_TIERS } from './models/severityTierModel.ts';
import { SUBJECT_TEMPLATES } from './models/advisoryComposer.ts';

const nonnegative = z.number().finite().nonnegative();
const score = z.number().min(0).max(100);
const riskFeatures = z.object({
  cvssScore: z.number().min(0).max(10),
  epssScore: z.number().min(0).max(1),
  cisaKev: z.boolean(),
  exploitStatus: z.enum(['None', 'POC Available', 'Reported In Wild', 'Active Weaponized']),
  daysSincePublished: nonnegative,
}).strict();
const severityFeatures = riskFeatures.extend({
  cweRiskLevel: nonnegative,
  sourceFeedWeight: score,
});
const digestFeatures = severityFeatures.omit({ exploitStatus: true, cweRiskLevel: true }).extend({
  exploitStatus: z.number().int().min(0).max(3),
  credibilityScore: score,
  assetCriticality: nonnegative,
  recipientTier: z.enum(['ALL', 'CRITICAL_ONLY', 'SUBSCRIBED_ONLY']),
  findingInDigest: z.boolean(),
  timeInDigestMinutes: nonnegative,
});
const count = nonnegative.int().max(10000);
const compositionFeatures = z.object({
  criticalCount: count, highCount: count, mediumCount: count, lowCount: count, unknownCount: count,
  totalFindings: count, maxCvssScore: z.number().min(0).max(10), avgCvssScore: z.number().min(0).max(10),
  maxEpssScore: z.number().min(0).max(1), avgEpssScore: z.number().min(0).max(1),
  kevCount: count, weaponizedCount: count, reportedInWildCount: count, pocCount: count,
  affectedAssetCount: count, uniqueVendorCount: count, avgMatchConfidence: score,
  avgDaysSincePublished: nonnegative, avgSourceFeedWeight: score,
}).strict();
const compositionSample = z.object({
  features: compositionFeatures,
  perFinding: z.array(riskFeatures.extend({
    matchConfidence: score, sourceFeedWeight: score, assetCriticality: nonnegative,
  })).max(500),
  summaryStyle: z.enum(['URGENT', 'STANDARD', 'INFORMATIONAL']),
  priorityEmphasis: z.enum(['IMMEDIATE_ACTION', 'MONITOR', 'REVIEW']),
  remediationEmphasis: z.enum(['PATCH_FIRST', 'WORKAROUND_FIRST', 'VENDOR_GUIDANCE_FIRST']),
  subjectTemplate: z.string().refine((value) => SUBJECT_TEMPLATES.includes(value), 'Unknown subject template'),
  wasActionable: z.boolean(),
}).strict();
const outcome = z.enum(['TIDY', 'PATCHED', 'RESOLVED', 'DELIVERED', 'FALSE_POSITIVE']);

export const mlTelemetrySchema = z.object({
  memoryPercent: z.number().min(0).max(100),
  activeWorkers: nonnegative, concurrencyLimit: nonnegative, latencyMs: nonnegative,
  deadLetters: nonnegative, pendingClaims: nonnegative, itemsPerSecond: nonnegative,
  poolWaiting: nonnegative,
}).strict();

export const mlDeliveryOutcomeSchema = z.object({
  jobId: z.uuid().optional(),
  delayObserved: z.boolean().optional(),
  provider: z.string().min(1).max(100),
  attempt: z.number().int().min(1), delayMs: nonnegative,
  succeeded: z.boolean(), isRateLimited: z.boolean(), isPermanentFailure: z.boolean(),
}).strict();
export const mlDeliveryErrorSchema = z.object({
  provider: z.string().min(1).max(100), statusCode: z.number().int().min(0).max(599),
  errorMessage: z.string().max(1000), attemptNumber: z.number().int().min(1),
  hourOfDay: z.number().int().min(0).max(23), isPermanent: z.boolean(),
}).strict();

// Labels must come from an analyst or measured outcome, never the prediction being trained.
export const mlFeedbackSchema = z.discriminatedUnion('source', [
  z.object({ source: z.literal('calibrationPairs'), sample: z.object({
    credibilityScore: score, isActionable: z.boolean(),
  }).strict() }).strict(),
  z.object({ source: z.literal('exploitRiskSamples'), sample: z.object({
    features: riskFeatures.extend({ exploitationSourcesCount: count }),
    riskLevel: z.enum(EXPLOIT_RISK_LEVELS),
  }).strict() }).strict(),
  z.object({ source: z.literal('severityTierSamples'), sample: z.object({
    features: severityFeatures, tier: z.enum(SEVERITY_TIERS),
  }).strict() }).strict(),
  z.object({ source: z.literal('digestSelectionSamples'), sample: z.object({
    features: digestFeatures, isRelevant: z.boolean(),
  }).strict() }).strict(),
  z.object({ source: z.literal('zeroDayRateLimitSamples'), sample: z.object({
    zeroDayCount: count, credibilityScores: z.array(score).max(10000),
    outcomes: z.array(outcome).max(10000),
  }).strict().refine((sample) =>
    sample.credibilityScores.length === sample.zeroDayCount &&
    sample.outcomes.length === sample.zeroDayCount,
  'Provide one measured outcome paired with each zero-day credibility score') }).strict(),
  z.object({ source: z.literal('emailCompositionSamples'), sample: compositionSample }).strict(),
]).refine((value) => JSON.stringify(value).length <= 28000, 'Feedback exceeds the event storage limit');

export function appendMlFeedback(data: TrainingDataSources, input: unknown): void {
  const parsed = mlFeedbackSchema.safeParse(input);
  if (!parsed.success) {
    const legacyZeroDayFeedback = z.object({
      source: z.literal('zeroDayRateLimitSamples'),
      sample: z.object({
        zeroDayCount: count,
        credibilityScores: z.array(score).max(10000),
        keptOutcomes: z.array(outcome).max(10000),
        droppedOutcomes: z.array(outcome).max(10000),
      }).strict().refine((sample) => sample.credibilityScores.length === sample.zeroDayCount &&
        sample.keptOutcomes.length + sample.droppedOutcomes.length === sample.zeroDayCount),
    }).strict();
    if (legacyZeroDayFeedback.safeParse(input).success) return;
    throw parsed.error;
  }
  const feedback = parsed.data;
  switch (feedback.source) {
    case 'calibrationPairs': (data.calibrationPairs ??= []).push(feedback.sample); break;
    case 'exploitRiskSamples': (data.exploitRiskSamples ??= []).push(feedback.sample); break;
    case 'severityTierSamples': (data.severityTierSamples ??= []).push(feedback.sample); break;
    case 'digestSelectionSamples': (data.digestSelectionSamples ??= []).push(feedback.sample); break;
    case 'zeroDayRateLimitSamples': (data.zeroDayRateLimitSamples ??= []).push(feedback.sample); break;
    case 'emailCompositionSamples': (data.emailCompositionSamples ??= []).push(feedback.sample); break;
  }
}
