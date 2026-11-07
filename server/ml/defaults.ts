/**
 * Default constants for ML-powered pipeline integration.
 *
 * These mirror the existing hardcoded defaults in the pipeline code so that
 * the ML integration layer is a strict superset of behavior — when models
 * are untrained, the system behaves identically to the pre-ML baseline.
 */

/** Default auto-dispatch confidence threshold (percentage) — matches pipelineEngine.ts. */
export const DEFAULT_AUTO_DISPATCH_THRESHOLD = 90;

/** Default initial retry delay in minutes for email delivery. */
export const DEFAULT_EMAIL_RETRY_INITIAL_DELAY_MINUTES = 5;

/** Default backoff multiplier for email delivery. */
export const DEFAULT_EMAIL_RETRY_MULTIPLIER = 2;

/** Default maximum delay in minutes (1 week) for email delivery. */
export const DEFAULT_EMAIL_RETRY_MAX_DELAY_MINUTES = 1440;

/** Default maximum delivery attempts. */
export const DEFAULT_EMAIL_RETRY_MAX_ATTEMPTS = 5;

/** Default maximum zero-day findings per pipeline run — matches pipelineEngine.ts:101. */
export const DEFAULT_MAX_ZERO_DAYS_PER_RUN = 50;

/** Default feed recovery initial delay in minutes — matches feedRecovery.ts:13. */
export const DEFAULT_FEED_RECOVERY_INITIAL_DELAY_MINUTES = 5;

/** Default feed recovery max delay in minutes (1 hour) — matches feedRecovery.ts:14. */
export const DEFAULT_FEED_RECOVERY_MAX_DELAY_MINUTES = 60;

/** Default feed recovery backoff multiplier — matches feedRecovery.ts:14. */
export const DEFAULT_FEED_RECOVERY_BACKOFF_MULTIPLIER = 2;

/** Default feed recovery max steps — matches feedRecovery.ts:14 (2^6 = 64x). */
export const DEFAULT_FEED_RECOVERY_MAX_STEPS = 6;

/** Default EPSS threshold for high-risk classification — matches severityClassifier.ts:12. */
export const DEFAULT_EPSS_HIGH_THRESHOLD = 0.4;

/** Default feed credibility weight — matches intelligenceMatcher.ts:46. */
export const DEFAULT_FEED_CREDIBILITY_WEIGHT = 0.6;

/** Default keyword credibility weight — matches intelligenceMatcher.ts:46. */
export const DEFAULT_KEYWORD_CREDIBILITY_WEIGHT = 0.4;

/** Default digest finding limit per severity bucket — matches templateCompiler.ts:652. */
export const DEFAULT_DIGEST_FINDINGS_PER_SEVERITY = 25;

/** Default alias confirmation threshold — used as fallback for isConfirmedFinding. */
export const DEFAULT_ALIAS_CONFIRMED_THRESHOLD = 0.5;
