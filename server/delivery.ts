import { validateNativeDelivery, type NativeDelivery } from './correlation/notificationEvidence.ts';
import { describeError, writeEvent } from './events';
import { classifyDeliveryError, computeRetryDelay, getMlRuntime } from './ml/integration.ts';
import { advisoryEmail } from './advisoryEmail';
import {
  htmlAttachmentIsAttachable,
  renderFindingsDocument,
  renderFindingsText,
  resolveAdvisoryTemplate,
  type SavedTemplateRecord,
} from './deliveryDocument.ts';
import type pg from 'pg';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { DEFAULT_SETTINGS, DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import type {
  WatchListItem,
  NormalizedCVE,
  AliasEntry,
  IntelligenceArticle,
  IntelligenceMatch,
} from '../src/types/index.ts';
import { newsArticleIdentity, recordNewsDeliveries } from './newsQueue.ts';
import {
  activeClaims,
  attachClaimsToJob,
  claimItems,
  claimsForJob,
  markClaimsDelivered,
  reconcileDuplicateOutboxClaims,
  releaseClaims,
  releaseUnattachedClaims,
} from './deliveryClaims.ts';
import { uniqueEnabledEmailRecipients } from './emailRecipients.ts';
/**
 * Payload carried by a consolidated news delivery job.
 *
 * `articles` is the de-duplication view: `newsQueue.alreadyNotified` reads it
 * from every queued and accepted job to decide whether an article was already
 * delivered to a recipient. It must therefore always list every article the
 * email carries.
 */
export interface NewsEvidencePayload {
  /** First IntelligenceMatch.id consolidated into this email. */
  matchId: string;
  /** Primary article, retained for backwards-compatible consumers. */
  article: Pick<IntelligenceArticle, 'id' | 'title' | 'url' | 'sourceFeeds' | 'publishedDate'>;
  /** Every article carried by this consolidated email. */
  articles: Array<Pick<IntelligenceArticle, 'id' | 'title' | 'url' | 'sourceFeeds' | 'publishedDate'> & {identity?: string}>;
  /** Assets the articles were matched against. */
  assets: string[];
  /** @deprecated First matched asset; use `assets`. */
  asset: { name: string; vendor?: string; product?: string };
  /** CVE identifiers referenced by the matched article, if any. */
  cveIds: string[];
  /** Structured evidence text for the email body. */
  evidence: string;
  /** True when the article describes an unassigned vulnerability (potential zero-day). */
  zeroDay?: boolean;
  credibilityScore?: number;
}
/** Zero-day evidence consolidated into a digest instead of individual alerts. */
export interface ZeroDayDigestPayload {
  /** `DIGEST_<vendor>_<product>` identity from `rankAndRateLimitZeroDays`. */
  digestId: string;
  vendor: string;
  product: string;
  /** Matches this digest replaces. Kept for audit, not for re-dispatch. */
  matchIds: string[];
  matchCount: number;
  findings: Array<{
    findingId?: string;
    cveId?: string;
    assetName: string;
    evidence: string;
    credibilityScore?: number;
  }>;
  articles: Array<{ id: string; title: string; url: string; sourceFeeds: string[] }>;
}


import { buildAliasMap, parseCPE23 } from '../src/utils/cpeMatcher';
import { randomUUID, createHmac, createHash } from 'node:crypto';
import { mergeCveRecords, stableJson } from '../src/utils/deduplicator';
import nodemailer from 'nodemailer';
import type { Config } from './config';
import { transaction, get, getMany, list, put, appendAudit, schemaLockKey } from './db';
import type { Db } from './db';
import { createRequester, type Requester } from './network';
import { isFindingDelivery } from '../src/utils/findingDelivery.ts';
import {
  effectiveSubject,
  normalizeEmailSubject,
  renderReviewEdits,
  renderReviewText,
} from './emailEdits';
import {
  EMAIL_PROVIDER_LABELS,
  EmailProviderError,
  emailIsConfigured,
  lookupProviderDelivery,
  sendProviderEmail,
} from './emailProviders';
import { decrypt, encryptionKeys } from './secrets';
import { isSmtpEmailProvider } from '../src/types/index.ts';
import type {
  Advisory,
  Finding,
  EmailRecipient,
  WebhookEndpoint,
  EmailDeliveryLog,
  WebhookDeliveryLog,
  AlertedCVE,
  EmailConfiguration,
  AppSettings,
  ReviewEdits,
} from '../src/types/index.ts';
export interface Job {
  id: string;
  dedupe_key: string;
  channel: 'email' | 'webhook';
  target_id: string;
  advisory_id: string;
  payload: {
    subject: string;
    text: string;
    html?: string;
    recipientEmail?: string;
    cveIds: string[];
    nativeCorrelation?: NativeDelivery;
    cveRevisions?: Record<string, string>;
    findingRevisions?: Record<string, string>;
      /** Provider-assigned message id of a prior attempt that could not be recorded. */
      unconfirmedProviderId?: string;
      /**
     * Digest jobs carry only the findings the target is subscribed to. Delivery
     * revalidation and receipt accounting must use this subset, not the union
     * advisory, or a KEV-only recipient would be blocked by unrelated findings.
     */
    includedFindingIds?: string[];
    /** Stable per-batch key used for CVE dispatch accounting across recipients. */
    digestKey?: string;
    /**
     * IntelligenceMatch (security news/advisory) evidence queued for direct
     * delivery to the Security team. When present, the job carries no advisory
     * row and is validated as a news bundle instead.
     */
    newsEvidence?: NewsEvidencePayload;
    /**
     * Legacy unverifiable-match review bulletin.
     *
     * No longer produced: findings the policy could not fully confirm are now
     * dispatched in the ordinary consolidated finding email, annotated with
     * their confidence limitation. The field is retained so an outbox row queued
     * by an older build is still recognised as a standalone (advisory-less)
     * bundle and delivered or terminally failed on its own terms instead of being
     * mistaken for a job whose advisory vanished.
     */
    unverifiableMatch?: {
      findings: Array<{ findingId: string; cveId: string; evidence: string; severity: string }>;
      cveIds: string[];
      timezone?: string;
    };
    /**
     * Zero-day digest consolidated under the per-run cap
     * (`rankAndRateLimitZeroDays`). When present, the job is a standalone summary
     * of withheld zero-day evidence and carries no advisory row. The findings it
     * names are NOT part of the ordinary dispatch path — they were removed from
     * it deliberately — so delivery must not treat them as a finding bundle.
     */
    zeroDayDigest?: ZeroDayDigestPayload;
    /**
     * The content revision this payload was queued under. Queueing proves the
     * revision; re-deriving it later from the advisory does not. The advisory a
     * digest job references is the union of every recipient's findings, so the
     * content-derived key differs from the per-recipient key for any mixed
     * subscription set. Approval re-hashes the stored payload and must compare
     * against this value, not a recomputed union revision.
     */
    contentRevision?: string;
    /**
     * When true, the job is a calendar daily-digest delivery: an overall summary
     * email. Such jobs never carry a PDF attachment — the body is the summary
     * itself — so the sender skips PDF rendering entirely.
     */
    dailyDigest?: boolean;
    /**
     * ISO instant pinned when the body was rendered.
     *
     * The document embeds this timestamp, and the PDF attachment is rendered
     * from the same HTML. Pinning it proves the attachment matches the body and
     * gives retries byte-identical content instead of a document that drifts by
     * a second on every attempt.
     */
    generatedAt?: string;
  };
  attempts: number;
  prior_attempt_at?: Date | string | null;
  lock_token: string;
  review_approved?: boolean;
  edits?: ReviewEdits;
  priority?: number;
}
export type MailSender = (
  job: Job,
) => Promise<string | { id: string; provider: EmailDeliveryLog['provider'] }>;

/**
 * Applies the operator's review edits to a queued job.
 *
 * This is the single place where the email body, its plain-text companion and
 * the subject are reconciled. `deliverNext` calls it before handing the job to
 * the transport, and `buildPdfAttachment` renders the PDF from the same
 * `payload.html`, so an edit made in the Action Center cannot update the email
 * without updating its attachment.
 *
 * The transform is idempotent (see `renderReviewEdits`), which matters because
 * approval may already have merged the notice/comment into the stored body.
 */
export function applyJobEdits(job: Job): Job {
  if (!job.edits || !Object.keys(job.edits).length) return job;
  const edits = job.edits;
  return {
    ...job,
    payload: {
      ...job.payload,
      html: renderReviewEdits(job.payload.html, edits),
      text: renderReviewText(job.payload.text, edits),
      subject: effectiveSubject(job.payload.subject, edits),
    },
  };
}
export interface EmailAttachment {
  filename: string;
  content: Buffer;
  contentType: string;
}

/** Exactly the same post-edit bytes as the HTML message part. */
export function findingHtmlAttachment(content: Job): EmailAttachment | undefined {
  if (!(isFindingDelivery(content.advisory_id) || content.advisory_id.startsWith('FINDINGS:')))
    return undefined;
  const html = content.payload.html;
  if (!htmlAttachmentIsAttachable(html))
    throw new Error('Finding email HTML is missing or exceeds the attachment limit; delivery deferred');
  return {
    filename: `${deliveryAttachmentStem(content)}.html`,
    content: Buffer.from(html, 'utf8'),
    contentType: 'text/html; charset=utf-8',
  };
}
export interface EmailRetryPolicy {
  /** When false, a transient failure becomes terminal after the first attempt. */
  enabled: boolean;
  /** Total attempts, including the first send. */
  maxAttempts: number;
  initialDelayMinutes: number;
  maxDelayMinutes: number;
}
const boundedInt = (value: unknown, fallback: number, min: number, max: number) => {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
};
/**
 * Resolves the operator-configured retry policy. Persisted settings from older
 * deployments may not contain these fields yet, so missing values fall back to
 * the documented defaults instead of disabling retries silently.
 */
export function emailRetryPolicy(settings?: Partial<AppSettings> | null): EmailRetryPolicy {
  const initialDelayMinutes = boundedInt(
    settings?.emailRetryInitialDelayMinutes,
    DEFAULT_SETTINGS.emailRetryInitialDelayMinutes,
    1,
    1440,
  );
  return {
    enabled: settings?.emailRetryEnabled ?? DEFAULT_SETTINGS.emailRetryEnabled,
    maxAttempts: boundedInt(settings?.emailRetryMaxAttempts, DEFAULT_SETTINGS.emailRetryMaxAttempts, 1, 20),
    initialDelayMinutes,
    maxDelayMinutes: Math.max(
      initialDelayMinutes,
      boundedInt(settings?.emailRetryMaxDelayMinutes, DEFAULT_SETTINGS.emailRetryMaxDelayMinutes, 1, 10080),
    ),
  };
}
export const DEFAULT_EMAIL_RETRY_POLICY = emailRetryPolicy(DEFAULT_SETTINGS);
/**
 * Exponential backoff capped by the configured maximum, so a provider outage is
 * retried durably without hammering the relay and without retrying forever.
 */
export const emailRetryDelayMs = (attempt: number, policy: EmailRetryPolicy) =>
  Math.min(
    policy.maxDelayMinutes * 60_000,
    policy.initialDelayMinutes * 60_000 * 2 ** Math.max(0, attempt - 1),
  );
export function emailRetryDelayPlan(
  attempt: number,
  policy: EmailRetryPolicy,
  mlDelayMs?: number,
): { delayMs: number; source: 'OPERATOR' | 'ML' | 'ML_CAPPED' } {
  const operatorDelayMs = emailRetryDelayMs(attempt, policy);
  if (mlDelayMs === undefined || !Number.isFinite(mlDelayMs) || mlDelayMs <= operatorDelayMs)
    return { delayMs: operatorDelayMs, source: 'OPERATOR' };
  const ceiling = policy.maxDelayMinutes * 60_000;
  return {
    delayMs: Math.min(ceiling, mlDelayMs),
    source: mlDelayMs > ceiling ? 'ML_CAPPED' : 'ML',
  };
}
export function observedRetryDelay(
  priorAttemptAt: Date | string | null | undefined,
  attemptStartedAt: number,
): { delayMs: number; observed: boolean } {
  if (!priorAttemptAt) return { delayMs: 0, observed: false };
  const priorTime = new Date(priorAttemptAt).getTime();
  return Number.isFinite(priorTime)
    ? { delayMs: Math.max(0, attemptStartedAt - priorTime), observed: true }
    : { delayMs: 0, observed: false };
}
/** Human-readable schedule stored on the delivery log for operator visibility. */
export const emailRetrySchedule = (policy: EmailRetryPolicy) =>
  policy.enabled
    ? Array.from(
        { length: policy.maxAttempts },
        (_, index) => `${Math.round(emailRetryDelayMs(index + 1, policy) / 60_000)}m`,
      )
    : [];
/**
 * Content-relevant CVE fingerprint used for delivery staleness checks.
 *
 * Only fields that affect advisory content (severity, remediation links,
 * CISA KEV status in the finding-detail line) or matching applicability are
 * included. Enrichment and metadata fields — EPSS scores, exploit status,
 * exploitation sources, source-feed attribution, publication/modification
 * timestamps, CPE weakness IDs — are excluded because feed refreshes update
 * them independently of the matching engine without altering the advisory a
 * recipient receives.
 *
 * This deliberately mirrors the field set of `matchingCveSignature` in
 * pipeline.ts (the signature the pipeline uses for its reusable-match
 * optimisation) plus `cvss`, `remediation` and `cisaKev.isKev`, all of which
 * surface in delivered content. Aligning these two signatures prevents a
 * benign enrichment refresh from triggering a false "CVE intelligence
 * changed" failure when the pipeline correctly treats the refresh as a
 * no-op.
 */
export const revision = (cve: NormalizedCVE) => {
  const canonical = mergeCveRecords([cve]).get(cve.cveId) || cve;
  return createHash('sha256')
    .update(
      stableJson({
        cveId: canonical.cveId,
        title: canonical.title,
        description: canonical.description,
        cvss: canonical.cvss,
        cpeMatches: canonical.cpeMatches,
        cpeMatchDetails: canonical.cpeMatchDetails,
        versionRange: canonical.versionRange,
        purls: canonical.purls,
        applicabilityRequiresReview: canonical.applicabilityRequiresReview,
        applicabilityPolicy: canonical.applicabilityPolicy,
        remediation: canonical.remediation,
        isKev: canonical.cisaKev?.isKev ?? false,
      }),
    )
    .digest('hex');
};
/**
 * Finding fingerprint for delivery staleness checks and advisory content
 * revision (dedupe key).
 *
 * `exploitRisk` is intentionally excluded: it is derived from enrichment
 * data (EPSS, KEV, exploit status) that the pipeline refreshes independently
 * of matching. Including it would make the content-revision change whenever
 * a feed refresh updated a score, which in turn prevents the ON-CONFLICT
 * resurrection of a failed job from matching (different dedupe key) and
 * forces a new advisory even though the delivered email content — severity,
 * remediation links, affected systems — is unchanged. The revalidation
 * already catches genuine applicability changes via the `!match` and
 * `notificationStatus` checks below.
 *
 * `matchedCpe` and the free-text `matchingEvidence` are excluded as well: the
 * CPE recorded is the NVD criterion in one context and the inventory CPE in
 * another, while the evidence string embeds the confidence the policy happened
 * to require. Both describe *how* the match was spelled, not *whether* the
 * asset is affected, so including them made revalidation report "inventory or
 * matching evidence changed" — and the bundle fail — after a benign policy or
 * spelling difference. Affected-system content is covered by `assetName`.
 */
export const findingRevision = (finding: Finding) =>
  createHash('sha256')
    .update(
      stableJson({
        cveId: finding.cveId,
        assetId: finding.matchedAssetId,
        assetName: finding.matchedAssetName,
        // Include the matched asset vendor/product so a cosmetic identity
        // label change (e.g. an alias thesaurus rename) re-renders a digest
        // summary instead of silently shipping stale labels. Pure enrichment
        // fields remain excluded to avoid churn on feed refreshes.
        assetVendor: finding.matchedAssetVendor,
        assetProduct: finding.matchedAssetProduct,
      }),
    )
    .digest('hex');
/**
 * Content revision for one advisory. Queueing the same advisory revision twice
 * is idempotent; a materially changed advisory (new findings, revised severity,
 * summary, remediation, or changed CVE evidence) gets a new revision and can be
 * delivered again.
 */
export const advisoryRevision = (advisory: Advisory, findings: Finding[]) =>
  createHash('sha256')
    .update(
      stableJson({
        advisory: {
          // The advisory ID is intentionally excluded: pipeline-created
          // advisories receive a new random ID on every run, so including it
          // would defeat idempotent delivery of unchanged content. An explicit
          // operator dispatch key still distinguishes intentional resends.
          title: advisory.title,
          severity: advisory.severity,
          // Delivery content is a set, not a sequence. Sorting here keeps the
          // dedupe key stable when the pipeline or a digest buffer returns the
          // same findings in a different database order.
          cveIds: [...advisory.cveIds].sort(),
          findingIds: [...advisory.findingIds].sort(),
          executiveSummary: advisory.executiveSummary,
          remediationInstructions: advisory.remediationInstructions,
          affectedSystems: [...advisory.affectedSystems].sort(),
          isDigestBatch: advisory.isDigestBatch ?? false,
          vendorLink: advisory.vendorLink ?? '',
        },
        findings: findings
          .map((finding) => [
            finding.id,
            findingRevision(finding),
            // A CVE evidence change (affected CPEs, version range, remediation,
            // severity) alters the delivered advisory even when the finding row
            // itself is unchanged. `revision` excludes enrichment noise, so this
            // honours the documented dedupe contract without churn on feed
            // refreshes.
            revision(finding.cve),
          ])
          .sort(([left], [right]) => left.localeCompare(right)),
      }),
    )
    .digest('hex')
    .slice(0, 20);
export const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#16a34a',
  UNKNOWN: '#6b7280',
};
const uniqueSorted = (values: string[]) => Array.from(new Set(values)).sort();
/** Highest severity in a set of findings, used for combined digest subjects. */
const highestSeverity = (findings: Finding[]): Advisory['severity'] =>
  findings.reduce(
    (severity, finding) =>
      SEVERITY_ORDER.indexOf(finding.cve.cvss.severity) > SEVERITY_ORDER.indexOf(severity)
        ? finding.cve.cvss.severity
        : severity,
    'UNKNOWN' as Advisory['severity'],
  );
const findingDetail = (finding: Finding) =>
  `${finding.cveId} | ${finding.cve.cvss.severity}${finding.cve.cisaKev?.isKev ? ' | CISA KEV' : ''} | ${finding.matchedAssetName}`;
/** Deterministic vendor link so batch ordering cannot change the dedupe key. */
const vendorLinkFor = (findings: Finding[]) =>
  uniqueSorted(
    findings
      .map((finding) => finding.cve.remediation.vendorAdvisoryRef || finding.cve.remediation.patchUrl)
      .filter((link): link is string => !!link),
  )[0] || '';
/**
 * Builds the advisory view for a set of findings. Every recipient receives a
 * view containing exactly the findings its subscription permits, while the
 * persisted advisory is the union of all views for queue accounting.
 */
function digestView(advisory: Advisory, findings: Finding[]): Advisory {
  const cveIds = uniqueSorted(findings.map((finding) => finding.cveId));
  const systems = uniqueSorted(findings.map((finding) => finding.matchedAssetName));
  const severity = highestSeverity(findings);
  const vulnerabilitySeverityParts: string[] = [];
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const) {
    const count = findings.filter((finding) => finding.cve.cvss.severity === sev).length;
    if (count) vulnerabilitySeverityParts.push(count + ' ' + sev.charAt(0) + sev.slice(1).toLowerCase());
  }
  const vulnerabilitySeveritySummary = vulnerabilitySeverityParts.length
    ? vulnerabilitySeverityParts.join(', ')
    : '0 vulnerabilities';
  const summary =
    findings.length === 1
      ? '1 inventory correlation requires investigation. Confirm applicability and consult the vendor before remediation.'
      : `${findings.length} inventory correlations across ${systems.length} system${systems.length === 1 ? '' : 's'} require investigation. Confirm applicability and consult the vendor before remediation.`;
  return {
    ...advisory,
    title: `Vulnerability ${findings.length === 1 ? 'notice' : 'digest'}: ${vulnerabilitySeveritySummary}`,
    severity,
    cveIds,
    findingIds: findings.map((finding) => finding.id),
    executiveSummary: summary,
    affectedSystems: systems,
    vendorLink: vendorLinkFor(findings),
    isDigestBatch: true,
  };
}
const advisoryPriority = (findings: Finding[]) =>
  Math.max(
    0,
    ...findings.map((finding) =>
      finding.cve.cisaKev?.isKev
        ? 100
        : finding.exploitRisk === 'REPORTED_IN_WILD_EXPLOIT' ||
            finding.exploitRisk === 'WEAPONIZED_EXPLOIT' ||
            finding.cve.exploitationSources?.length
          ? 50
          : finding.notificationStatus === 'REVIEW_REQUIRED'
            ? 50
            : 0,
    ),
  );
export function recipientAllows(recipient: EmailRecipient, finding: Finding): boolean {
  return (
    recipient.subscriptionTier === 'ALL_SEVERITIES' ||
    (recipient.subscriptionTier === 'CRITICAL_HIGH_ONLY' &&
      ['CRITICAL', 'HIGH'].includes(finding.cve.cvss.severity)) ||
    (recipient.subscriptionTier === 'CISA_KEV_ONLY' && finding.cve.cisaKev?.isKev)
  );
}
export function webhookAllows(hook: WebhookEndpoint, finding: Finding): boolean {
  return (
    hook.events.includes('ALL') ||
    (hook.events.includes('CRITICAL') && finding.cve.cvss.severity === 'CRITICAL') ||
    (hook.events.includes('CISA_KEV') && finding.cve.cisaKev?.isKev)
  );
}
/** Converts the email body into a PDF attachment, or returns undefined when PDF
 *  delivery is disabled, the job carries no HTML body, or rendering fails.
 *  Failures degrade to HTML-only delivery instead of blocking the send.
 *
 *  The input is the *exact* HTML the message is sent with (the caller passes the
 /**
 * Attachment stem for a delivery.
 *
 * Real advisories keep their id. Synthetic bundles carry an internal prefix and
 * a potentially very long id list, which makes a poor filename and can exceed
 * filesystem limits; those get a truncation-safe stem derived from the same id.
 */
function deliveryAttachmentStem(job: Job): string {
  const id = job.advisory_id || job.id;
  if (!/^(NEWS|FINDINGS|ZERODAY|UNVERIFIABLE|SELFHEAL|DAILY[_-])/i.test(id)) return id;
  const [prefix] = id.split(':');
  const label = prefix.replace(/[_-]+/g, '-').toUpperCase();
  const fingerprint = createHash('sha256').update(id).digest('hex').slice(0, 12).toUpperCase();
  return `${label}-${fingerprint}`;
}

export type DeliveryConfirmation = 'delivered' | 'not-delivered' | 'unknown';
/**
 * Decides, without ever contacting the transport, whether a previous attempt
 * may already have delivered this message.
 *
 * Evidence that the provider accepted the message is committed only after the
 * send returns, so an attempt that sent and then lost its commit is
 * indistinguishable from one that never sent. The provider's own record of the
 * message id is therefore authoritative, and it is queried when the local
 * evidence is inconclusive. Only when that lookup cannot answer is the job
 * withheld rather than resent.
 *
 * SMTP failures before submission can be retried. Losing the connection after
 * DATA may hide acceptance, so an ambiguous outcome is not blindly resent.
 */
async function confirmPriorDelivery(
  db: Db,
  job: Job,
  config: Config,
  request: Requester,
): Promise<DeliveryConfirmation> {
  if (job.channel !== 'email') return 'not-delivered';
  const log = await get<EmailDeliveryLog>(db, 'emailLogs', job.id);
  if (log?.sentAt || log?.status === 'ACCEPTED') return 'delivered';
  // The recorded cause of the failure is decisive. A transport that provably
  // rejected the message (4xx/5xx response, refused SMTP session) means retrying
  // cannot duplicate it. The structured `transportRejected` flag is authoritative
  // (audit M-6): it is set by the finalize path from the concrete failure type,
  // not inferred from message text. The regex remains only for logs written
  // before the flag existed.
  if (log?.transportRejected === true) return 'not-delivered';
  if (log?.transportRejected === false) {
    // Explicitly not rejected: the attempt failed for an unknown reason
    // (timeout, reset, dropped socket) — fall through to provider confirmation.
  } else if (
    log?.errorMessage &&
    /HTTP \d{3}\b|did not accept the recipient|not configured|is missing/i.test(log.errorMessage)
  )
    return 'not-delivered';
  const saved = (await get<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
  // The local evidence is inconclusive, so ask the provider. This is the only
  // way to tell an attempt that delivered and lost its receipt from one that
  // never left, and it is what lets those jobs be recovered instead of held.
  const messageId = job.payload.unconfirmedProviderId || log?.providerId || '';
  if (!messageId) return 'unknown';
  const token = decrypt(saved.apiKey, encryptionKeys(config), `email-provider:${saved.provider}`);
  if (!token) return 'unknown';
  return lookupProviderDelivery(saved, token, messageId, request);
}

export function createMailSender(
  config: Config,
  db?: Db,
  request: Requester = createRequester(config),
): MailSender {
  const transporter = config.SMTP_HOST
    ? nodemailer.createTransport({
        host: config.SMTP_HOST,
        port: config.SMTP_PORT,
        secure: config.SMTP_PORT === 465,
        requireTLS: true,
        auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASSWORD } : undefined,
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 20000,
        disableFileAccess: true,
        disableUrlAccess: true,
      })
    : null;
  return async (job) => {
    const saved = (db && (await get<EmailConfiguration>(db, 'emailConfig', 'main'))) || DEFAULT_EMAIL_CONFIG;
    if (!emailIsConfigured(saved, config)) throw new Error('Email provider is not configured');
    if (job.channel === 'email') {
      const settings = (db && (await get<AppSettings>(db, 'settings', 'main'))) || DEFAULT_SETTINGS;
      if (settings.emailEnabled === false) throw new Error('Email delivery is disabled by settings');
    }
// Apply operator edits once. The attachment contains the exact HTML body.
    const content = applyJobEdits(job);
    // Failure to attach is a delivery failure, never a silent HTML-only send.
    const htmlAttachment = findingHtmlAttachment(content);
    const attachments: EmailAttachment[] = htmlAttachment ? [htmlAttachment] : [];
    if (!isSmtpEmailProvider(saved.provider)) {
      const token = decrypt(saved.apiKey, encryptionKeys(config), `email-provider:${saved.provider}`);
      if (!token) throw new Error('Email provider token is missing');
      const mailjetSecret =
        saved.provider === 'MAILJET_API'
          ? decrypt(saved.mailjetApiSecret, encryptionKeys(config), `email-mailjet:${saved.provider}`)
          : saved.mailjetApiSecret;
      const provider = EMAIL_PROVIDER_LABELS[saved.provider];
try {
        const id = await sendProviderEmail(
          { ...saved, mailjetApiSecret: mailjetSecret },
          token,
          content,
          request,
          config.MAILJET_SANDBOX_MODE === 'true',
          attachments,
        );
        return { id, provider };
      } catch (error) {
        if (error instanceof EmailProviderError) {
          error.provider = provider;
          throw error;
        }
        throw new EmailProviderError(`${provider} connection failed`, 502, 0, provider);
      }
    }
    const fromEmail = saved.fromEmail || config.SMTP_FROM;
    if (!fromEmail) throw new Error('SMTP from address is not configured');
    const fromDomain = fromEmail.split('@').pop() || 'localhost';
    const configuredSmtpHost = saved.smtpHost;
    const usesDeploymentSmtp = saved.provider === 'SMTP' && !configuredSmtpHost;
    const smtpPassword = usesDeploymentSmtp
      ? config.SMTP_PASSWORD
      : decrypt(saved.smtpPassword, encryptionKeys(config), `email-smtp:${saved.provider}`);
    const smtpTransport = usesDeploymentSmtp
      ? transporter
      : nodemailer.createTransport({
          host: configuredSmtpHost || config.SMTP_HOST,
          port: saved.smtpPort,
          secure: saved.smtpSecurity === 'IMPLICIT_TLS',
          requireTLS: saved.smtpSecurity === 'STARTTLS',
          auth: saved.smtpUsername ? { user: saved.smtpUsername, pass: smtpPassword } : undefined,
          connectionTimeout: 10000,
          greetingTimeout: 10000,
          socketTimeout: 20000,
          dnsTimeout: 5000,
          disableFileAccess: true,
          disableUrlAccess: true,
        });
    if (!smtpTransport) throw new Error('SMTP is not configured');
    const result = await smtpTransport.sendMail({
      from: { address: fromEmail, name: saved.fromName },
      ...(saved.replyTo ? { replyTo: saved.replyTo } : {}),
      to: content.payload.recipientEmail,
      subject: content.payload.subject,
      text: content.payload.text,
      html: content.payload.html,
      messageId: `<${content.id}@${fromDomain}>`,
      headers: {
        'X-BA-Threat-Intel-Delivery-ID': content.id,
        'Auto-Submitted': 'auto-generated',
        'List-Unsubscribe': saved.unsubscribeUrl || `<mailto:${fromEmail}?subject=unsubscribe>`,
        // RFC 8058 one-click is only valid for an HTTP(S) unsubscribe URL. A
        // mailto fallback is handled by the mail client, not an HTTP POST.
        ...(saved.unsubscribeUrl && /^https?:\/\//i.test(saved.unsubscribeUrl)
? { 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' }
          : {}),
      },
      ...(attachments.length ? { attachments } : {}),
    });
    if (
      !result.accepted?.some(
        (address) => String(address).toLowerCase() === content.payload.recipientEmail?.toLowerCase(),
      )
    )
      throw new Error('SMTP did not accept the recipient');
    return { id: result.messageId, provider: 'SMTP_Relay' };
  };
}
export async function enqueue(
  db: Db,
  channel: Job['channel'],
  targetId: string,
  advisoryId: string,
  payload: Job['payload'],
  dedupe: string,
  initialStatus: 'QUEUED' | 'REVIEW' = 'QUEUED',
  priority = 0,
  edits: ReviewEdits = {},
) {
  // Master switch: when email delivery is disabled, no email job is queued at
  // all. Provider configuration is left intact; only transport is blocked.
  if (channel === 'email') {
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    if (settings.emailEnabled === false) return null;
  }
  const id = randomUUID();
  // A content revision that already exists is normally a duplicate. Two safe
  // exceptions allow re-opening a FAILED job, and both require that no transport
  // ever confirmed an acceptance (provider_id is empty — an acceptance is a fact
  // and must never be re-sent):
  //
  //  - a bundle terminally failed because its findings were temporarily
  //    inapplicable: the pipeline only calls queueAdvisory again after
  //    revalidating the current inventory;
  //  - a consolidated notification batch (FINDINGS:/NEWS:) whose delivery failed
  //    terminally. The per-recipient claims are released by the finalize path
  //    exactly when the failure is provably non-delivery, so a later run
  //    re-claims the items and must be able to queue a replacement email.
  //    Without this the dedupe key blocked the replacement forever and the
  //    notification was lost (audit follow-up, Finding 2). The original failure
  //    stays in the audit/events trail; uncertain transport outcomes (provider
  //    lookup inconclusive, prior attempt possibly accepted) are never re-opened
  //    here — they are held for the confirm-prior-delivery check on retry.
  const inserted = await db.query(
    `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,priority,edits,delivery_outcome)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,'NOT_ATTEMPTED')
     ON CONFLICT(dedupe_key) DO UPDATE SET
       advisory_id=EXCLUDED.advisory_id,
       payload=EXCLUDED.payload,
       status=EXCLUDED.status,
       priority=EXCLUDED.priority,
       edits=EXCLUDED.edits,
       attempts=0,
       next_attempt=now(),
       error=NULL,
       provider_id=NULL,
       locked_at=NULL,
       lock_token=NULL,
       -- AUD-007: the reopen decision is the recorded delivery outcome, never
       -- error-message text. A job whose transport provably rejected the message
       -- (or never attempted one) may be re-opened; an UNKNOWN outcome means a
       -- prior attempt may have been accepted and stays blocked pending the
       -- confirm-prior-delivery check; ACCEPTED is a fact and is never re-sent.
       delivery_outcome=EXCLUDED.delivery_outcome,
       updated_at=now()
     WHERE outbox.status='FAILED'
       AND outbox.delivery_outcome IN ('NOT_ATTEMPTED','REJECTED')
       AND (
         COALESCE(outbox.error,'') LIKE '%no longer applicable%'
         OR (outbox.advisory_id LIKE 'UNVERIFIABLE:%' AND COALESCE(outbox.error,'') LIKE 'Review notification%')
         OR outbox.advisory_id LIKE 'FINDINGS:%'
         OR outbox.advisory_id LIKE 'NEWS:%'
       )
     RETURNING id`,
    [
      id,
      dedupe,
      channel,
      targetId,
      advisoryId,
      JSON.stringify(payload),
      channel === 'email' ? initialStatus : 'QUEUED',
      priority,
      JSON.stringify(channel === 'email' ? edits : {}),
    ],
  );
  if (!inserted.rowCount) return null;
  const insertedId = inserted.rows[0].id as string;
  if (channel === 'email') {
    const configuration = (await get<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    await put(db, 'emailLogs', insertedId, {
      id: insertedId,
      recipientEmail: payload.recipientEmail || '',
      advisoryId,
      subject: payload.subject,
      provider: EMAIL_PROVIDER_LABELS[configuration.provider],
      status: initialStatus === 'REVIEW' ? 'REVIEW_REQUIRED' : 'QUEUED',
      attemptCount: 0,
      retrySchedule: emailRetrySchedule(emailRetryPolicy(settings)),
      nextRetryTime: initialStatus === 'REVIEW' ? null : new Date().toISOString(),
      sentAt: '',
    } satisfies EmailDeliveryLog);
  } else {
    const hook = await get<WebhookEndpoint>(db, 'webhooks', targetId);
    await put(db, 'webhookLogs', insertedId, {
      id: insertedId,
      endpointId: targetId,
      endpointName: hook?.name || '',
      provider: hook?.provider || 'GENERIC_HMAC',
      advisoryId,
      cveId: payload.cveIds.join(', '),
      status: 'QUEUED',
      statusCode: 0,
      hmacSignature: '',
      sentAt: '',
    } satisfies WebhookDeliveryLog);
  }
  return insertedId;
}
/**
 * Canonical evidence-map builder for one set of findings (audit L-6).
 *
 * Every enqueue site (queueAdvisory, queueBulkNotificationAdvisory,
 * queueDigestAdvisory, the pipeline's legacy-payload rebuild) used to inline the
 * same two `Object.fromEntries` folds over `findingRevision`/`revision`. Divergence
 * between them would make the dedupe contract depend on which site built the
 * payload. This function is the one definition; callers spread it into their
 * payload. `cveIds`/`findingIds` keys are already unique per construction site.
 */
export function deliveryRevisionEvidence(findings: readonly Finding[]): {
  cveRevisions: Record<string, string>;
  findingRevisions: Record<string, string>;
} {
  return {
    cveRevisions: Object.fromEntries(findings.map((finding) => [finding.cveId, revision(finding.cve)])),
    findingRevisions: Object.fromEntries(findings.map((finding) => [finding.id, findingRevision(finding)])),
  };
}
export async function queueAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  html?: string,
  dispatchKey?: string,
) {
  const recipients = await list<EmailRecipient>(db, 'recipients'),
    hooks = await list<WebhookEndpoint>(db, 'webhooks');
  const selected = recipients.filter(
    (r) => r.enabled && findings.length > 0 && findings.every((finding) => recipientAllows(r, finding)),
  );
  // Deduplicate by content revision, not just advisory ID: a genuinely revised
  // advisory may be delivered again, while a repeated queue pass over the same
  // revision remains idempotent. Pipeline-created advisories get a new random
  // ID on every run, so the default dispatch key must be content-derived; an
  // explicit key (operator resend) still overrides it.
  const contentRevision = advisoryRevision(advisory, findings);
  const payload = {
    ...advisoryEmail(advisory, html, undefined, { findings }),
    cveIds: advisory.cveIds,
    ...deliveryRevisionEvidence(findings),
    contentRevision,
  };
  const stableDispatchKey = dispatchKey ?? contentRevision;
  let count = 0;
  const priority = advisoryPriority(findings);
  // When `deferEveryoneUntilSecurityDelivered` is enabled and at least one
  // Security-team recipient is in the batch, Everyone-group recipients are NOT
  // queued here. They are queued for delivery by the delivery worker once a
  // Security-team delivery for this advisory is confirmed ACCEPTED, so the
  // Security team sees the alert first. Every recipient is queued for delivery:
  // there is no operator review gate on the finding path.
  const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
  const deferEveryone = settings.deferEveryoneUntilSecurityDelivered;
  const hasSecurityRecipients = selected.some((r) => r.deliveryGroup !== 'EVERYONE');
  for (const recipient of selected) {
    if (deferEveryone && hasSecurityRecipients && recipient.deliveryGroup === 'EVERYONE') continue;
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        advisory.id,
        { ...payload, recipientEmail: recipient.email },
        `${stableDispatchKey}:${contentRevision}:email:${recipient.id}`,
        'QUEUED',
        priority,
      )
    )
      count++;
  }
  for (const hook of hooks.filter(
    (h) => h.enabled && findings.length > 0 && findings.every((finding) => webhookAllows(h, finding)),
  ))
    if (
      await enqueue(
        db,
        'webhook',
        hook.id,
        advisory.id,
        payload,
        `${stableDispatchKey}:${contentRevision}:webhook:${hook.id}`,
        'QUEUED',
        priority,
      )
    )
      count++;
  if (!count) return 0;
  advisory.recipientCount = selected.length;
  advisory.deliveryStatus = count ? 'PENDING' : 'DRAFT';
  await put(db, 'advisories', advisory.id, advisory);
  return count;
}
/**
 * After a Security-team delivery is confirmed ACCEPTED by the transport, queue
 * the same email for Everyone-group recipients for immediate delivery. This is
 * the deferred half of the `deferEveryoneUntilSecurityDelivered` setting: the
 * Security team sees the alert first, and once the delivery is confirmed the
 * identical document goes out to the Everyone group.
 *
 * Reuses the accepted job's payload verbatim — apart from the per-recipient
 * address — so every group receives the same email, and the same PDF
 * attachment (rendered from that body). The enqueue dedupe key is
 * content-stable and an existing pending or accepted job for the recipient is
 * skipped, so repeated invocations (one per Security-team recipient) create at
 * most one job set even if several deliveries succeed.
 */
export async function queueEveryoneDeliveryJobs(
  db: Db,
  acceptedJob: Job,
  settings: AppSettings,
): Promise<number> {
  if (!settings.deferEveryoneUntilSecurityDelivered) return 0;
  // Only trigger from a Security-team (or legacy undefined) delivery, never
  // from another Everyone job that was just accepted.
  const securityRecipient = await get<EmailRecipient>(db, 'recipients', acceptedJob.target_id);
  if (!securityRecipient || securityRecipient.deliveryGroup === 'EVERYONE') return 0;
  const advisory = await get<Advisory>(db, 'advisories', acceptedJob.advisory_id);
  if (!advisory) return 0;
  // Reuse the accepted delivery's payload verbatim, stripping only the
  // per-recipient email address so each Everyone job gets its own.
  const { recipientEmail: _omit, ...sharedPayload } = acceptedJob.payload as Job['payload'] & {
    recipientEmail?: string;
  };
  const dispatchKey =
    acceptedJob.payload.digestKey ??
    acceptedJob.dedupe_key.split(':email:')[0].split(':webhook:')[0];
  const contentRevision = sharedPayload.contentRevision ?? acceptedJob.advisory_id;
  // Skip recipients that already have a pending or active job for this content.
  // This guards against duplicates when the setting was toggled on after initial
  // queuing, when the daily-digest path already queued Everyone recipients, and
  // when this function is invoked once per accepted Security-team job.
  //
  // Channel-scoped (audit M-5): a webhook job for the same advisory shares
  // nothing with an email recipient. `ACCEPTED` is included deliberately — an
  // operator resend of the same advisory must not re-queue the broadcast.
  const pending = await db.query<{ target_id: string }>(
    "SELECT target_id FROM outbox WHERE advisory_id=$1 AND channel='email' AND status IN ('REVIEW','QUEUED','SENDING','ACCEPTED')",
    [acceptedJob.advisory_id],
  );
  const activeTargets = new Set(pending.rows.map((row) => row.target_id));
  const everyoneRecipients = (await list<EmailRecipient>(db, 'recipients')).filter(
    (r) => r.enabled && r.deliveryGroup === 'EVERYONE',
  );
  if (!everyoneRecipients.length) return 0;
  let queued = 0;
  const priority = acceptedJob.priority ?? 0;
  for (const recipient of everyoneRecipients) {
    if (activeTargets.has(recipient.id)) continue;
    // The recipient must still be subscribed to every finding in the accepted
    // bundle; the consolidated document is delivered as-is.
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        acceptedJob.advisory_id,
        { ...sharedPayload, recipientEmail: recipient.email },
        `${dispatchKey}:everyone:${contentRevision}:email:${recipient.id}`,
        'QUEUED',
        priority,
      )
    )
      queued++;
  }
  if (queued) {
    await writeEvent(db, {
      category: 'EMAIL',
      level: 'INFO',
      code: 'delivery.everyone_queued_after_security',
      message: `Queued ${queued} Everyone-group delivery job(s) for advisory ${acceptedJob.advisory_id} after Security-team delivery was confirmed`,
      context: {
        advisoryId: acceptedJob.advisory_id,
        securityJobId: acceptedJob.id,
        everyoneJobsQueued: queued,
      },
    });
    await appendAudit(
      db,
      'Everyone delivery jobs queued',
      `${acceptedJob.advisory_id}: ${queued} job(s) after security delivery acceptance`,
      'delivery-worker',
      'EMAIL',
      'INFO',
    );
  }
  return queued;
}
export interface BulkNotificationOptions {
  /**
   * Operator-supplied subject override. The queued delivery subject (and the
   * log shown in the Action Center) must match what the recipient receives.
   */
  subject?: string;
  /** Review edits persisted with every new job and applied at send time. */
  edits?: ReviewEdits;
}

export async function queueBulkNotificationAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  html: string,
  recipients: EmailRecipient[],
  dispatchKey?: string,
  options: BulkNotificationOptions = {},
): Promise<number> {
  if (findings.length === 0) return 0;
  const contentRevision = advisoryRevision(advisory, findings);
  const baseEmail = advisoryEmail(advisory, html, undefined, { findings });
  const payload = {
    ...baseEmail,
    subject: normalizeEmailSubject(options.subject) ?? baseEmail.subject,
    cveIds: advisory.cveIds,
    ...deliveryRevisionEvidence(findings),
    contentRevision,
  };
  const stableDispatchKey = dispatchKey ?? contentRevision;
  const priority = advisoryPriority(findings);
  const edits = options.edits ?? {};
  let count = 0;
  for (const recipient of recipients)
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        advisory.id,
        { ...payload, recipientEmail: recipient.email },
        `${stableDispatchKey}:${contentRevision}:email:${recipient.id}`,
        'QUEUED',
        priority,
        edits,
      )
    )
      count++;
  if (!count) return 0;
  advisory.recipientCount = recipients.length;
  advisory.deliveryStatus = 'PENDING';
  await put(db, 'advisories', advisory.id, advisory);
  return count;
}
// News evidence is queued through `server/newsQueue.ts` (`queueConsolidatedNews`).
// The previous per-match email produced one message per `IntelligenceMatch`,
// which meant the same article was emailed again whenever the matcher re-keyed
// it (it keys matches on `hash(cveId || articleId)`), arrived from another feed,
// or was re-correlated after a CVE was assigned. News is now consolidated into
// one email per recipient per run, and an article already sent to a recipient is
// never sent again.

export interface ConsolidatedFindingsDispatchOptions {
  /** Recipients to notify; defaults to every enabled recipient. */
  recipients?: EmailRecipient[];
  /**
   * Compiled advisory template to render with. Defaults to the operator's saved
   * template, so the delivered email matches the editor preview.
   */
  template?: string;
  /** Set only for Everyone recipients after Security-team acceptance. */
  afterSecurityAcceptance?: boolean;
}

/**
 * Deterministic identity of a consolidated finding batch.
 *
 * Derived from the finding ids, so the same set of findings always maps to the
 * same advisory id, dedupe bucket and document. That is what makes a repeated
 * queue pass idempotent and lets a queued batch be recognised after a restart.
 */
export function consolidatedFindingBatchId(findingIds: readonly string[]): string {
  return createHash('sha256').update([...findingIds].sort().join(',')).digest('hex').slice(0, 24);
}

/**
 * Builds the advisory view and the single document for a consolidated finding
 * batch.
 *
 * Used both when the batch is queued and when a queued batch has to be rebuilt
 * because some of its findings became stale, so the two paths can never produce
 * differently-shaped content.
 */
export function consolidatedFindingsDocument(
  findings: Finding[],
  generatedAt: Date,
  /** Compiled operator template (see `resolveAdvisoryTemplate`); default layout when omitted. */
  template?: string,
): { advisory: Advisory; document: { subject: string; text: string; html: string } } {
  const batchId = consolidatedFindingBatchId(findings.map((finding) => finding.id));
  const advisory: Advisory = {
    id: `ADV-${batchId.slice(0, 12).toUpperCase()}`,
    title: 'Security finding notification',
    severity: highestSeverity(findings),
    cveIds: uniqueSorted(findings.map((finding) => finding.cveId)),
    findingIds: findings.map((finding) => finding.id),
    createdDate: generatedAt.toISOString(),
    deliveryStatus: 'PENDING',
    recipientCount: 0,
    executiveSummary: `${findings.length} inventory correlation${findings.length === 1 ? '' : 's'} require investigation. Confirm applicability and consult the vendor before remediation.`,
    remediationInstructions:
      'Review vendor advisories and deploy tested remediation through your change process.',
    vendorLink: vendorLinkFor(findings),
    affectedSystems: uniqueSorted(findings.map((finding) => finding.matchedAssetName)),
    isDigestBatch: findings.length > 1,
  };
  const document = renderFindingsDocument({ advisory, findings, generatedAt, template });
  return { advisory, document: { subject: document.subject, text: document.text, html: document.html } };
}

/** Loads the operator's saved template, compiled; the same one the editor previews. */
async function loadAdvisoryTemplate(db: Db): Promise<string> {
  return resolveAdvisoryTemplate(await get<SavedTemplateRecord>(db, 'template', 'main'));
}

/** Rebuilds a queued consolidated batch's payload from its surviving findings. */
function consolidatedPayloadFor(
  advisory: Advisory,
  findings: Finding[],
  cveIds: string[],
  template?: string,
): Job['payload'] {
  const generatedAt = new Date();
  const { document } = consolidatedFindingsDocument(findings, generatedAt, template);
  const evidence = deliveryRevisionEvidence(findings);
  return {
    ...document,
    cveIds,
    includedFindingIds: findings.map((finding) => finding.id),
    ...evidence,
    contentRevision: createHash('sha256')
      .update(stableJson({ findingIds: findings.map((finding) => finding.id).sort(), ...evidence }))
      .digest('hex')
      .slice(0, 20),
    generatedAt: generatedAt.toISOString(),
    digestKey: advisory.id,
  };
}

/**
 * Queues ONE consolidated finding email per eligible recipient for a set of
 * findings — including findings the matching policy could not fully confirm.
 *
 * This replaces the former "review bulletin": there is no operator review
 * queue. A finding held by the confidence or applicability policy is dispatched
 * like any other, and the rendered advisory states the limitation and its
 * reason on the finding itself (see `advisoryRender`).
 *
 * Consolidation guarantees:
 *  - one email per recipient, whatever the number of findings in the batch;
 *  - a finding is announced at most once PER RECIPIENT: deduplication is the
 *    durable `(recipient_id, finding_id)` claim in `delivery_claims`, not the
 *    finding's global `reviewNotifiedAt` (AUD-001). A recipient added after
 *    another recipient was already told about a finding still receives it;
 *  - the claim and the outbox job are written in one transaction, so two
 *    concurrent runs cannot both queue the same finding for the same recipient
 *    (AUD-002);
 *  - the body and the PDF attachment are built from the same document
 *    (`renderFindingsDocument`).
 */
/**
 * True when `db` is a pool (no transaction open) rather than a checked-out
 * client. `transaction()` must only be opened on a pool: a client is already
 * inside one, and reusing it would fail with "Client has already been
 * connected".
 */
const isPool = (db: Db): db is pg.Pool =>
  typeof (db as pg.Pool).connect === 'function' &&
  typeof (db as unknown as { release?: unknown }).release !== 'function';

export async function queueConsolidatedFindingNotifications(
  db: Db,
  findings: Finding[],
  options: ConsolidatedFindingsDispatchOptions = {},
): Promise<number> {
  // `reviewNotifiedAt` is deliberately NOT a filter here. It is a global stamp
  // written when any recipient's email is accepted, so using it to exclude
  // findings silently dropped them for every recipient who had not been told
  // yet. It is retained for aggregate reporting and for builds that predate
  // `delivery_claims`; the per-recipient claim below is the deduplication key.
  const unique = [...new Map(findings.filter((finding) => finding?.id).map((finding) => [finding.id, finding])).values()]
    .filter((finding) => !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status))
    .sort((left, right) => left.cveId.localeCompare(right.cveId) || left.id.localeCompare(right.id));
  if (!unique.length) return 0;
  // Keep all record aliases for historical receipt lookup, even disabled ones.
  const configuredRecipients = await list<EmailRecipient>(db, 'recipients');
  const recipients = uniqueEnabledEmailRecipients(options.recipients ?? configuredRecipients);
  if (!recipients.length) return 0;
  const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
  const securityRecipients = recipients.filter((recipient) => recipient.deliveryGroup !== 'EVERYONE');
  // Defer only the individual findings that Security can actually receive.
  // Otherwise an Everyone-only severity can get stranded forever.
  const deferForFinding = (finding: Finding): boolean =>
    Boolean(settings.deferEveryoneUntilSecurityDelivered) &&
    !options.afterSecurityAcceptance &&
    securityRecipients.some((recipient) => recipientAllows(recipient, finding));
  const deliveryRecipients = recipients;
  // Read side of the claim: skip items this recipient already has. The write
  // side (`claimItems`) is what actually enforces uniqueness under concurrency.
  const alreadyClaimed = await activeClaims(
    db,
    configuredRecipients.map((recipient) => recipient.id),
    'finding',
    unique.map((finding) => finding.id),
  );
  let queued = 0;
  const generatedAt = new Date();
  // Resolved once per pass: every recipient's document is rendered from the same
  // template, and the template is never read per recipient.
  const template = options.template ?? (await loadAdvisoryTemplate(db));
  const documentCache = new Map<string, { payload: Job['payload']; priority: number }>();
  for (const recipient of deliveryRecipients) {
    const aliases = configuredRecipients.filter((candidate) =>
      candidate.email.trim().toLowerCase() === recipient.email.trim().toLowerCase());
    const claimedIds = new Set(aliases.flatMap((candidate) => [...(alreadyClaimed.get(candidate.id) ?? [])]));
    const permitted = unique.filter((finding) =>
      recipientAllows(recipient, finding) && !claimedIds.has(finding.id) &&
      (recipient.deliveryGroup !== 'EVERYONE' || !deferForFinding(finding)));
    if (!permitted.length) continue;
    const findingIds = permitted.map((finding) => finding.id);
    const bucket = consolidatedFindingBatchId(findingIds);
    let built = documentCache.get(bucket);
    if (!built) {
      const { advisory, document } = consolidatedFindingsDocument(permitted, generatedAt, template);
      const evidence = deliveryRevisionEvidence(permitted);
      built = {
        payload: {
          ...document,
          cveIds: advisory.cveIds,
          includedFindingIds: findingIds,
          ...evidence,
          contentRevision: createHash('sha256')
            .update(stableJson({ findingIds: [...findingIds].sort(), ...evidence }))
            .digest('hex')
            .slice(0, 20),
          generatedAt: generatedAt.toISOString(),
          digestKey: advisory.id,
        },
        priority: advisoryPriority(permitted),
      };
      documentCache.set(bucket, built);
    }
    // Claim and enqueue atomically. A concurrent run that claimed any of these
    // findings first makes this transaction roll back, so the loser queues
    // nothing and the winner's message is the only one that carries them.
    //
    // A denied claim never blocks the granted ones (audit follow-up, Finding 3):
    // the message is built from the claims this run actually won, so unrelated
    // new findings are still delivered instead of being suppressed alongside the
    // contested one. The claims of a denied item are never taken, so there is
    // nothing to roll back for it.
    const enqueueWithClaim = async (tx: Db) => {
      const claim = await claimItems(tx, claimsForJob(recipient.id, 'finding', findingIds));
      if (!claim.granted.length) return null;
      const granted = new Set(claim.granted.map((request) => request.itemId));
      const owned = permitted.filter((finding) => granted.has(finding.id));
      const ownedIds = owned.map((finding) => finding.id);
      const ownedBucket = consolidatedFindingBatchId(ownedIds);
      const ownedCache = documentCache.get(ownedBucket);
      const ownedDocument = ownedCache ?? (() => {
        const { advisory, document } = consolidatedFindingsDocument(owned, generatedAt);
        const evidence = deliveryRevisionEvidence(owned);
        const builtPayload = {
          payload: {
            ...document,
            cveIds: advisory.cveIds,
            includedFindingIds: ownedIds,
            ...evidence,
            contentRevision: createHash('sha256')
              .update(stableJson({ findingIds: [...ownedIds].sort(), ...evidence }))
              .digest('hex')
              .slice(0, 20),
            generatedAt: generatedAt.toISOString(),
            digestKey: advisory.id,
          },
          priority: advisoryPriority(owned),
        } as { payload: Job['payload']; priority: number };
        documentCache.set(ownedBucket, builtPayload);
        return builtPayload;
      })();
      const id = await enqueue(
        tx,
        'email',
        recipient.id,
        `FINDINGS:${ownedBucket}`,
        { ...ownedDocument.payload, recipientEmail: recipient.email },
        `findings:${ownedDocument.payload.contentRevision}:email:${recipient.id}`,
        'QUEUED',
        ownedDocument.priority,
      );
      if (!id) {
        await reconcileDuplicateOutboxClaims(
          tx,
          `findings:${ownedDocument.payload.contentRevision}:email:${recipient.id}`,
          claim.granted,
        );
        return null;
      }
      await attachClaimsToJob(tx, id, claimsForJob(recipient.id, 'finding', ownedIds));
      return id;
    };
    // The caller may already be inside a transaction (the pipeline runs the
    // whole queue pass in one); only open a new one when `db` is a pool.
    const jobId = isPool(db) ? await transaction(db, enqueueWithClaim) : await enqueueWithClaim(db);
    if (jobId) queued++;
  }
  if (queued)
    await writeEvent(db, {
      category: 'EMAIL',
      level: 'INFO',
      code: 'delivery.findings_consolidated',
      message: 'Consolidated finding email queued for eligible recipients',
      context: { findings: unique.length, recipientsNotified: queued },
    });
  return queued;
}

/**
 * Queues one consolidated email per Security-team recipient for a zero-day
 * digest produced by `rankAndRateLimitZeroDays`.
 *
 * Audit C-3: the per-run zero-day cap removed the suppressed matches *and* their
 * counterpart findings from the notification path. Nothing replaced them, so
 * exceeding the cap turned a notification storm into silence. The digest is now
 * delivered as a single summary, keeping the cap's cost bound (one email per
 * recipient per digest) while the operator still learns the evidence exists.
 *
 * Idempotent per recipient per content revision, exactly like the news path: the
 * same digest re-derived on a later run produces the same dedupe key.
 */
export async function queueZeroDayDigestNotification(
  db: Db,
  digest: ZeroDayDigestPayload,
  recipients: EmailRecipient[],
): Promise<number> {
  const selected = recipients.filter(
    (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
  );
  if (!selected.length || !digest.findings.length) return 0;
  const safeLine = (value: string) =>
    value.replace(/[\r\n\t]+/g, ' ').replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '').trim();
  const productLabel = `${digest.vendor} / ${digest.product}`;
  const subject = safeLine(
    `[Threat intelligence] [ZERO-DAY DIGEST] ${productLabel} (${digest.matchCount} matches)`,
  );
  const lines = digest.findings.map((finding, index) =>
    [
      `${index + 1}. Asset: ${safeLine(finding.assetName)}`,
      finding.cveId ? `   CVE: ${safeLine(finding.cveId)}` : '   CVE: (none assigned - potential zero-day)',
      `   Evidence: ${safeLine(finding.evidence)}`,
      typeof finding.credibilityScore === 'number'
        ? `   Credibility: ${finding.credibilityScore}/100`
        : '',
    ]
      .filter(Boolean)
      .join('\n'),
  );
  const sources = digest.articles.length
    ? `\n\nSources:\n${digest.articles.map((article) => `- ${safeLine(article.title)}\n  ${safeLine(article.url)}`).join('\n')}`
    : '';
  const text =
    `Zero-day digest for ${safeLine(productLabel)}\n\n` +
    `${digest.matchCount} potential zero-day match(es) were consolidated into this digest ` +
    `because the per-run notification cap was reached. Each item below was withheld from ` +
    `individual delivery and requires manual triage.\n\n` +
    `${lines.join('\n\n')}${sources}\n\n` +
    'This is applicability evidence, not a confirmed advisory. Confirm source authenticity and consult the vendor before remediation.';
  const articleIds = digest.articles.map((article) => article.id).sort();
  // Two digests with no articles can still describe entirely different
  // findings. Include the canonical source URL identities AND stable finding
  // evidence instead of using a shared "no-articles" dedupe key.
  const articleIdentities = [...new Set(digest.articles.map(newsArticleIdentity))].sort();
  const findingIdentities = [...new Set(digest.findings.map((finding) =>
    finding.findingId ? `finding:${finding.findingId}` :
      `evidence:${finding.cveId || ''}:${finding.assetName}:${finding.evidence}`,
  ))].sort();
  const contentRevision = createHash('sha256')
    .update(stableJson({ articleIdentities, findingIdentities })).digest('hex').slice(0, 24);
  const identity = `zeroday:${digest.digestId}:${contentRevision}`;
  const payload: ZeroDayDigestPayload = {
    ...digest,
    articles: digest.articles.map((article) => ({ ...article, sourceFeeds: [...article.sourceFeeds] })),
  };
  let queued = 0;
  for (const recipient of selected) {
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        `ZERODAY:${digest.digestId}`,
        {
          subject,
          text,
          cveIds: [...new Set(digest.findings.map((finding) => finding.cveId).filter(Boolean))].sort() as string[],
          zeroDayDigest: payload,
          contentRevision,
          recipientEmail: recipient.email,
        },
        `${identity}:email:${recipient.id}`,
        'QUEUED',
      )
    )
      queued++;
  }
  return queued;
}

/**
 * Optional HTML override for a recipient's digest view.
 *
 * The override only replaces the *body*; the subject, plain text, version and
 * attachment filename still come from the canonical document builder. Attaching
 * the override's HTML verbatim is what keeps "the attachment is the email"
 * true even when an operator template produced the body.
 */
export type DigestRender = (
  advisory: Advisory,
  findings: Finding[],
) => string | undefined;

const MAX_PLAIN_TEXT_BYTES = 2 * 1024 * 1024;

/**
 * Builds the one document delivered for a digest view.
 *
 * Ordering is deterministic (severity, then CVE, then asset) so the same batch
 * always renders the same document — including on retries, where the pinned
 * instant guarantees byte-identical attachment input.
 */
function digestDocument(
  view: Advisory,
  findings: Finding[],
  render: DigestRender | undefined,
  generatedAt: Date,
): { subject: string; text: string; html?: string; generatedAt: string } {
  const ordered = digestOrdered(view, findings);
  const base = renderFindingsDocument({ advisory: view, findings: ordered, generatedAt });
  const override = render?.(view, ordered);
  const html = override ?? base.html;
  return {
    subject: base.subject || view.title,
    // The text alternative always describes the same findings as the HTML. It is
    // bounded so a very large batch cannot produce an oversized message part.
    text: renderFindingsText(view, ordered).slice(0, MAX_PLAIN_TEXT_BYTES) || base.text,
    html,
    generatedAt: generatedAt.toISOString(),
  };
}

/** Deterministic presentation order for a digest document. */
function digestOrdered(view: Advisory, findings: Finding[]): Finding[] {
  const rank = (severity: string) => SEVERITY_ORDER.indexOf(severity as (typeof SEVERITY_ORDER)[number]);
  return [...findings].sort((left, right) => {
    const bySeverity = rank(right.cve.cvss.severity) - rank(left.cve.cvss.severity);
    if (bySeverity) return bySeverity;
    const byCve = left.cveId.localeCompare(right.cveId);
    if (byCve) return byCve;
    const byAsset = left.matchedAssetName.localeCompare(right.matchedAssetName);
    return byAsset || left.id.localeCompare(right.id);
  }).map((finding) => finding);
}

export interface DigestQueueResult {
  /** Persisted union advisory, or the supplied advisory when nothing was queued. */
  advisory: Advisory;
  /** Number of transport jobs created (email + webhook). */
  jobs: number;
  /** Findings that were included in at least one job. */
  findingIds: string[];
  /** Number of targets that could receive at least one finding. */
  eligible: number;
}

/**
 * Queues one combined email per recipient (and one webhook per endpoint) for a
 * batch of findings.
 *
 * The union advisory is persisted for queue accounting and UI visibility, while
 * each transport receives a recipient-specific view containing only the findings
 * its subscription tier permits. This is what makes a single digest safe for a
 * mixed set of ALL_SEVERITIES, CRITICAL_HIGH_ONLY and CISA_KEV_ONLY subscribers.
 *
 * Deduplication is content-derived and per target. Re-running the same batch is
 * idempotent, and the stable Message-ID in `createMailSender` lets the receiving
 * provider collapse a retry that raced a process crash.
 */
export async function queueDigestAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  render?: DigestRender,
  dispatchKey?: string,
): Promise<DigestQueueResult> {
  const recipients = uniqueEnabledEmailRecipients(await list<EmailRecipient>(db, 'recipients'));
  const hooks = (await list<WebhookEndpoint>(db, 'webhooks')).filter((hook) => hook.enabled);

  const recipientBatches = new Map<string, Finding[]>();
  for (const recipient of recipients) {
    const permitted = findings.filter((finding) => recipientAllows(recipient, finding));
    if (permitted.length) recipientBatches.set(recipient.id, permitted);
  }
  const webhookBatches = new Map<string, Finding[]>();
  for (const hook of hooks) {
    const permitted = findings.filter((finding) => webhookAllows(hook, finding));
    if (permitted.length) webhookBatches.set(hook.id, permitted);
  }

  const includedIds = new Set<string>();
  for (const batch of [...recipientBatches.values(), ...webhookBatches.values()])
    for (const finding of batch) includedIds.add(finding.id);
  const included = findings.filter((finding) => includedIds.has(finding.id));
  if (!included.length) return { advisory, jobs: 0, findingIds: [], eligible: 0 };

  const union = digestView(advisory, included);
  const contentRevision = advisoryRevision(union, included);
  const stableDispatchKey = dispatchKey ?? contentRevision;
  const priority = advisoryPriority(included);
  let jobs = 0;
  let recipientCount = 0;
  // One render instant for the whole batch: the body, its plain-text companion
  // and the PDF attachment of every recipient describe the same document.
  const generatedAt = new Date();

  for (const [recipientId, batch] of recipientBatches) {
    const recipient = recipients.find((candidate) => candidate.id === recipientId)!;
    // Legacy buffered digests use the SAME recipient/finding claims as current
    // consolidated findings. Without this, both paths can email the same CVE.
    const enqueueOwned = async (tx: Db): Promise<boolean> => {
      const requested = claimsForJob(recipient.id, 'finding', batch.map((f) => f.id));
      const claimed = await claimItems(tx, requested);
      if (!claimed.granted.length) return false;
      const ids = new Set(claimed.granted.map((request) => request.itemId));
      const owned = batch.filter((finding) => ids.has(finding.id));
      const view = digestView(union, owned);
      const document = digestDocument(view, owned, render, generatedAt);
      const revision = advisoryRevision(view, owned);
      const key = `${stableDispatchKey}:${revision}:email:${recipient.id}`;
      const payload = {
        ...document,
        cveIds: view.cveIds,
        includedFindingIds: owned.map((finding) => finding.id),
        ...deliveryRevisionEvidence(owned),
        digestKey: stableDispatchKey,
        contentRevision: revision,
        recipientEmail: recipient.email,
      };
      const id = await enqueue(tx, 'email', recipient.id, union.id, payload, key, 'QUEUED', priority);
      if (!id) {
        await reconcileDuplicateOutboxClaims(tx, key, claimed.granted);
        return false;
      }
      await attachClaimsToJob(tx, id, claimed.granted);
      return true;
    };
    const scheduled = isPool(db) ? await transaction(db, enqueueOwned) : await enqueueOwned(db);
    if (scheduled) {
      jobs++;
      recipientCount++;
    }
  }

  for (const [hookId, batch] of webhookBatches) {
    const view = digestView(union, batch);
    const payload = {
      ...digestDocument(view, batch, render, generatedAt),
      cveIds: view.cveIds,
      includedFindingIds: batch.map((finding) => finding.id),
      ...deliveryRevisionEvidence(batch),
      digestKey: stableDispatchKey,
      contentRevision,
    };
    if (
      await enqueue(
        db,
        'webhook',
        hookId,
        union.id,
        payload,
        `${stableDispatchKey}:${contentRevision}:webhook:${hookId}`,
        'QUEUED',
        priority,
      )
    )
      jobs++;
  }

  if (!jobs)
    return {
      advisory: union,
      jobs: 0,
      // These findings were already accepted by an identical queued batch.
      // Callers use this to discard them from their local buffer.
      findingIds: included.map((finding) => finding.id),
      eligible: recipientBatches.size + webhookBatches.size,
    };

  union.recipientCount = recipientCount;
  union.deliveryStatus = 'PENDING';
  await put(db, 'advisories', union.id, union);
  return {
    advisory: union,
    jobs,
    findingIds: included.map((finding) => finding.id),
    eligible: recipientBatches.size + webhookBatches.size,
  };
}

export async function deliverNext(
  pool: pg.Pool,
  config: Config,
  request: Requester,
  sendMail: MailSender,
): Promise<boolean> {
  const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
  const job = await transaction(pool, async (db) => {
    const claimed = await db.query(
      `WITH candidate AS (
         SELECT id,
           CASE WHEN channel='email' AND attempts > 0 THEN
             (SELECT occurred_at FROM operational_events
              WHERE code='ml.delivery.outcome' AND context->>'jobId'=outbox.id::text
              ORDER BY id DESC LIMIT 1)
           END AS prior_attempt_at
         FROM outbox
         WHERE ((status='QUEUED' AND next_attempt<=now()) OR
           (status='SENDING' AND locked_at<now()-interval '2 minutes'))
           AND (channel<>'email' OR $2::boolean)
         ORDER BY priority DESC, next_attempt
         FOR UPDATE SKIP LOCKED LIMIT 1
       )
       UPDATE outbox AS o
       SET status='SENDING',locked_at=now(),lock_token=$1,attempts=attempts+1,updated_at=now()
       FROM candidate AS c WHERE o.id=c.id
       RETURNING o.*,c.prior_attempt_at`,
      [randomUUID(), settings.emailEnabled !== false],
    );
    return claimed.rows[0] as Job | undefined;
  });
  if (!job) return false;
  const attemptStartedAt = Date.now();
  const observedDelay = job.channel === 'email' && job.attempts > 1
    ? observedRetryDelay(job.prior_attempt_at, attemptStartedAt)
    : { delayMs: 0, observed: false };
  const retryDelayObserved = observedDelay.delayMs;
  let transportAttempted = false;
  // A previous ambiguous attempt must be resolved BEFORE any later transport
  // rejection can establish that the whole job is safe to requeue.
  let previousAttemptConfirmedNotDelivered = job.attempts === 1;
  // Declared before the try block: the failure path releases the per-recipient
  // claims of a consolidated finding batch, and that needs the job's findings.
  let declaredFindingIds: string[] = [];
  // Email retries follow the operator policy; webhooks retain the historical
  // six-attempt policy because their budget is not exposed as an email setting.
  const retryPolicy = emailRetryPolicy(job.channel === 'email' ? settings : DEFAULT_SETTINGS);
  // Master switch: when email delivery is disabled, no outbound email is
  // generated or sent. Provider configuration is left intact; only transport
  // is blocked. Fail closed so a disabled setting can never leak an email.
  let permanent = false;
  let providerId = '',
    statusCode = 0,
    signature = '',
    error = '',
    retryNotBefore = 0;
  // Structured transport failure for the event log; `error` stays the short
  // message used by retry policy and the outbox row.
  let errorInfo: Record<string, unknown> = {};
  let emailProvider: EmailDeliveryLog['provider'] | undefined;
  // Declared outside the try block: it is assigned inside and read again by the
  // post-delivery bookkeeping below. A block-scoped `const` made that read a
  // compile error and, under a non-strict loader, a ReferenceError *after* the
  // mail/webhook had already been sent — the outbox row would then never be
  // marked ACCEPTED and the alert would be re-sent on every retry.
  let declaredCveIds: string[] = [];
  // Set when the revalidation detects a stale advisory bundle so the catch
  // block can trigger an immediate rebuild instead of a hard permanent failure.
  let staleAdvisory = false;
  // Set when a legacy payload was rebuilt from current intelligence during this
  // attempt, so the recovery path does not rebuild the same payload twice.
  let legacyRebuilt = false;
  // Set when the bundle is blocked by a finding whose *confidence policy* still
  // holds it rather than one whose applicability changed. Retained for the
  // rebuild decision below (a policy hold can never be resolved by rebuilding),
  // but it no longer diverts the job to a review queue — findings are dispatched
  // and the email states the limitation.
  let holdGated = false;
  // Set when the transport returned 2xx but the attempt could not be marked
  // ACCEPTED because the response was rejected (confirm-before-send). This only
  // happens for email; a webhook response needs no confirmation.
  let unconfirmedError = '';
  // Structured classification of the last transport failure (audit M-6): true
  // when the provider provably rejected the message. Persisted on the delivery
  // log so confirmPriorDelivery does not have to re-infer it from error text.
  let transportRejected = false;
  try {
    if (!retryPolicy.enabled && job.attempts > 1 && job.channel === 'email') {
      permanent = true;
      throw new Error('Automatic email retry is disabled by the current settings');
    }
    // Approval resets the attempt count. The transport budget still applies
    // after approval, including recovery of an abandoned sending lease.
    if (job.attempts > retryPolicy.maxAttempts) {
      permanent = true;
      throw new Error('Delivery retry budget exhausted after worker recovery');
    }
    let native: NativeDelivery | undefined;
    if (job.payload.nativeCorrelation) {
      try {
        native = await validateNativeDelivery(pool, job);
      } catch {
        // Native validation is deterministic: a payload that fails once (policy
        // off, evidence hash mismatch, confidence demoted) fails on every retry.
        permanent = true;
        throw new Error('Native evidence or notification policy is no longer applicable');
      }
      // Native evidence is delivered regardless of confidence. The rendered
      // advisory states the limitation on each affected finding, so suppressing
      // the email only hid real exposure from the security team.
    }
    const advisory = await get<Advisory>(pool, 'advisories', job.advisory_id);
    const currentFindings: Finding[] = [];
    // Zero-day digest jobs are standalone summaries: their findings were
    // deliberately withheld from the dispatch path, so there is no advisory and
    // no applicable-finding revalidation to perform.
    //
    // Operational alerts (self-healing watchdog) are the same shape: they are
    // infrastructure messages keyed SELFHEAL:* with no advisory row. Without
    // this exemption they were terminally rejected as "Queued advisory no longer
    // exists" and the Security team never received a degradation alert.
    const isOperationalAlert =
      typeof job.advisory_id === 'string' && job.advisory_id.startsWith('SELFHEAL:');
    // A consolidated finding batch is a standalone document built from the
    // findings it carries; it has no advisory row by design.
    const isConsolidatedFindings =
      typeof job.advisory_id === 'string' && job.advisory_id.startsWith('FINDINGS:');
    // Its findings are revalidated like an advisory's, but the matched asset
    // lives on the finding record itself: the consolidated queue writes
    // `matchedAssetId`, not a `watchlist` row, so the watchlist lookup below
    // would declare every finding stale ("no longer active") and terminally
    // fail a perfectly deliverable batch. The synthetic view below skips the
    // watchlist join and validates against the stored finding row directly.
    if (
      !advisory &&
      !native &&
      !isOperationalAlert &&
      !isConsolidatedFindings &&
      !job.payload.newsEvidence &&
      !job.payload.unverifiableMatch &&
      !job.payload.zeroDayDigest &&
      job.advisory_id !== 'TEST'
    ) {
      permanent = true;
      throw new Error('Queued advisory no longer exists');
    }
    // A digest job intentionally carries only the subset of the advisory that
    // this target may receive. Legacy and non-digest jobs omit these fields and
    // are validated against the whole advisory exactly as before.
    declaredCveIds = job.payload.cveIds ?? advisory?.cveIds ?? [];
    declaredFindingIds = job.payload.includedFindingIds ?? advisory?.findingIds ?? [];
    if (advisory && declaredCveIds.some((id) => !job.payload.cveRevisions?.[id])) {
      // Jobs queued before content-revision evidence existed cannot be validated
      // against the advisory they describe. Rebuild the payload from the
      // current CVE cache first; revalidation below then decides whether it is
      // still deliverable. If the rebuild cannot produce evidence for every
      // declared CVE (e.g. the CVE was removed from the cache), the bundle is
      // stale and recovery rebuilds it from the current inventory instead.
      const { rebuildLegacyDeliveryPayload } = await import('./pipeline');
      if (await rebuildLegacyDeliveryPayload(pool, job)) {
        legacyRebuilt = true;
        declaredCveIds = job.payload.cveIds ?? advisory.cveIds;
      }
      if (declaredCveIds.some((id) => !job.payload.cveRevisions?.[id])) {
        permanent = true;
        staleAdvisory = true;
        throw new Error(
          'Advisory revision is no longer applicable; rebuild legacy queued payload from current intelligence',
        );
      }
    }
    if (advisory && !declaredFindingIds.length && !job.payload.digestKey) {
      // Nothing in this bundle can still be delivered; recover through the same
      // current-inventory rebuild path instead of a bare operator-facing error.
      // A bundle keyed as a digest carries its own content revision per CVE, so
      // it is validated below like any other payload even when it references no
      // findings (a consolidated digest view can legitimately be a summary).
      permanent = true;
      staleAdvisory = true;
      throw new Error('Advisory has no findings; rebuild from current inventory before delivery');
    }
    // A consolidated finding batch has no advisory row, but its findings must
    // be revalidated exactly like an advisory's: a finding resolved after
    // queueing must not be delivered. The synthetic advisory view is built from
    // the payload's own finding ids so the rebuild path below applies unchanged.
    const revalidationView: Advisory | undefined =
      advisory ??
      (isConsolidatedFindings && declaredFindingIds.length
        ? {
            id: job.advisory_id,
            title: job.payload.subject,
            severity: 'UNKNOWN',
            cveIds: declaredCveIds,
            findingIds: declaredFindingIds,
            createdDate: job.payload.generatedAt ?? new Date().toISOString(),
            deliveryStatus: 'PENDING',
            recipientCount: 0,
            executiveSummary: '',
            remediationInstructions: '',
            vendorLink: '',
            affectedSystems: [],
            isDigestBatch: declaredFindingIds.length > 1,
          }
        : undefined);
    if (revalidationView) {
      // Revalidation must use the same operator-managed aliases as the pipeline
      // that produced the finding; otherwise an alias-matched finding is
      // permanently rejected as "no longer applicable".
      const aliasEntries = await list<AliasEntry>(pool, 'aliases');
      const vendorAliases = buildAliasMap(aliasEntries, 'VENDOR');
      const productAliases = buildAliasMap(aliasEntries, 'PRODUCT');
      const invalid: string[] = [];
      // Findings whose evidence changed or that no longer apply. The document is
      // rebuilt without them rather than delivering a body that disagrees with
      // its own CVE list.
      const staleIds = new Set<string>();
      let revalidationError = '';
      const findingMap = await getMany<Finding>(pool, 'findings', declaredFindingIds);
      const findings = [...findingMap.values()];
      const assetIds = [...new Set(findings.map((f) => f.matchedAssetId))];
      const cveIds = [...new Set(findings.map((f) => f.cveId))];
      // Only inventory that is still active can confirm a finding. A paused,
      // disabled or deleted asset must not let a queued advisory pass the
      // applicability recheck and reach the transport, so inactive rows are
      // dropped here and the finding is reported as no longer matching below.
      const [storedAssets, cveMap, withdrawalMap] = await Promise.all([
        // A consolidated finding batch carries its asset identity on the finding
        // record itself (`matchedAssetId`), not in a `watchlist` row, so the
        // watchlist lookup would report every finding as inactive. For those
        // bundles the finding row IS the inventory evidence and is used directly.
        getMany<WatchListItem>(pool, 'watchlist', assetIds),
        getMany<NormalizedCVE>(pool, 'cveData', cveIds),
        getMany<{ modifiedDate: string }>(pool, 'cveWithdrawals', cveIds),
      ]);
      const assetMap = new Map([...storedAssets].filter(([, asset]) => asset.active !== false));
      if (isConsolidatedFindings)
        for (const finding of findings)
          if (!assetMap.has(finding.matchedAssetId))
            assetMap.set(finding.matchedAssetId, {
              id: finding.matchedAssetId, active: true,
            } as unknown as WatchListItem);
      for (const id of declaredFindingIds) {
        const finding = findingMap.get(id);
        const asset = finding ? assetMap.get(finding.matchedAssetId) : undefined;
        const cachedCve = finding ? cveMap.get(finding.cveId) : undefined;
        const withdrawal = finding ? withdrawalMap.get(finding.cveId) : undefined;
        // Retention may delete the regenerable threat-cache record while a
        // manually reviewed advisory is still queued. The finding embeds the
        // validated CVE snapshot, so fall back to it instead of permanently
        // rejecting an otherwise deliverable bundle.
        const cve = cachedCve || finding?.cve;
        // Revalidation is a safety check, not a reason to lose the job. A corrupt
        // stored asset/CVE row made runVulnerabilityPipeline throw, which skipped
        // the commit below entirely: the outbox row stayed SENDING until the
        // two-minute lease expired, was re-claimed, and hit the same corrupt row
        // for every attempt until the budget was gone. The batch error also
        // rejected the worker tick that had already committed earlier deliveries.
        let match: Finding | undefined;
        let revalidationFailed = false;
        // A consolidated finding batch already embeds the validated CVE snapshot
        // and asset identity, and the synthetic view re-derives it on every
        // attempt: the pipeline run may derive a *different* match object for
        // identical inputs, which would make `findingRevision(match)` disagree
        // with the queued evidence and mark the batch stale. For those bundles
        // the stored finding row IS the validated evidence and is used directly.
        const storedMatches = isConsolidatedFindings
          ? findingMap.get(id)
          : undefined;
        try {
          match =
            storedMatches ??
            (asset && cve
              ? runVulnerabilityPipeline(
                  [],
                  [cve],
                  [asset],
                  [],
                  [],
                  // Fall back to the documented defaults for any setting the stored
                  // object does not carry, so revalidation applies the same policy
                  // the pipeline used instead of an implicit 90% threshold.
                  { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
                  'Server worker',
                  false,
                  vendorAliases,
                  productAliases,
                  undefined,
                  aliasEntries,
                ).newFindings[0]
              : undefined);
        } catch {
          if (!isConsolidatedFindings) revalidationFailed = true;
        }
        // A failed recheck cannot prove the finding is still applicable, so the
        // job is held (never sent) and committed as retryable instead of being
        // mislabelled as a permanent stale-bundle failure.
        if (revalidationFailed) {
          revalidationError = 'Finding applicability could not be re-verified; delivery deferred';
          continue;
        }
        if (match) currentFindings.push(match);
        // A finding the policy still holds for review is disclosed, not withheld.
        // Every match is dispatched; the rendered advisory annotates the finding
        // with its confidence limitation. Only a finding that no longer applies
        // at all (removed, resolved, withdrawn, CVE changed) is dropped.
        if (match && match.notificationStatus !== 'QUEUED_FOR_DISPATCH') holdGated = true;
        const reason = !finding
          ? 'a finding was removed'
          : !asset
            ? 'the matched inventory item is no longer active'
            : ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status)
              ? 'a finding was resolved or dismissed'
              : cve && withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate)
                ? 'a CVE was withdrawn'
                : cve &&
                    job.payload.cveRevisions?.[cve.cveId] &&
                    job.payload.cveRevisions[cve.cveId] !== revision(cve)
                  ? 'CVE intelligence changed'
                  : !match
                    ? 'current inventory no longer matches'
                    : job.payload.findingRevisions?.[id] !== findingRevision(match)
                      ? 'inventory or matching evidence changed'
                      : undefined;
        if (reason) {
          invalid.push(reason);
          staleIds.add(id);
        }
      }
      // A safety-check failure defers the whole bundle: it is retried on the
      // normal backoff and can never reach the transport while unproven.
      if (revalidationError) throw new Error(revalidationError);
      const surviving = currentFindings.filter((finding) => !staleIds.has(finding.id));
      currentFindings.length = 0;
      currentFindings.push(...surviving);
      // A finding is dropped from the delivered document in two situations, both
      // re-rendered from the survivors so the email still describes exactly what
      // it carries:
      //  - the finding is no longer applicable (removed, resolved, withdrawn,
      //    inventory deactivated). This is true for every bundle shape, and
      //    excluding it is what lets the remaining findings still be delivered.
      //  - the evidence was merely re-derived. A consolidated batch is rebuilt
      //    from its survivors; a content-revisioned advisory keeps its existing
      //    rebuild path, because its body cannot be re-hashed here.
      // Enumerated positively: a new or reworded reason must default to the safe
      // whole-bundle rebuild, never to silently editing an advisory body.
      const EVIDENCE_ONLY_REASONS = new Set([
        'inventory or matching evidence changed',
        'CVE intelligence changed',
      ]);
      const evidenceOnly = invalid.every((reason) => EVIDENCE_ONLY_REASONS.has(reason));
      if (invalid.length) {
        if (surviving.length && (revalidationView.id.startsWith('FINDINGS:') || !evidenceOnly)) {
          declaredFindingIds = surviving.map((finding) => finding.id);
          declaredCveIds = [...new Set(surviving.map((finding) => finding.cveId))];
          // Every shape is rebuilt with the canonical document builder so the
          // attachment stays the email. A digest keeps its batch key so the
          // advisory accounting still recognises the delivery. The per-recipient
          // address is preserved: the rebuilt bundle still goes to this target.
          job.payload = {
            ...consolidatedPayloadFor(
              revalidationView,
              surviving,
              declaredCveIds,
              await loadAdvisoryTemplate(pool),
            ),
            ...(job.payload.recipientEmail ? { recipientEmail: job.payload.recipientEmail } : {}),
          };
        } else if (!surviving.length) {
          // Nothing in this bundle can still be delivered.
          permanent = true;
          staleAdvisory = true;
          throw new Error(
            `Some advisory findings are no longer applicable; rebuild from current inventory. Reason: ${[...new Set(invalid)].join('; ')}.`,
          );
        } else {
          // A content-revisioned advisory body cannot be edited: sending it after
          // any finding becomes stale would disclose or act on invalidated
          // inventory. Mark the bundle as stale and rebuild it instead of
          // surfacing a hard error that requires operator intervention.
          permanent = true;
          staleAdvisory = true;
          throw new Error(
            `Some advisory findings are no longer applicable; rebuild from current inventory. Reason: ${[...new Set(invalid)].join('; ')}.`,
          );
        }
      }
    }
    if (job.channel === 'email') {
      if (job.target_id !== 'test') {
        const rec = await get<EmailRecipient>(pool, 'recipients', job.target_id);
        if (!rec?.enabled || rec.email !== job.payload.recipientEmail) {
          permanent = true;
          throw new Error('Recipient removed, changed, or disabled');
        }
        if (native && rec.subscriptionTier !== 'ALL_SEVERITIES') {
          permanent = true;
          throw new Error('Recipient subscription no longer permits unscored intelligence');
        }
        // A consolidated finding batch is validated against the recipient's
        // subscription the same way an advisory is. Its findings are the ones
        // the payload carries, so `currentFindings` must be loaded even though
        // there is no advisory row.
        if (revalidationView && !currentFindings.every((finding) => recipientAllows(rec, finding))) {
          permanent = true;
          throw new Error('Recipient subscription no longer permits all advisory findings');
        }
        // Findings are dispatched to every recipient group that is subscribed;
        // there is no review gate on the delivery path.
      }
      // Confirm before sending. A failed attempt whose outcome is unknown (the
      // send threw after the transport had already accepted the message, or a
      // worker crash left the attempt count advanced) is sent again by a retry.
      // HTML advisory bodies do not carry the delivery id, so this confirmation
      // is the only way to prevent a duplicate alert. The check never blocks a
      // first attempt. On retries it is mandatory: approval authorizes content,
      // not a duplicate send when a prior transport outcome is still unknown.
      if (job.attempts > 1) {
        const confirmation = await confirmPriorDelivery(pool, job, config, request);
        if (confirmation === 'delivered') {
          providerId = 'CONFIRMED_PRIOR_DELIVERY';
          throw Object.assign(new Error('A previous attempt was already accepted by the transport'), {
            confirmedPriorAcceptance: true,
          });
        }
        if (confirmation === 'unknown') {
          // Do not treat the next attempt's rejection as proof about an older
          // ambiguous send. A provider lookup is required before resending.
          throw new Error(
            'Previous delivery outcome could not be confirmed yet; the resend is deferred until it can be',
          );
        }
        previousAttemptConfirmedNotDelivered = confirmation === 'not-delivered';
      }
      // Record the attempt before the transport is contacted. A crash between
      // the provider accepting the message and the commit is then detectable,
      // and the confirmation above resolves it on recovery.
      //
      // The per-recipient claims are attached to this job here, in the same
      // transaction: the claim is only promoted to DELIVERED by the job that
      // actually carries it, so a claim re-taken by a later run after expiry is
      // never overwritten by a stale delivery.
      //
      // AUD-007: the delivery outcome moves to UNKNOWN *before* the provider is
      // contacted. A worker crash after the transport accepted the message then
      // leaves the job in the safe state — resend stays blocked pending provider
      // confirmation — instead of looking like a job that was never sent.
      await transaction(pool, async (db) => {
        const log = await get<EmailDeliveryLog>(db, 'emailLogs', job.id);
        if (log)
          await put(db, 'emailLogs', job.id, {
            ...log,
            status: 'SENDING',
            attemptCount: job.attempts,
            nextRetryTime: null,
          });
        if (job.channel === 'email') {
          const carried = job.payload.includedFindingIds ?? [];
          if (carried.length)
            await attachClaimsToJob(db, job.id, claimsForJob(job.target_id, 'finding', carried));
          const carriedArticles = job.payload.newsEvidence?.articles ?? [];
          if (carriedArticles.length)
            await attachClaimsToJob(
              db,
              job.id,
              claimsForJob(job.target_id, 'article', carriedArticles.map((article) => newsArticleIdentity(article))),
            );
        }
        // An ACCEPTED outcome is a fact and is never downgraded.
        await db.query(
          `UPDATE outbox SET delivery_outcome='UNKNOWN' WHERE id=$1 AND delivery_outcome<>'ACCEPTED'`,
          [job.id],
        );
      });
      // Prepare/validate the exact post-edit email before entering a possible
      // transport attempt. Oversized/missing HTML is a LOCAL error, not proof
      // that the provider may have accepted the message.
      const preparedEmail = applyJobEdits(job);
      findingHtmlAttachment(preparedEmail);
      // Before any possible external send, persist UNKNOWN. A crash after
      // provider acceptance is then safe to reconcile without a blind retry.
      await transaction(pool, async (db) => {
        await db.query(
          `UPDATE outbox SET delivery_outcome='UNKNOWN' WHERE id=$1 AND delivery_outcome<>'ACCEPTED'`,
          [job.id],
        );
      });
      // Edits and attachment preflight were performed before the state was
      // marked as an external attempt; send those same validated bytes.
      transportAttempted = true;
      const result = await sendMail(preparedEmail);
      providerId = typeof result === 'string' ? result : result.id;
      if (typeof result !== 'string') emailProvider = result.provider;
    } else {
      const hook = await get<WebhookEndpoint>(pool, 'webhooks', job.target_id);
      if (!hook?.enabled) {
        permanent = true;
        throw new Error('Webhook removed or disabled');
      }
      if (native && (native.confidence !== 'HIGH' || !hook.events.includes('ALL'))) {
        permanent = true;
        throw new Error('Webhook subscription does not permit native intelligence');
      }
      if (advisory && !currentFindings.every((finding) => webhookAllows(hook, finding))) {
        permanent = true;
        throw new Error('Webhook event subscription no longer permits all advisory findings');
      }
      const url = decrypt(hook.url, encryptionKeys(config), `webhook-url:${hook.id}`),
        secret = decrypt(hook.secretToken, encryptionKeys(config), `webhook:${hook.id}`);
      const body = JSON.stringify(
        hook.provider === 'GENERIC_HMAC'
          ? { id: job.id, advisoryId: job.advisory_id, ...job.payload }
          : { text: job.payload.text },
      );
      const timestamp = Math.floor(Date.now() / 1000).toString();
      signature = 'sha256=' + createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
      const response = await request(url, {
        method: 'POST',
        body,
        headers: {
          'content-type': 'application/json',
          'x-vulnstream-signature': signature,
          'x-vulnstream-timestamp': timestamp,
          'idempotency-key': job.id,
        },
        timeoutMs: 25000,
        socketTimeoutMs: 15000,
      });
      statusCode = response.status;
      if (statusCode < 200 || statusCode >= 300) {
        const rawDelay = response.headers['retry-after'];
        const delay = (Array.isArray(rawDelay) ? rawDelay[0] : rawDelay)?.trim();
        if (delay) {
          const retryAt = /^\d+$/.test(delay)
            ? Date.now() + Number(delay) * 1000
            : /[a-z]/i.test(delay)
              ? Date.parse(delay)
              : NaN;
          if (retryAt > Date.now()) {
            if (!Number.isFinite(retryAt) || retryAt > 8640000000000000) {
              permanent = true;
              throw new Error(
                'Webhook Retry-After exceeds supported scheduling range; operator review required',
              );
            }
            retryNotBefore = retryAt;
          }
        }
        permanent = statusCode >= 400 && statusCode < 500 && ![408, 429].includes(statusCode);
        throw new Error(`Webhook HTTP ${statusCode}`);
      }
      providerId = String(statusCode);
    }
  } catch (e) {
    errorInfo = describeError(e);
    error = e instanceof Error ? e.message : 'Delivery failed';
    // Audit M-6: classify *why* the attempt failed, not just whether it did.
    // A provable rejection (HTTP 4xx/5xx body from the provider, refused SMTP
    // session, or missing configuration) means the transport never accepted the
    // message — retrying cannot duplicate it. Everything else (timeout, socket
    // reset, dropped connection) leaves the outcome unknown, and only a
    // provider lookup can then decide whether a resend is safe.
    const smtpFailure = e as { command?: unknown; responseCode?: unknown };
    const beforeSubmission = typeof smtpFailure?.command === 'string' &&
      /^(CONN|AUTH(?: .*)?|EHLO|HELO|STARTTLS|MAIL FROM|RCPT TO)$/i.test(smtpFailure.command);
    const rejectedData = smtpFailure?.command === 'DATA' && typeof smtpFailure.responseCode === 'number' &&
      smtpFailure.responseCode >= 400 && smtpFailure.responseCode < 600;
    transportRejected =
      e instanceof EmailProviderError
        ? e.status >= 400 && e.status < 500
        : beforeSubmission || rejectedData || /HTTP \d{3}\b|did not accept the recipient|not configured|is missing/i.test(error);
    if (e instanceof EmailProviderError) {
      permanent = e.status >= 400 && e.status < 500 && ![408, 429].includes(e.status);
      retryNotBefore = e.retryAt;
      emailProvider = e.provider;
    }
    if ((e as { confirmedPriorAcceptance?: boolean }).confirmedPriorAcceptance) {
      // The transport already has this message. Clear the error so the job is
      // committed ACCEPTED; a later bookkeeping failure is escalated by the
      // caller instead of being retried as an unconfirmed send.
      error = '';
      errorInfo = {};
      unconfirmedError = 'Delivery accepted by the transport but receipt bookkeeping did not complete';
    }
  }
  let finalized = false;
  // The claims this job owns are the ones its (possibly rebuilt) payload
  // carries. A finding dropped by revalidation is released so a later run can
  // deliver it if it becomes applicable again.
  let carriedFindingIds: string[] = job.payload.includedFindingIds ?? [];
  let droppedFindingIds: string[] = [];
  try {
  await transaction(pool, async (db) => {
    const current = await db.query('SELECT status,lock_token FROM outbox WHERE id=$1 FOR UPDATE', [job.id]);
    if (current.rows[0]?.lock_token !== job.lock_token) return;
    const failed =
        !!error && (permanent || !retryPolicy.enabled || job.attempts >= retryPolicy.maxAttempts),
      mlDelayMs = getMlRuntime()?.deliveryOptimizer.isTrained() ? computeRetryDelay(job.attempts) : undefined,
      retryDelay = emailRetryDelayPlan(job.attempts, retryPolicy, mlDelayMs);
    const retryDelayBaseAt = Date.now();
    const nextAttemptAt = Math.max(retryNotBefore, retryDelayBaseAt + retryDelay.delayMs);
    const next = new Date(nextAttemptAt);
    const scheduledRetryDelayMs = nextAttemptAt - retryDelayBaseAt;
    const scheduledRetryDelaySource = retryNotBefore > retryDelayBaseAt + retryDelay.delayMs
      ? 'PROVIDER_RETRY_AFTER'
      : retryDelay.source;
    // A consolidated finding batch is rebuilt from its surviving findings, so
    // the row must carry the payload that was actually sent. Without this the
    // outbox kept the pre-rebuild body and a later retry or audit would show
    // findings the recipient never received.
    const rebuiltPayload = job.advisory_id.startsWith('FINDINGS:') ? job.payload : undefined;
    carriedFindingIds = job.payload.includedFindingIds ?? [];
    droppedFindingIds = declaredFindingIds.filter((id) => !carriedFindingIds.includes(id));
    if (job.channel === 'email' && droppedFindingIds.length)
      await releaseClaims(db, claimsForJob(job.target_id, 'finding', droppedFindingIds), {
        jobId: job.id,
      });
    // AUD-007: persist the transport's verdict in the same transaction that
    // commits the outbox status.
    //   error empty          → the transport confirmed acceptance → ACCEPTED.
    //   transportRejected    → the transport provably refused the message
    //                          (HTTP 4xx/5xx body, refused SMTP session, missing
    //                          configuration) → REJECTED. Retrying cannot
    //                          duplicate it, so a resend is allowed.
    //   anything else        → timeout, socket reset, dropped connection, an
    //                          unknown prior outcome → UNKNOWN. A resend is
    //                          blocked until provider confirmation resolves it.
    //   NOT_ATTEMPTED        → only when the failure happened before any send
    //                          path (transportAttempted is false): the message
    //                          provably never left. An earlier UNKNOWN is never
    //                          downgraded — an attempt may already have
    //                          happened for this job on a prior attempt.
    const deliveryOutcome: 'NOT_ATTEMPTED' | 'REJECTED' | 'UNKNOWN' | 'ACCEPTED' = !error
      ? 'ACCEPTED'
      : !previousAttemptConfirmedNotDelivered
        ? 'UNKNOWN'
        : transportAttempted
          ? (transportRejected ? 'REJECTED' : 'UNKNOWN')
          : 'NOT_ATTEMPTED';
    await db.query(
      `UPDATE outbox SET status=$2,next_attempt=$3,error=$4,provider_id=$5,locked_at=NULL,lock_token=NULL,updated_at=now(),delivery_outcome=$6
          ${rebuiltPayload ? ',payload=$7::jsonb' : ''} WHERE id=$1`,
      [
        job.id,
        error ? (failed ? 'FAILED' : 'QUEUED') : 'ACCEPTED',
        next,
        // Keep the failure reason on the row so the Action Center can show why
        // a delivery is being retried or has failed.
        error || null,
        providerId || null,
        // The outcome is a fact once recorded: ACCEPTED is never downgraded, and
        // UNKNOWN is only upgraded by provider evidence (REJECTED) — never to
        // NOT_ATTEMPTED, because a prior attempt may already have delivered.
        deliveryOutcome,
        ...(rebuiltPayload ? [JSON.stringify(rebuiltPayload)] : []),
      ],
    );
    if (error && !failed) {
      // A rate-limited or blackholed endpoint must not be hammered once per
      // queued job. Share this target's backoff with its remaining pending work;
      // bound the batch so the global state lock is not held across the queue.
      await db.query(
        `WITH pending AS (
           SELECT id FROM outbox
           WHERE channel=$1 AND target_id=$2 AND status='QUEUED' AND id<>$3 AND next_attempt < $4
           ORDER BY next_attempt
           LIMIT 1000
         )
         UPDATE outbox o SET next_attempt=$4, updated_at=now() FROM pending p WHERE o.id=p.id`,
        [job.channel, job.target_id, job.id, next],
      );
    }
    if (job.channel === 'email') {
      const log = await get<EmailDeliveryLog>(db, 'emailLogs', job.id);
      if (log) {
        // Only stamp sentAt when the email is accepted; preserve the existing
        // value on RETRYING so a provider-accepted-but-temporarily-deferred
        // timestamp survives the retry cycle.
        const status = error ? (failed ? 'FAILED' : 'RETRYING') : 'ACCEPTED';
        const sentAt =
          status === 'ACCEPTED' ? new Date().toISOString() : status === 'RETRYING' ? log.sentAt : undefined;
        await put(db, 'emailLogs', job.id, {
          ...log,
          provider: emailProvider || log.provider,
          // Persist the transport-assigned message id so a later retry can ask
          // the provider whether the prior attempt was accepted (see
          // confirmPriorDelivery). Without this the lookup is dead code and HTTP
          // providers with non-status transport failures stay `unknown` until
          // the retry budget is spent.
          providerId: providerId || undefined,
          // Audit M-6: record whether the transport provably rejected this
          // attempt, so the resend-withhold decision never depends on matching
          // error-message text.
          transportRejected,
          status,
          attemptCount: job.attempts,
          retryDelayMs: error && !failed ? scheduledRetryDelayMs : undefined,
          retryDelaySource: error && !failed ? scheduledRetryDelaySource : undefined,
          errorMessage: error || undefined,
          nextRetryTime: error && !failed ? next.toISOString() : null,
          sentAt,
          // A test message or generated digest is not a finding email and never
          // enters the Action Center. Every real accepted finding delivery
          // becomes a PENDING follow-up action; an already-actioned log is never
          // reopened by a retry.
          ...(status === 'ACCEPTED' && job.target_id !== 'test' && isFindingDelivery(job.advisory_id)
            ? {
                actionStatus: log.actionStatus === 'ACTIONED' ? 'ACTIONED' : 'PENDING',
              }
            : {}),
        });
      }
    } else {
      const log = await get<WebhookDeliveryLog>(db, 'webhookLogs', job.id);
      if (log)
        await put(db, 'webhookLogs', job.id, {
          ...log,
          status: error ? (failed ? 'FAILED' : 'QUEUED') : 'SUCCESS',
          statusCode,
          hmacSignature: signature,
          // FIX: Preserve sentAt on retry (QUEUED) and null on permanent
          // failure (FAILED), mirroring the email-log sentAt fix. The old
          // `error ? '' : ...` cleared the timestamp on every error including
          // retries, losing the original dispatch time.
          sentAt: !error ? new Date().toISOString() : failed ? null : log.sentAt,
        });
      if (!error) {
        const hook = await get<WebhookEndpoint>(db, 'webhooks', job.target_id);
        if (hook) await put(db, 'webhooks', hook.id, { ...hook, deliveryCount: hook.deliveryCount + 1 });
      }
    }
    if (job.channel === 'email' && job.target_id !== 'test') {
      const recipient = await get<EmailRecipient>(db, 'recipients', job.target_id);
      if (recipient) {
        const counts = (
          await db.query(
            "SELECT count(*) FILTER (WHERE status='ACCEPTED')::int AS accepted, count(*) FILTER (WHERE status IN ('ACCEPTED','FAILED'))::int AS terminal FROM outbox WHERE channel='email' AND target_id=$1",
            [job.target_id],
          )
        ).rows[0];
        await put(db, 'recipients', recipient.id, {
          ...recipient,
          deliverySuccessRate: counts.terminal ? (counts.accepted / counts.terminal) * 100 : 0,
        });
      }
    }
    const advisory = await get<Advisory>(db, 'advisories', job.advisory_id);
    if (advisory) {
      const totals = (
        await db.query(
          "SELECT count(*) FILTER(WHERE status='FAILED')::int AS failed,count(*) FILTER(WHERE status IN ('REVIEW','QUEUED','SENDING'))::int AS pending,count(*) FILTER(WHERE status='ACCEPTED')::int AS accepted FROM outbox WHERE advisory_id=$1",
          [advisory.id],
        )
      ).rows[0];
      // Acceptance by a transport is not proof of inbox delivery. A bundle whose
      // only outcome so far is a transport failure stays FAILED; an advisory can
      // have several batches over its lifetime (daily digests, re-queued
      // findings), so an earlier acceptance must not be overwritten by a later
      // partial failure, and a failure must not erase an accepted bundle.
      advisory.deliveryStatus = Number(totals.pending)
        ? 'PENDING'
        : Number(totals.accepted)
          ? 'ACCEPTED'
          : Number(totals.failed)
            ? 'FAILED'
            : advisory.deliveryStatus;
      await put(db, 'advisories', advisory.id, advisory);
      if (!error) {
        const dispatchKey = job.payload.digestKey ?? job.dedupe_key.split(':email:')[0].split(':webhook:')[0];
        const dispatchIds = declaredCveIds.map((cveId) => `${cveId}:${dispatchKey}`);
        const priorAlerts = await getMany<AlertedCVE>(db, 'alertedCves', declaredCveIds);
        const priorDispatches = await getMany(db, 'alertDispatches', dispatchIds);
        for (const cveId of declaredCveIds) {
          const prior = priorAlerts.get(cveId);
          const now = new Date().toISOString();
          // Digest jobs carry one batch key across every recipient, so the same
          // CVE is counted once even when several subscription cohorts receive
          // it. Non-digest jobs retain the original content-revision key.
          const same =
            prior?.lastDispatchKey === dispatchKey || !!priorDispatches.get(`${cveId}:${dispatchKey}`);
          await put(db, 'alertDispatches', `${cveId}:${dispatchKey}`, {
            cveId,
            dispatchKey,
            acceptedAt: now,
          });
          await put(db, 'alertedCves', cveId, {
            cveId,
            firstAlertedAt: prior?.firstAlertedAt || now,
            lastAlertedAt: now,
            advisoryId: advisory.id,
            recipientEmails: Array.from(
              new Set([
                ...(prior?.recipientEmails || []),
                ...(job.channel === 'email' ? [job.payload.recipientEmail!] : []),
              ]),
            ),
            status: 'DISPATCHED',
            lastDispatchKey: dispatchKey,
            dispatchCount: (prior?.dispatchCount || 0) + (same ? 0 : 1),
          } satisfies AlertedCVE);
        }
      }
      // Batch-fetch all finding rows in a single query instead of per-finding.
      const findingMap = await getMany<Finding>(db, 'findings', advisory.findingIds);
      // Only the findings this target actually delivered describe this
      // recipient's bundle. Assessment or digest bundles that are already
      // accepted must not be flipped back to FAILED because the digest window
      // rolled over and a later partial bundle for the same advisory is still
      // pending.
      const deliveredIds =
        job.payload.includedFindingIds !== undefined ? new Set(job.payload.includedFindingIds) : undefined;
      for (const findingId of deliveredIds ?? advisory.findingIds) {
        const f = findingMap.get(findingId);
        if (!f) continue;
        // A finding held for review was queued in this bundle deliberately
        // (assessment and digest payloads may include them). Once the transport
        // for that bundle accepts it, its notification lifecycle is dispatched;
        // otherwise it would remain REVIEW_REQUIRED — perpetually re-selected by
        // the daily digest — while its advisory reports ACCEPTED. A rejected or
        // still-pending bundle keeps the hold in place.
        const reviewHeld = f?.notificationStatus === 'REVIEW_REQUIRED';
        const releasedByReview = reviewHeld && !error && !totals.pending && !totals.failed;
        // Generated advisories (pipeline, digest, daily) are never bound to the
        // findings they describe — only manually reviewed advisories set
        // `advisoryId`. Gating this bookkeeping on that binding left every
        // auto-queued finding marked QUEUED_FOR_DISPATCH after an accepted send,
        // so it was re-queued and re-sent on the next pipeline run. A
        // REVIEW_REQUIRED finding released by this acceptance has neither
        // field set yet, so it must be admitted explicitly.
        if (f.advisoryId === advisory.id || (!f.advisoryId && f.autoDispatchedAt) || releasedByReview)
          await put(db, 'findings', findingId, {
            ...f,
            advisoryId: f.advisoryId ?? advisory.id,
            notificationStatus: releasedByReview
              ? 'AUTO_DISPATCHED'
              : ['NOT_APPLICABLE', 'REVIEW_REQUIRED'].includes(f.notificationStatus)
                ? f.notificationStatus
                : totals.pending
                  ? 'QUEUED_FOR_DISPATCH'
                  : totals.failed
                    ? 'DELIVERY_FAILED'
                    : 'AUTO_DISPATCHED',
            autoDispatchedAt:
              (releasedByReview || !reviewHeld) && !totals.pending && !totals.failed
                ? new Date().toISOString()
                : null,
          });
    }
    }
    // The durable receipt is the per-recipient claim: this recipient has now
    // been told about these findings, and no later run may queue them for it
    // again. Promotion is scoped to the claims this job owns (job_id, attached
    // by `attachClaimsToJob` in the queue transaction), so a claim re-taken by
    // a later run after expiry is never overwritten by a stale delivery. It is
    // committed in the same transaction as ACCEPTED.
    if (job.channel === 'email' && !error) {
      const acceptedAt = new Date().toISOString();
      if (carriedFindingIds.length)
        await markClaimsDelivered(db, claimsForJob(job.target_id, 'finding', carriedFindingIds), {
          jobId: job.id,
          deliveredAt: acceptedAt,
        });
      const carriedArticles = job.payload.newsEvidence?.articles ?? [];
      if (carriedArticles.length)
        await markClaimsDelivered(
          db,
          claimsForJob(job.target_id, 'article', carriedArticles.map((article) => newsArticleIdentity(article))),
          { jobId: job.id, deliveredAt: acceptedAt },
        );
    }
    // `reviewNotifiedAt` is retained for aggregate reporting and for builds that
    // predate `delivery_claims`. It is a GLOBAL stamp — the first recipient's
    // acceptance sets it — so it must never be used to decide whether a
    // particular recipient still needs the finding (AUD-001).
    if (job.channel === 'email' && !error && carriedFindingIds.length) {
      await db.query(
        `UPDATE records SET data=jsonb_set(data,'{reviewNotifiedAt}',to_jsonb($2::text)),updated_at=now()
         WHERE kind='findings' AND id=ANY($1::text[]) AND COALESCE(data->>'reviewNotifiedAt','')=''`,
        [carriedFindingIds, new Date().toISOString()],
      );
    }
    // A terminally failed delivery releases the claims THIS job owns only when
    // non-delivery is PROVEN (audit follow-up, High #1): the recorded outcome is
    // the evidence, not the error text.
    //
    //   REJECTED      the transport provably refused the message → safe to free;
    //                 retrying cannot duplicate it.
    //   NOT_ATTEMPTED the failure happened before any send path (transport
    //                 attempted flag false) → nothing ever left, safe to free.
    //   UNKNOWN       the outcome is ambiguous: the provider may have accepted
    //                 the message before the connection dropped. The claims stay
    //                 held so no later batch can re-notify the item while the
    //                 first email may still be in the recipient's inbox. The
    //                 confirm-prior-delivery path reconciles the outcome with
    //                 the provider on the next attempt and releases the claims
    //                 only once non-delivery is established there.
    const confirmedNonDelivery = deliveryOutcome === 'REJECTED' || deliveryOutcome === 'NOT_ATTEMPTED';
    if (job.channel === 'email' && error && failed && confirmedNonDelivery) {
      if (carriedFindingIds.length)
        await releaseClaims(db, claimsForJob(job.target_id, 'finding', carriedFindingIds), {
          jobId: job.id,
        });
    }
    if (job.channel === 'email' && error && failed && !confirmedNonDelivery)
      await writeEvent(db, {
        category: 'EMAIL',
        level: 'WARNING',
        code: 'delivery.claims_held_pending_outcome',
        message: 'Terminal failure with an unresolved transport outcome; per-recipient claims held for reconciliation',
        context: {
          jobId: job.id,
          advisoryId: job.advisory_id,
          deliveryOutcome,
          claims: carriedFindingIds.length,
        },
      });
// After a Security-team delivery is confirmed ACCEPTED, queue the same
    // email for Everyone-group recipients. This is the deferred half of the
    // `deferEveryoneUntilSecurityDelivered` setting; the function is a no-op when
    // the setting is off or the recipient is not Security-team.
    if (job.channel === 'email' && !error && job.target_id !== 'test') {
      await queueEveryoneDeliveryJobs(db, job, settings);
    }
    if (job.channel === 'email' && job.payload.newsEvidence?.articles?.length) {
      const articleClaims = claimsForJob(
        job.target_id,
        'article',
        job.payload.newsEvidence.articles.map((article) => newsArticleIdentity(article)),
      );
      if (!error) {
        // The notification is durable only after the transport accepts it.
        const acceptedAt = new Date().toISOString();
        await recordNewsDeliveries(db, job.target_id, job.advisory_id,
          job.payload.newsEvidence.articles, acceptedAt);
      } else if (failed && confirmedNonDelivery) {
        // The recipient never received these articles: free THIS job's claims so
        // the next run re-queues them instead of losing them. Ownership is
        // enforced, exactly as for findings. An UNKNOWN outcome keeps the claims
        // held, exactly as for findings — the provider may have accepted the
        // message before the connection failed.
        await releaseClaims(db, articleClaims, { jobId: job.id });
      } else if (failed) {
        await writeEvent(db, {
          category: 'EMAIL',
          level: 'WARNING',
          code: 'delivery.claims_held_pending_outcome',
          message: 'Terminal news failure with an unresolved transport outcome; article claims held for reconciliation',
          context: {
            jobId: job.id,
            advisoryId: job.advisory_id,
            deliveryOutcome,
            articles: job.payload.newsEvidence.articles.length,
          },
        });
      }
    }
    await writeEvent(db, {
      category: job.channel === 'email' ? 'EMAIL' : 'EVENT',
      level: error ? 'WARNING' : 'INFO',
      code: error ? 'delivery.attempt_failed' : 'delivery.accepted',
      message: error ? 'Delivery attempt failed; retry policy applied' : 'Transport accepted delivery',
      context: {
        jobId: job.id,
        channel: job.channel,
        attempt: job.attempts,
        advisoryId: job.advisory_id,
        ...(error ? errorInfo : {}),
      },
    });
    if (job.channel === 'email' && transportAttempted && !staleAdvisory && !holdGated && !unconfirmedError) {
      const observedStatus = Number(/HTTP\s+(\d{3})\b/i.exec(error)?.[1] ?? statusCode);
      const classification = classifyDeliveryError({
        provider: emailProvider ?? 'unknown', statusCode: observedStatus,
        errorMessage: error, attemptNumber: job.attempts, hourOfDay: new Date().getUTCHours(),
      });
      await writeEvent(db, {
        category: 'ML', code: 'ml.delivery.outcome', message: 'Observed delivery attempt outcome',
        context: {
          jobId: job.id, provider: emailProvider ?? 'unknown', attempt: job.attempts, delayMs: retryDelayObserved,
          delayObserved: observedDelay.observed,
          succeeded: !error, isRateLimited: observedStatus === 429, isPermanentFailure: permanent,
        },
      });
      if (error) await writeEvent(db, {
        category: 'ML', code: 'ml.delivery.classification', message: 'Delivery classification recommendation',
        context: { ...classification, jobId: job.id, authoritativePermanent: permanent },
      });
      if (error) await writeEvent(db, {
        category: 'ML', code: 'ml.delivery.error', message: 'Observed transport error classification',
        context: {
          provider: emailProvider ?? 'unknown', statusCode: observedStatus,
          errorMessage: error.slice(0, 1000), attemptNumber: job.attempts,
          hourOfDay: new Date().getUTCHours(), isPermanent: permanent,
        },
      });
    }
    if (failed && error) {
      await writeEvent(db, {
        category: job.channel === 'email' ? 'EMAIL' : 'EVENT',
        level: 'ERROR',
        code: 'delivery.exhausted',
        message: `Delivery retries exhausted for advisory ${job.advisory_id}; permanent failure`,
        context: {
          jobId: job.id,
          channel: job.channel,
          attempts: job.attempts,
          advisoryId: job.advisory_id,
          error,
          ...errorInfo,
        },
      });
    }
    await appendAudit(
      db,
      error ? 'Delivery attempt failed' : 'Delivery accepted',
      `${job.channel} delivery ${job.id}; attempt ${job.attempts}`,
      'delivery-worker',
      job.channel === 'email' ? 'EMAIL' : 'WEBHOOK',
      error ? 'WARNING' : 'INFO',
    );
    finalized = true;
  });
  } catch (bookkeepingError) {
    if (!unconfirmedError) throw bookkeepingError;
    // The transport already holds this message but the receipt could not be
    // recorded. Report it loudly instead of rethrowing: a rethrown error makes
    // the worker tick look failed, and the row is still SENDING so a later
    // attempt would resend. The lease expiry plus confirm-before-send is the
    // backstop if this process dies here.
    await writeEvent(pool, {
      category: 'EMAIL',
      level: 'ERROR',
      code: 'delivery.receipt_unconfirmed',
      message: unconfirmedError,
      context: { jobId: job.id, advisoryId: job.advisory_id, attempt: job.attempts, ...describeError(bookkeepingError) },
    }).catch(() => undefined);
  }
  if (finalized && staleAdvisory) {
    try {
      const { rebuildFromCurrentInventory } = await import('./pipeline');
      await rebuildFromCurrentInventory(pool, job.advisory_id, error, { payloadRebuilt: legacyRebuilt });
    } catch (rebuildError) {
      await writeEvent(pool, {
        category: 'EMAIL',
        level: 'ERROR',
        code: 'delivery.rebuild_failed',
        message: 'Stale delivery was retained as failed; rebuilding could not complete',
        context: { jobId: job.id, advisoryId: job.advisory_id, ...describeError(rebuildError) },
      });
    }
  }

  return true;
}

