import type {
  AppSettings,
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  AlertedCVE,
  EmailRecipient,
  WebhookEndpoint,
  WebhookDeliveryLog,
  EmailDeliveryLog,
  AuditLog,
  PipelineExecution,
  TemplateCustomization,
  EmailConfiguration,
  IntelligenceArticle,
  IntelligenceMatch,
  AliasEntry,
} from '../src/types/index.ts';
import type { ZeroDayDigest } from '../src/engine/pipelineEngine.ts';
import {
  DEFAULT_TEMPLATE_CUSTOMIZATION,
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  compileCustomizedTemplate,
  compileDailyDigestTemplate,
} from '../src/utils/templateCompiler.ts';
export const DEFAULT_EMAIL_CONFIG: EmailConfiguration = {
  provider: 'SMTP',
  fromEmail: '',
  fromName: 'BA Threat Intel',
  apiKey: '',
  replyTo: '',
  unsubscribeUrl: '',
  apiEndpoint: '',
  apiHeaderKey: 'Authorization',
  apiAuthPrefix: 'Bearer',
  apiSourceDomain: '',
  smtpHost: '',
  smtpPort: 587,
  smtpSecurity: 'STARTTLS',
  smtpUsername: '',
  smtpPassword: '',
  mailtrapMode: 'LIVE',
  mailtrapInboxId: '',
  postmarkMessageStream: 'outbound',
  mailjetApiSecret: '',
};
/**
 * Timezone applied when the operator has not configured one in Settings.
 *
 * Resolved from the runtime clock rather than a hard-coded IANA name: the
 * browser reports the operator's local zone and the server reports its own.
 * Rendering and the daily-digest schedule both use this fallback, so a fresh
 * deployment displays local time instead of UTC.
 */
export const DEFAULT_TIMEZONE = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
})();

export const DEFAULT_SETTINGS: AppSettings = {
  scopeHours: 24,
  schedulerIntervalMinutes: 60,
  schedulerEnabled: true,
  advisoryPrefix: 'ADV-',
  autoDispatchEnabled: false,
  autoDispatchConfidenceThreshold: 90,
  reviewConfidenceThreshold: 0,
  autoDispatchUnverifiableMatches: false,
  autoDispatchNewsToSecurityTeam: false,
  reviewUnverifiableMatches: false,
  deferEveryoneUntilSecurityDelivered: false,
  digestBatchingEnabled: true,
  digestWindowMinutes: 5,
  emailRetryEnabled: true,
  emailRetryMaxAttempts: 6,
  emailRetryInitialDelayMinutes: 1,
  emailRetryMaxDelayMinutes: 60,
  emailEnabled: true,
  webhookSigningSecret: '',
  authorityPrecedence: ['VENDOR_PSIRT', 'CISA_KEV', 'FIRST_EPSS', 'NVD_BATCH'],
  ssrfProtection: { blockPrivateIps: true, blockLoopback: true, allowRedirects: true },
  securityPolicy: {
    sessionTimeoutMins: 30,
    csrfProtection: true,
    minPasswordLen: 14,
    maxLoginAttempts: 5,
    lockoutMins: 15,
    autoAliasTtlDays: 30,
  },
  // Standard keeps the event table small enough to stay fast during an
  // incident; verbose is an explicit forensic choice.
  logVerbosity: 'standard',
  ntpConfig: { enabled: false, server: '', driftToleranceMs: 50 },
  retentionConfig: {
    enabled: false,
    retentionHours: 24,
    cleanupIntervalMinutes: 60,
    maxArchivedRecords: 10000,
    autoCleanup: true,
    retentionMode: 'rolling',
  },
  timezone: DEFAULT_TIMEZONE,
  dailyDigest: {
    enabled: true,
    time: '09:00',
    includeHealthReport: true,
  },
  selfHealing: {
    enabled: true,
    cooldownMinutes: 30,
    emailNotifications: true,
  },
};
/**
 * Collections that can grow without bound in a large installation. `/api/state`
 * returns only a bounded recent slice plus exact counts for these kinds; the
 * paginated `/api/collections/:kind` endpoint is the source for full browsing.
 */
export const HEAVY_COLLECTION_KINDS = [
  'cveData',
  'findings',
  'advisories',
  'alertedCves',
  'emailLogs',
  'webhookLogs',
  'executions',
  'auditLogs',
  'intelligenceArticles',
  'intelligenceMatches',
  // Audit F-3: digests accumulate one row per vendor/product that ever hit the
  // zero-day cap. Without this they are invisible to capped browsing and to
  // the archive screen's per-kind counts.
  'zeroDayDigests',
] as const;
export type HeavyCollectionKind = (typeof HEAVY_COLLECTION_KINDS)[number];

export const COLLECTION_KINDS = [
  'feeds',
  'watchlist',
  'recipients',
  'webhooks',
  'aliases',
  ...HEAVY_COLLECTION_KINDS,
] as const;
export type CollectionKind = (typeof COLLECTION_KINDS)[number];

export const isCollectionKind = (value: string): value is CollectionKind =>
  (COLLECTION_KINDS as readonly string[]).includes(value);

export type CollectionCounts = Record<CollectionKind, number>;

/** Aggregate counts used by dashboards and navigation badges. */
export interface AppSummary {
  activeFindings: number;
  criticalFindings: number;
  kevFindings: number;
  deliveredEmails: number;
}

export interface CollectionPage<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface AppState {
  feeds: ThreatFeed[];
  watchlist: WatchListItem[];
  cveData: NormalizedCVE[];
  findings: Finding[];
  advisories: Advisory[];
  alertedCves: AlertedCVE[];
  recipients: EmailRecipient[];
  webhooks: WebhookEndpoint[];
  webhookLogs: WebhookDeliveryLog[];
  emailLogs: EmailDeliveryLog[];
  auditLogs: AuditLog[];
  executions: PipelineExecution[];
  settings: AppSettings;
  emailConfig: EmailConfiguration;
  intelligenceArticles: IntelligenceArticle[];
  intelligenceMatches: IntelligenceMatch[];
  /** Zero-day digests consolidated by the per-run cap (audit F-3 exposure). */
  zeroDayDigests: ZeroDayDigest[];
  templateCustomization: TemplateCustomization;
  customAdvisoryTemplate: string | null;
  advisoryTemplate: string;
  dailyDigestCustomization: TemplateCustomization;
  dailyDigestTemplate: string;
  dailyDigestCustomTemplate: string | null;
  aliases: AliasEntry[];
  /** Exact row counts for every collection, independent of the returned slice. */
  counts: CollectionCounts;
  /** Aggregates computed server-side so bounded slices cannot skew KPI cards. */
  summary: AppSummary;
}

const zeroCounts = (): CollectionCounts =>
  Object.fromEntries(COLLECTION_KINDS.map((kind) => [kind, 0])) as CollectionCounts;

export const emptyState = (): AppState => ({
  feeds: [],
  intelligenceArticles: [],
  intelligenceMatches: [],
  zeroDayDigests: [],
  watchlist: [],
  cveData: [],
  findings: [],
  advisories: [],
  alertedCves: [],
  recipients: [],
  webhooks: [],
  webhookLogs: [],
  emailLogs: [],
  auditLogs: [],
  executions: [],
  aliases: [],
  settings: structuredClone(DEFAULT_SETTINGS),
  emailConfig: { ...DEFAULT_EMAIL_CONFIG },
  templateCustomization: { ...DEFAULT_TEMPLATE_CUSTOMIZATION },
  customAdvisoryTemplate: null,
  advisoryTemplate: compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION),
  dailyDigestCustomization: { ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION },
  dailyDigestTemplate: compileDailyDigestTemplate(DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  dailyDigestCustomTemplate: null,
  counts: zeroCounts(),
  summary: { activeFindings: 0, criticalFindings: 0, kevFindings: 0, deliveredEmails: 0 },
});
export type Role = 'ADMIN' | 'OPERATOR' | 'VIEWER';
export interface SessionInfo {
  username: string;
  /** Address the operator's password-reset code is sent to; null until set. */
  email?: string | null;
  role: Role;
  csrfToken: string;
  expiresAt: string;
}
