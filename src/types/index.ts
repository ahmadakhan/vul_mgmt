import { NvdVersionRange } from '../utils/versionComparator.ts';
import type { VulnerabilityEcosystemId } from '../../shared/vulnerability.ts';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export type ExposureLevel = 'INTERNET_FACING' | 'INTERNAL_CRITICAL' | 'DMZ' | 'WORKSTATION' | 'CLOUD_INFRA';

export type ExploitRiskLevel =
  | 'CISA_KEV_EXPLOITED'
  | 'REPORTED_IN_WILD_EXPLOIT'
  | 'WEAPONIZED_EXPLOIT'
  | 'HIGH_EPSS_PROBABILITY'
  | 'ELEVATED'
  | 'STANDARD';

export type NotificationStatus =
  | 'AUTO_DISPATCHED'
  | 'QUEUED_FOR_DISPATCH'
  | 'DIGEST_BATCHED'
  | 'REVIEW_REQUIRED'
  | 'NOT_APPLICABLE'
  | 'SUPPRESSED_VEX_NOT_AFFECTED'
  | 'DELIVERED'
  | 'DELIVERY_FAILED'
  | 'SECURITY_REJECTED';

export type FindingStatus =
  'MONITORED' | 'REMEDIATION_AVAILABLE' | 'PATCH_APPLIED' | 'RESOLVED' | 'FALSE_POSITIVE';

/**
 * Feed types the server can actually ingest. The runtime adapter set and this
 * list must stay identical: a feed that is not in this list cannot be polled.
 */
export const FEED_TYPES = [
  'JSON_SEARCH_API',
  'NVD_API',
  'MITRE_CVE',
  'CISA_KEV',
  'EPSS_API',
  'OPENCVE_API',
  'VULNCHECK_KEV',
  'OTX_API',
  'OSV_API',
  'GITHUB_ADVISORIES',
  'RSS_ATOM',
  'GOOGLE_CSE',
] as const;

export type FeedType = (typeof FEED_TYPES)[number];

export type FeedAuthType = 'NONE' | 'API_KEY' | 'BEARER' | 'BASIC';

export interface IntelligenceArticle {
  id: string;
  url: string;
  title: string;
  summary: string;
  publishedDate: string;
  modifiedDate: string;
  cveIds: string[];
  sourceFeeds: string[];
  /** True when the article describes a vulnerability without an assigned CVE ID (potential zero-day). */
  zeroDay?: boolean;
  /**
   * Pre-CVE cluster identity assigned by the correlation layer when this
   * article was ingested before a CVE existed. When the CVE is later
   * published, articles in the same cluster are linked to it so the
   * canonical identifier inherits the accumulated evidence and operator
   * dispositions instead of alerting as a brand-new incident.
   */
  clusterId?: string;
  /** CVE ID this cluster was resolved to by the CVE-publication linkage. */
  resolvedCveId?: string;
}
export interface IntelligenceMatch {
  id: string;
  cveId: string | null;
  assetId: string;
  assetName: string;
  articleIds: string[];
  status: 'CORROBORATED' | 'REVIEW_REQUIRED';
  evidence: string;
  findingId?: string;
  /** True when matched articles describe a vulnerability without an assigned CVE (potential zero-day). */
  zeroDay?: boolean;
  /** Credibility score: source feed weight × keyword confidence (0–100). */
  credibilityScore?: number;
  /** ML calibration recommendation; original evidence score remains authoritative. */
  calibratedCredibilityScore?: number;
  /** Historical evidence features persisted for ML training; excludes outcome-derived labels. */
  sourceFeedWeight?: number;
  keywordScore?: number;
}
export const EVENT_CATEGORIES = [
  'PIPELINE',
  'FEED',
  'MATCHING',
  'EMAIL',
  'SYSTEM',
  'ISSUE',
  'EVENT',
  'ML',
] as const;
export interface OperationalEvent {
  id: string;
  timestamp: string;
  category: (typeof EVENT_CATEGORIES)[number];
  level: 'INFO' | 'WARNING' | 'ERROR';
  code: string;
  message: string;
  runId?: string;
  context: Record<string, unknown>;
  /** Correlation-worker metadata, present only on telemetry-sourced events. */
  trackingId?: string;
  /** Raw telemetry event name (dot-namespaced), distinct from the pipeline `code`. */
  event?: string;
  /** Worker-local sequence; restarts per process, so it orders within a writer only. */
  sequence?: number;
  ingestionLatencyMs?: number;
  extractionLatencyMs?: number;
  totalDatabaseTimeMs?: number;
  /** Retry attempt number for transient database failures. */
  attempt?: number;
}

export interface CVSSData {
  version: '3.0' | '3.1' | '4.0' | '2.0' | 'UNKNOWN';
  score: number;
  vector: string;
  severity: Severity;
}

export interface EPSSData {
  score: number;
  percentile: number;
}

export interface CisaKevData {
  isKev: boolean;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  knownRansomwareCampaignUse?: 'Known' | 'Unknown';
}

export type VexStatus = 'affected' | 'not_affected' | 'fixed' | 'under_investigation';

/**
 * VEX statements can be scoped to a single product/CPE/PURL. An unscoped
 * statement applies to the whole advisory; a scoped statement only applies to
 * findings whose matched inventory falls inside the declared scope.
 */
export interface VexScope {
  cpe?: string;
  purl?: string;
  vendor?: string;
  product?: string;
}

export interface VexStatement {
  status: VexStatus;
  justification?: string;
  impactStatement?: string;
  /** Feed/provider that supplied the statement. */
  source?: string;
  /** Optional product/package scope. */
  scope?: VexScope;
  /**
   * Only signed statements may suppress alerts. Legacy statements without this
   * field are treated as signed for backward compatibility; ingestion marks
   * unsigned generic-feed claims explicitly.
   */
  signed?: boolean;
  timestamp?: string;
}

export type ExploitabilityConflictState =
  | 'NONE'
  | 'CONSISTENT'
  | 'CONFLICT'
  | 'EXPLOIT_INTELLIGENCE_OVERRIDE'
  | 'UNDER_INVESTIGATION'
  | 'SCOPE_MISMATCH';

/** Result of the per-source exploitability lattice for one finding scope. */
export interface ExploitabilityAssessment {
  status: VexStatus | 'unknown';
  conflictState: ExploitabilityConflictState;
  suppressed: boolean;
  requiresReview: boolean;
  reason: string;
  sources: string[];
  applicableStatements: number;
  ignoredStatements: number;
}

export interface RemediationPlaybook {
  patchUrl: string;
  vendorAdvisoryRef: string;
  immediateActions: string[];
  workarounds: string[];
  rollbackPlan: string;
  stepByStep: string[];
}

export interface ReviewEdits {
  /** Operator override for the outgoing email subject. */
  subject?: string;
  audienceNotice?: string;
  reviewerComment?: string;
  reviewerName?: string;
  customBodyOverride?: string;
  customFields?: Record<string, string>;
  recipientMode?: 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE';
  customEmail?: string;
}

/**
 * Operator follow-up state for a delivered finding email.
 *
 * Once the transport accepts a finding email it lands in the Action Center as
 * `PENDING`: the delivery itself succeeded, but an operator still has to
 * acknowledge it, or edit and send a corrected copy. Acknowledging (or sending
 * an updated copy) moves it to `ACTIONED`, which is what raises the action SLA
 * from PENDING to COMPLIANT. Optional for records written before the field
 * existed; the UI treats a delivered log without a value as PENDING.
 */
export type EmailActionStatus = 'PENDING' | 'ACTIONED';

export interface TemplateCustomization {
  fontFamily: 'sans' | 'mono' | 'serif' | 'system';
  fontColor: string;
  headingColor: string;
  accentColor: string;
  canvasBg: string;
  cardBg: string;
  headerBg: string;
  badgeStampText: string;
  badgeStampColor: string;
  showStamp: boolean;
  showClassificationBanner: boolean;
  classificationText: string;
  borderStyle: 'solid' | 'dashed' | 'none';
  borderRadius: string;
}

export interface NormalizedCVE {
  cveId: string; // Canonical CVE-YYYY-NNNNN
  title: string;
  description: string;
  publishedDate: string;
  modifiedDate: string;
  cvss: CVSSData;
  cwe: string[];
  cpeMatches: string[]; // CPE 2.3 formatted strings
  versionRange?: NvdVersionRange; // NVD Version Interval
  applicabilityRequiresReview?: boolean;
  applicabilityPolicy?: 'REVIEW_ONLY';
  /** Internal provider-specific evidence used to reconcile independent revision clocks. */
  sourceApplicability?: Record<string, SourceApplicabilityEvidence>;
  cpeMatchDetails?: { criteria: string; range?: NvdVersionRange }[];
  purls?: string[]; // Package URLs (PURL)
  vex?: VexStatement; // CSAF 2.0 VEX status (legacy single-statement form)
  /** Per-source VEX statements. Resolved through the exploitability lattice. */
  vexStatements?: VexStatement[];
  sourceFeeds: string[];
  exploitationSources?: string[];
  epss: EPSSData;
  cisaKev: CisaKevData;
  exploitStatus: 'Active Weaponized' | 'POC Available' | 'Reported In Wild' | 'None';
  remediation: RemediationPlaybook;
}

export interface SourceApplicabilityEvidence {
  modifiedDate: string;
  cpeMatches: string[];
  cpeMatchDetails: { criteria: string; range?: NvdVersionRange }[];
  versionRange?: NvdVersionRange;
  purls?: string[];
  applicabilityRequiresReview?: boolean;
  applicabilityPolicy?: 'REVIEW_ONLY';
  contentHash: string;
}

export interface WatchListItem {
  id: string;
  vendor: string;
  product: string;
  version?: string;
  cpes: string[]; // Strict CPE 2.3 entries
  purls?: string[]; // Optional PURLs
  targetHw?: string; // Architecture e.g. x86_64, aarch64
  exposure?: ExposureLevel; // Deprecated: all products treated with uniform enterprise priority
  assetTag: string;
  ownerGroup: string;
  active: boolean;
  notes?: string;
  createdAt: string;
}

export interface Finding {
  id: string;
  /** Decision support only; never overrides applicability, VEX or operator policy. */
  mlAssessment?: {
    assessedAt: string;
    cpeParseRecommended: boolean;
    matchConfidence: number;
    aliasConfidence: number;
    exploitRisk: string;
    severityTier: string;
    remediationCompleteness: 'complete' | 'partial' | 'sparse';
  };
  cveId: string;
  cve: NormalizedCVE;
  matchedAssetId: string;
  matchedAssetName: string;
  matchedAssetVendor?: string;
  matchedAssetProduct?: string;
  /** PURLs of the matched inventory item, used to scope VEX statements. */
  matchedAssetPurls?: string[];
  matchedCpe: string;
  matchingMethod: string;
  matchingEvidence: string;
  /** Match confidence (0–100). 0 indicates the version range could not be verified
   *  and the finding is an unverifiable match held for security-team review. */
  confidence?: number;
  exposure?: ExposureLevel; // Deprecated
  exploitRisk: ExploitRiskLevel;
  /** Per-source VEX lattice result captured at correlation time. */
  exploitability?: ExploitabilityAssessment;
  notificationStatus: NotificationStatus;
  status: FindingStatus;
  autoDispatchedAt: string | null;
  advisoryId: string | null;
  /** Execution ID that produced this finding, for filtering findings per run. */
  executionId?: string;
  /**
   * Timestamp when the unverifiable-match review notification email was accepted
   * by the transport. Null when the finding has not yet been notified. Once set,
   * the pipeline will not re-queue the notification, guaranteeing the email is
   * sent at most once per finding. Optional for backward compatibility with
   * records written before this field existed.
   */
  reviewNotifiedAt?: string | null;
  timeline: {
    timestamp: string;
    action: string;
    system: string;
    details: string;
  }[];
}

export interface ThreatFeed {
  id: string;
  name: string;
  type: FeedType;
  url: string;
  authType: FeedAuthType;
  authSecretKey?: string;
  rateLimitPerMin: number;
  requestTimeoutSeconds?: number;
  recoveryDelayMinutes?: number;
  enabled: boolean;
  healthStatus: 'HEALTHY' | 'DEGRADED' | 'DOWN' | 'UNTESTED';
  lastSync: string | null;
  latencyMs: number;
  vendorSeed: boolean;
  itemCountLastRun: number;
  errorLog?: string | null;
  ssrfValidated: boolean;
  etag?: string;
  consecutiveFailures?: number;
  circuitOpenUntil?: string | null;
  lastRecoveryAttemptAt?: string;
}

/**
 * A single CPE 2.3 entry returned by the NVD CPE dictionary search. These are
 * NVD-maintained official CPE names offered as verified alternatives when an
 * operator registers a monitored product.
 */
export interface NvdCpeSearchResult {
  cpeName: string;
  cpeNameId: string;
  part: string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  targetSw: string;
  targetHw: string;
  /** Human-readable title from the NVD CPE dictionary, when available. */
  title?: string;
  /**
   * True when this entry was found via the wildcard-vendor dictionary search
   * (matched on product name alone), not the vendor-scoped keyword search.
   * Still a verified, exact NVD dictionary CPE — only the search path differs.
   */
  viaWildcardVendor?: boolean;
}

export interface NvdCpeSearchResponse {
  results: NvdCpeSearchResult[];
  totalResults: number;
}

export interface ThreatSearchHit {
  cve: NormalizedCVE;
  /** CPE 2.3 strings that matched the requested vendor/product. */
  matchingCpes: string[];
  /** Origin of the result: `NVD_API` for the CVE Search API, `KEYWORD_FALLBACK` for keyword-search results. */
  source: 'NVD_API' | 'KEYWORD_FALLBACK';
}

export interface ThreatSearchResponse {
  hits: ThreatSearchHit[];
  totalResults: number;
  vendor: string;
  product: string;
  rateLimited: boolean;
  retryAfter?: number;
  /** Whether an NVD API key was loaded and supplied with the request. */
  apiKeyUsed: boolean;
  /** ISO date string (YYYY-MM-DD) the scan was constrained to, when a start date was supplied. */
  startDate?: string;
}

/** Databases and public feeds that can contribute a vulnerability-search result. */
export type VulnerabilitySource = 'OSV' | 'NVD' | 'CISA_KEV' | 'OSINT';

export interface VulnerabilityReference {
  /** Source label such as `ADVISORY`, `FIX`, `WEB`, or `Vendor Advisory`. */
  type?: string;
  url: string;
}

/**
 * One affected package/build entry. OSV reports range events; NVD reports CPE
 * criteria and version intervals. Both are flattened into the same display
 * model so the results view does not need per-source branching.
 */
export interface VulnerabilityAffectedPackage {
  ecosystem: string;
  packageName: string;
  purl?: string;
  /** Exact versions listed by the source (bounded by the service). */
  affectedVersions: string[];
  /** Human-readable ranges such as `>= 1.0.0, < 1.2.3`. */
  affectedRanges: string[];
  /** Versions/events the source marks as the first fixed release. */
  fixedVersions: string[];
}

export interface VulnerabilityKevInfo {
  isKev: boolean;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  knownRansomwareCampaignUse?: string;
}

export interface VulnerabilitySearchResult {
  /** Primary identifier: CVE when available, otherwise the OSV advisory ID. */
  id: string;
  cveIds: string[];
  aliases: string[];
  title: string;
  description: string;
  severity: Severity;
  cvss: {
    score: number | null;
    vector: string | null;
    version: string | null;
  };
  publishedDate: string | null;
  modifiedDate: string | null;
  /** Every source that contributed to this merged result. */
  sources: VulnerabilitySource[];
  affectedPackages: VulnerabilityAffectedPackage[];
  cpeMatches: string[];
  fixedVersions: string[];
  references: VulnerabilityReference[];
  /** Preferred human-facing advisory link for this record. */
  advisoryUrl: string | null;
  kev: VulnerabilityKevInfo | null;
  /** Verbatim upstream payloads, surfaced in the expandable raw-data panel. */
  rawSources: { source: VulnerabilitySource; data: unknown }[];
}

export interface VulnerabilitySearchParams {
  /** Free-text query: a product, package, keyword, CVE identifier, or *, all, any. */
  query?: string;
  /** Product name to filter/search by. */
  productName?: string;
  ecosystem?: VulnerabilityEcosystemId;
  packageName?: string;
  version?: string;
  cveId?: string;
  limit?: number;
  /** When false, only the primary database is queried (no NVD/KEV enrichment). */
  includeOsint?: boolean;
  /** Optional watchlist item IDs to filter results to monitored products. */
  watchlistIds?: string[];
  /** Optional date filter: results from this date onward (ISO string). */
  fromDate?: string;
}

export type VulnerabilitySearchIntent = 'CVE' | 'PACKAGE' | 'KEYWORD';

/** One real-time web result returned by the live OSINT provider. */
export interface LiveOsintResult {
  title: string;
  /** Plain-text snippet; provider markup and entities are stripped server-side. */
  snippet: string;
  /** Direct deep link, restricted to HTTP(S) without embedded credentials. */
  url: string;
  /** Hostname of the link, used as the visible source domain. */
  domain: string;
  /** Domain spelling supplied by the provider (may include a subdomain). */
  displayLink: string | null;
  /** Publication timestamp when the result page exposes one. */
  publishedDate: string | null;
}

export type LiveOsintStatus = 'OK' | 'DISABLED' | 'NOT_CONFIGURED' | 'ERROR';

/**
 * Real-time web intelligence. This is kept separate from `results` because a
 * web hit is an investigative lead, not a normalized CVE record; merging it
 * into the vulnerability cards would misrepresent unverified pages as
 * authoritative advisories.
 */
export interface LiveOsintIntelligence {
  provider: 'Google Custom Search';
  status: LiveOsintStatus;
  /** Search phrase sent to the provider; null when the source was not queried. */
  query: string | null;
  results: LiveOsintResult[];
}

export interface VulnerabilitySearchResponse {
  results: VulnerabilitySearchResult[];
  totalResults: number;
  query: {
    text: string;
    ecosystem: string | null;
    packageName: string | null;
    version: string | null;
    cveId: string | null;
    intent: VulnerabilitySearchIntent;
  };
  sourcesQueried: VulnerabilitySource[];
  /** Real-time web results from the optional Google Custom Search integration. */
  liveOsint: LiveOsintIntelligence;
  /** Non-fatal source failures or input fallbacks, shown above the results. */
  warnings: string[];
  rateLimited: boolean;
  generatedAt: string;
}

/** Granularity for the analytics timeline buckets. */
export type TimelineBucket = 'day' | 'week' | 'month';

/** Selectable time windows for the Threat Analytics & Trends timeline. */
export type TimelineRange = '7d' | '30d' | '90d' | '365d' | 'all';

export interface TimelinePoint {
  label: string;
  cveCount: number;
  critical: number;
  high: number;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface ExploitStatusDistribution {
  activeWeaponized: number;
  reportedInWild: number;
  pocAvailable: number;
  none: number;
}

export interface VendorAnalytics {
  vendor: string;
  cveCount: number;
  critical: number;
  high: number;
}

export interface CveScoreBin {
  range: string;
  count: number;
}

export interface ThreatAnalytics {
  totalCves: number;
  kevCount: number;
  timeline: TimelinePoint[];
  severityDistribution: SeverityDistribution;
  exploitStatusDistribution: ExploitStatusDistribution;
  topVendors: VendorAnalytics[];
  cvssScoreHistogram: CveScoreBin[];
  generatedAt: string;
}

/** Classification tiers for the severity classifier. */
export type SeverityTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface SeverityClassification {
  tier: SeverityTier;
  score: number;
  vector: string;
  source: string;
  rationale: string[];
}

export interface CpeParseComponent {
  field: string;
  value: string;
  isWildcard: boolean;
  isAmbiguous: boolean;
}

export interface CpeParseResult {
  cpe: string;
  parsed: {
    prefix: string;
    part: string;
    vendor: string;
    product: string;
    version: string;
    update: string;
    edition: string;
    language: string;
    swEdition: string;
    targetSw: string;
    targetHw: string;
    other: string;
    raw: string;
    isValid: boolean;
  } | null;
  components: CpeParseComponent[];
  errors: string[];
}

export interface AliasExpansion {
  canonical: string;
  scope: 'VENDOR' | 'PRODUCT';
  matchedAliases: string[];
  builtInMatches: boolean;
  customMatches: boolean;
}

export interface FalsePositiveCheck {
  name: string;
  passed: boolean;
  severity: 'BLOCK' | 'WARN';
  detail: string;
}

export interface CpeMatchSimulation {
  assetCpe: CpeParseResult;
  vulnerabilityCpe: CpeParseResult;
  assetVendorAlias: AliasExpansion | null;
  assetProductAlias: AliasExpansion | null;
  match: {
    matched: boolean;
    method: string;
    confidence: number;
    viaAlias: boolean;
    evidence: string;
    reason?: string;
  };
  versionRangeCheck: {
    inRange: boolean;
    reason: string;
  } | null;
  falsePositiveChecks: FalsePositiveCheck[];
  severity: SeverityClassification | null;
}

export interface Advisory {
  id: string;
  title: string;
  severity: Severity;
  cveIds: string[];
  findingIds: string[];
  createdDate: string;
  deliveryStatus: 'ACCEPTED' | 'DELIVERED' | 'PENDING' | 'FAILED' | 'RETRYING' | 'DRAFT';
  recipientCount: number;
  executiveSummary: string;
  remediationInstructions: string;
  affectedSystems: string[];
  isDigestBatch?: boolean;
  vendorLink?: string;
  edits?: ReviewEdits;
}

export interface PipelinePhase {
  name: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'WARNING' | 'FAILED' | 'CANCELLED';
  durationMs: number;
  details: string;
  metrics?: Record<string, string | number>;
}

export interface PipelineExecution {
  id: string;
  /** Human-friendly label for this run, e.g. `Run 3add6860`. Absent on legacy rows. */
  name?: string;
  startTime: string;
  endTime: string | null;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'QUARANTINED' | 'CANCELLED';
  stopRequestedAt?: string;
  scopeHours: number;
  /** Use a successfully committed source checkpoint instead of rescanning the full lookback. */
  incrementalFeeds?: boolean;
  phases: PipelinePhase[];
  stats: {
    rawIngested: number;
    normalized: number;
    deduplicated: number;
    inRunDuplicatesDropped: number;
    /** Findings newly detected by this run, excluding matches already known from earlier runs. */
    matchedWatchlist: number;
    autoDispatchedNotifications: number;
    advisoriesDispatched: number;
    webhooksFired: number;
    vexSuppressedCount: number;
    notificationsQueued?: number;
    advisoriesQueued?: number;
    /**
     * How many times the recovery sweep has handed this run back as QUEUED.
     * Audit F-1: the count used to be derived from log lines, but the bounded
     * log cap could evict the marker and silently reset the poison-pill budget.
     * A structured counter survives eviction; older executions are still
     * counted via the historical marker for one deploy cycle.
     */
    recoveryAttempts?: number;
    /** Findings held for the digest window; they are queued by the delivery worker. */
    digestBuffered?: number;
    /** IntelligenceMatch records auto-sent to the Security team this run. */
    newsNotificationsQueued?: number;
    /** Unverifiable-match notifications queued to the Security team this run. */
    unverifiableNotificationsQueued?: number;
    /**
     * Consolidated zero-day digest emails queued to the Security team this run.
     * Digests replace the individual alerts the per-run cap withheld, so this
     * counter is how an operator confirms nothing was silently dropped.
     */
    zeroDayDigestNotificationsQueued?: number;
  };
  logs: string[];
}

export interface AlertedCVE {
  cveId: string;
  firstAlertedAt: string;
  lastAlertedAt: string;
  advisoryId: string;
  recipientEmails: string[];
  status: 'DISPATCHED' | 'SUPPRESSED';
  dispatchCount: number;
  lastDispatchReason?: string;
  lastDispatchKey?: string;
}

/** An operator-managed addition to the matching engine's vendor/product alias
 * thesaurus (see src/utils/cpeMatcher.ts DEFAULT_VENDOR_ALIASES/DEFAULT_PRODUCT_ALIASES
 * for the built-in, code-reviewed baseline this only adds on top of). */
export interface AliasEntry {
  id: string;
  /** Whether this maps vendor or product names. */
  scope: 'VENDOR' | 'PRODUCT';
  /** The normalized name a CVE's CPE/PURL vendor or product field actually uses. */
  canonical: string;
  /** Alternate names that should resolve to `canonical` during matching. */
  aliases: string[];
  notes?: string;
  createdAt: string;
  /** MANUAL rows are operator-managed. AUTO rows are derived from current
   * inventory/confirmed-correlation evidence and expire when that evidence
   * lapses. REVOKED rows are operator tombstones: they are never used for
   * matching and they block the automatic lifecycle from re-learning the
   * relation. */
  source?: 'MANUAL' | 'AUTO' | 'REVOKED';
  /** How an automatic relation was learned. Operator rows are `OPERATOR`. */
  provenance?: 'INVENTORY' | 'CONFIRMED_CORRELATION' | 'OPERATOR';
  /** First time the automatic relation was observed. */
  firstSeenAt?: string;
  /** Last time current inventory/correlation evidence supported the row. */
  lastSeenAt?: string;
  /** Automatic rows are retained until this time, then removed. */
  expiresAt?: string;
  /** Number of distinct confirmed findings supporting a learned relation. */
  evidenceCount?: number;
  /** Pairs blocked by an operator revocation. Only present on REVOKED rows. */
  revokedAliases?: string[];
  revokedAt?: string;
}

export interface EmailRecipient {
  id: string;
  name: string;
  email: string;
  role: string;
  /** Legacy recipients without a group continue to receive automatic delivery. */
  deliveryGroup?: 'SECURITY_TEAM' | 'EVERYONE';
  subscriptionTier: 'ALL_SEVERITIES' | 'CRITICAL_HIGH_ONLY' | 'CISA_KEV_ONLY';
  enabled: boolean;
  deliverySuccessRate: number;
  /** Opt a recipient into the daily digest (daily summary + health report) subscription. */
  dailyDigest?: boolean;
}

export interface WebhookEndpoint {
  id: string;
  name: string;
  url: string;
  provider: 'SLACK' | 'TEAMS' | 'GENERIC_HMAC';
  secretToken: string;
  enabled: boolean;
  events: ('CRITICAL' | 'CISA_KEV' | 'ALL')[];
  deliveryCount: number;
}

export interface WebhookDeliveryLog {
  id: string;
  endpointId: string;
  endpointName: string;
  provider: 'SLACK' | 'TEAMS' | 'GENERIC_HMAC';
  advisoryId: string;
  cveId: string;
  status: 'SUCCESS' | 'FAILED' | 'QUEUED';
  statusCode: number;
  hmacSignature: string;
  sentAt: string;
}

export interface EmailDeliveryLog {
  id: string;
  recipientEmail: string;
  advisoryId: string;
  subject: string;
  provider:
    'Mailtrap' | 'SendGrid' | 'Postmark' | 'Custom API' | 'SMTP_Relay' | 'Local_Mock' | 'Mailjet';
  status:
    | 'REVIEW_REQUIRED'
    | 'QUEUED'
    /** Attempt in flight: the transport has been (or is about to be) contacted. */
    | 'SENDING'
    | 'ACCEPTED'
    | 'DELIVERED'
    | 'BOUNCED'
    | 'RETRYING'
    | 'FAILED'
    | 'CANCELLED';
  attemptCount: number;
  retrySchedule: string[];
  nextRetryTime: string | null;
  sentAt: string;
  errorMessage?: string;
  /** Provider-assigned message id of the last attempt, when one was returned. */
  providerId?: string;
  /** Delay selected for the next retry, in milliseconds. */
  retryDelayMs?: number;
  /** Whether the operator policy or its ML recommendation selected the delay. */
  retryDelaySource?: 'OPERATOR' | 'ML' | 'ML_CAPPED' | 'PROVIDER_RETRY_AFTER';
  /**
   * Action Center follow-up state. Set to PENDING by the delivery worker when
   * the transport accepts a finding email, and moved to ACTIONED when an
   * operator acknowledges it or sends an updated copy.
   */
  actionStatus?: EmailActionStatus;
  /** When the operator action (acknowledge / update-and-send) was recorded. */
  actionedAt?: string;
  /** How many updated copies were dispatched from the Action Center. */
  followUpCount?: number;
  /**
   * True when the transport *provably rejected* the last attempt (HTTP 4xx/5xx
   * response, refused SMTP session, or missing configuration). Set by the
   * delivery worker instead of being inferred from the error text, so the
   * resend-withhold decision in confirmPriorDelivery never depends on a message
   * string that could drift (audit M-6).
   */
  transportRejected?: boolean;
}

export interface EmailQueueItem {
  id: string;
  recipientEmail: string;
  advisoryId: string;
  subject: string;
  status: 'REVIEW' | 'QUEUED' | 'SENDING' | 'FAILED';
  attempts: number;
  nextAttemptAt: string | null;
  createdAt: string;
  error: string | null;
  preview?: string;
  cveIds?: string[];
  edits?: ReviewEdits;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  category: 'PIPELINE' | 'SECURITY' | 'FEED' | 'WATCHLIST' | 'EMAIL' | 'WEBHOOK';
  level: 'INFO' | 'WARNING' | 'ERROR';
  event: string;
  details: string;
  actor: string;
  ipAddress: string;
  context?: {
    action?: string;
    resourceType?: string;
    resourceId?: string;
    requestId?: string;
    outcome: 'SUCCESS' | 'FAILURE' | 'DENIED' | 'RECORDED';
    fields?: string[];
  };
  prevHash: string;
  hash: string;
}

export const SMTP_EMAIL_PROVIDERS = [
  'SMTP_CUSTOM',
  'GMAIL_SMTP',
  'MAILEROO_SMTP',
  'LETTR_SMTP',
  'MAILJET_SMTP',
  'SENDGRID_SMTP',
] as const;
export const EMAIL_PROVIDERS = [
  'SMTP',
  'API',
  ...SMTP_EMAIL_PROVIDERS,
  'MAILTRAP',
  'SENDGRID',
  'POSTMARK',
  'MAILJET_API',
] as const;
export type EmailProvider = (typeof EMAIL_PROVIDERS)[number];
/**
 * `API` is its own case, not an SMTP relay: a custom API provider posts over
 * its configured endpoint, so treating it as SMTP let the delivery worker send
 * retries with the deployment SMTP transport while the queue reported it as a
 * successful accepted delivery.
 */
export const isSmtpEmailProvider = (provider: EmailProvider) =>
  provider === 'SMTP' || (SMTP_EMAIL_PROVIDERS as readonly string[]).includes(provider);
export interface EmailConfiguration {
  provider: EmailProvider;
  fromEmail: string;
  fromName: string;
  /** Optional reply-to address for operator feedback; omitted when blank. */
  replyTo?: string;
  /** Optional URL for the List-Unsubscribe header; defaults to a mailto link when blank. */
  unsubscribeUrl?: string;
  /** Encrypted in storage; always blank in browser state. */
  apiKey: string;
  hasApiKey?: boolean;
  /** Generic API transport settings. Secrets are encrypted in storage. */
  apiEndpoint: string;
  apiHeaderKey: string;
  apiAuthPrefix: string;
  apiSourceDomain: string;
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: 'IMPLICIT_TLS' | 'STARTTLS';
  smtpUsername: string;
  /** Encrypted in storage; always blank in browser state. */
  smtpPassword: string;
  hasSmtpPassword?: boolean;
  hasMailjetApiSecret?: boolean;
  mailtrapMode: 'LIVE' | 'SANDBOX';
  mailtrapInboxId: string;
  postmarkMessageStream: string;
  mailjetApiSecret: string;
}

export interface RetentionConfig {
  enabled: boolean;
  retentionHours: number;
  cleanupIntervalMinutes: number;
  maxArchivedRecords: number;
  autoCleanup: boolean;
  retentionMode: 'strict' | 'rolling' | 'checkpoints';
}

/** Record kinds the retention policy is allowed to delete. */
export type RetentionKind =
  | 'cveData'
  | 'intelligenceArticles'
  | 'intelligenceMatches'
  | 'zeroDayDigests'
  | 'emailLogs'
  | 'webhookLogs'
  | 'executions'
  | 'auditLogs'
  | 'events';

export interface RetentionRunResult {
  ranAt: string;
  mode: RetentionConfig['retentionMode'];
  retentionHours: number;
  cutoff: string;
  scanned: number;
  deleted: number;
  unknownAge: number;
  byKind: Record<RetentionKind, number>;
  /** Transient queue/event rows removed by the same policy window. */
  system?: { outbox: number; events: number };
}

export interface RetentionPreviewRow {
  total: number;
  past: number;
  deletable: number;
}

export interface RetentionPreview {
  cutoff: string;
  records: Record<RetentionKind, RetentionPreviewRow>;
  protected: { findings: number; advisories: number };
  scanned: number;
}

export interface CorrelationSimulationMatch {
  cve: NormalizedCVE;
  method: string;
  confidence: number;
  evidence: string;
  autoAction: string;
  suppressed: boolean;
  suppressionReason?: string;
}

/** Result of the read-only matching simulator. The server evaluates the full
 * CVE cache so the browser never has to download it to preview a match. */
export interface CorrelationSimulation {
  testedAt: string;
  matchedCves: CorrelationSimulationMatch[];
  totalScanned: number;
  aliasExpanded: boolean;
  intervalEvaluated: boolean;
}

export interface AppSettings {
  scopeHours: number;
  schedulerIntervalMinutes: number;
  schedulerEnabled: boolean;
  advisoryPrefix: string;
  autoDispatchEnabled: boolean;
  /**
   * Minimum confidence (0–100) required for a finding to auto-dispatch without
   * manual review. Set to 0 to dispatch all findings regardless of confidence.
   * The default (90) matches the previous hardcoded threshold.
   */
  autoDispatchConfidenceThreshold: number;
  reviewConfidenceThreshold?: number;
  /**
   * When true, unverifiable matches (whose version range cannot be confirmed)
   * participate in the confidence threshold instead of being held for review
   * unconditionally. Combined with autoDispatchConfidenceThreshold set to 0
   * this dispatches every finding automatically; the default (false) preserves
   * the conservative review-only hold for unverifiable matches.
   */
  autoDispatchUnverifiableMatches: boolean;
  /**
   * Retained for settings compatibility.
   *
   * News evidence (IntelligenceMatch records) matching the monitored inventory
   * is now always consolidated and sent to the Security team — one email per
   * run, with articles already delivered to a recipient removed. There is no
   * review-only holding of news.
   */
  autoDispatchNewsToSecurityTeam: boolean;
  /**
   * Retained for settings compatibility.
   *
   * Findings whose version range or applicability cannot be confirmed were
   * previously sent as a separate "for Review - Unverifiable matches" bulletin.
   * All findings are now dispatched in one consolidated email and each limited -
   * confidence finding states its confidence and the reason on the finding
   * itself. This flag no longer gates delivery.
   */
  reviewUnverifiableMatches: boolean;
  /**
   * When true, advisory emails are first delivered to the Security team group.
   * The same email is queued for the Everyone group only after a Security-team
   * delivery is confirmed ACCEPTED by the transport. Opt-in so existing
   * deployments keep their default simultaneous distribution.
   */
  deferEveryoneUntilSecurityDelivered: boolean;
  digestBatchingEnabled: boolean;
  digestWindowMinutes: number;
  /**
   * Durable retry policy for transient email transport failures. Retry is
   * enabled by default so a provider outage does not silently drop an alert.
   */
  emailRetryEnabled: boolean;
  /** Total delivery attempts, including the first send. */
  emailRetryMaxAttempts: number;
  /** Delay before the second attempt; doubles on each subsequent retry. */
  emailRetryInitialDelayMinutes: number;
  /** Upper bound for the exponential backoff delay. */
  emailRetryMaxDelayMinutes: number;
  /**
   * Master switch for all outbound email. When false, no advisory, digest,
   * news, self-healing, or test email is generated or sent by the delivery
   * worker. Provider configuration is left intact; only transport is blocked.
   */
  emailEnabled: boolean;
  webhookSigningSecret: string;
  authorityPrecedence: ('VENDOR_PSIRT' | 'CISA_KEV' | 'FIRST_EPSS' | 'NVD_BATCH')[];
  ssrfProtection: {
    blockPrivateIps: boolean;
    blockLoopback: boolean;
    allowRedirects: boolean;
  };
  securityPolicy: {
    sessionTimeoutMins: number;
    csrfProtection: boolean;
    minPasswordLen: number;
    maxLoginAttempts: number;
    lockoutMins: number;
    /** Days an automatically learned alias survives after its last supporting evidence. */
    autoAliasTtlDays: number;
  };
  /**
   * Operational logging detail level.
   *  - `standard`: lifecycle and security-relevant events only; the correlation
   *    worker's per-advisory telemetry is dropped at the source, so the table
   *    stays small and fast to search during an incident.
   *  - `verbose`: every correlation telemetry entry is persisted, including
   *    per-advisory extraction and database timings, for deep forensics.
   * Enforced server-side: selecting `standard` stops the rows being written at
   * all, rather than hiding them from the viewer after the fact.
   */
  logVerbosity: 'standard' | 'verbose';
  /**
   * Self-healing auto-recovery configuration.
   * When enabled, the worker tick monitors pipeline, scheduler, system, and
   * feed health. On issue detection, an alert is sent to the Security team
   * group, subject to a cooldown to prevent duplicate notifications.
   */
  selfHealing: {
    enabled: boolean;
    cooldownMinutes: number;
    emailNotifications: boolean;
  };
  ntpConfig: {
    enabled: boolean;
    server: string;
    driftToleranceMs: number;
  };
  retentionConfig: RetentionConfig;
  /**
   * IANA timezone identifier (e.g. `America/New_York`) used for scheduling the
   * daily digest and for formatting human-readable dates server-side and client-side.
   * Defaults to the runtime's local zone; an invalid value falls back to it at runtime.
   */
  timezone: string;
  /**
   * Daily digest subscription: a daily summary of findings plus an operational
   * health-check report sent to recipients that opt in, at `time` in `timezone`.
   */
  dailyDigest: {
    enabled: boolean;
    /** `HH:mm` 24h, e.g. `09:00`. */
    time: string;
    /** Include a server health-check snapshot in the daily report. */
    includeHealthReport: boolean;
  };
}

export interface SystemHealth {
  database: string;
  databaseLatencyMs: number;
  uptimeSeconds: number;
  heapBytes: number;
  workerEnabled: boolean;
  workerHeartbeat: string | null;
  workerStatus: 'DISABLED' | 'NOT_OBSERVED' | 'STALE' | 'HEALTHY';
  heartbeatAgeSeconds: number | null;
  deliveryQueue: {
    dueJobs: number;
    oldestDueCreatedAt: string | null;
    nextScheduledAttempt: string | null;
    expiredLeases: number;
  };
  lastScheduledRun: string | null;
  nextScheduledRun: string | null;
  schedulerEnabled: boolean;
  schedulerIntervalMinutes: number;
  backlog: { status: string; count: number }[];
  emailProvider: string;
  emailConfigured: boolean;
  httpsRequired: boolean;
  csrfEnforced: boolean;
  ssrfEnforced: boolean;
  ntp: string;
  checkedAt: string;
}
