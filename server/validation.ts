import { z } from 'zod';
import { FEED_TYPES, EMAIL_PROVIDERS, SMTP_EMAIL_PROVIDERS } from '../src/types/index.ts';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
export const shortText = z.string().trim().min(1).max(200);
export const idSchema = z
  .string()
  .min(1)
  .max(150)
  .refine((value) => !/[\u0000-\u001f\u007f]/.test(value), 'Identifier must not contain control characters');
const strings = z.array(z.string().max(2000)).max(100);
const httpsUrl = z
  .url()
  .max(2048)
  .refine((s) => {
    const u = new URL(s);
    return u.protocol === 'https:' && !u.username && !u.password;
  }, 'HTTPS URL without embedded credentials required');
const referenceUrl = z.union([
  z.literal(''),
  z
    .url()
    .max(2048)
    .refine((value) => {
      const url = new URL(value);
      return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password;
    }, 'HTTP(S) reference URL without embedded credentials required'),
]);
export const feedSchema = z
  .object({
    name: shortText,
    type: z.enum(FEED_TYPES),
    url: httpsUrl.refine(
      (s) =>
        !Array.from(new URL(s).searchParams.keys()).some((key) =>
          /token|password|passwd|secret|api.?key|access.?key|private.?key|signature|credential|(?:^|[_-])key(?:$|[_-])|(?:^|[_-])sig(?:$|[_-])/i.test(
            key,
          ),
        ),
      'Use the auth secret field rather than credentials in query parameters',
    ),
    authType: z.enum(['NONE', 'API_KEY', 'BEARER', 'BASIC']),
    authSecretKey: z.string().max(4096).optional(),
    rateLimitPerMin: z.number().int().min(1).max(600),
    requestTimeoutSeconds: z.number().int().min(5).max(120).optional(),
    recoveryDelayMinutes: z.number().int().min(1).max(60).default(5),
    enabled: z.boolean(),
    vendorSeed: z.boolean().default(false),
  })
  .refine(
    (feed) =>
      feed.type !== 'MITRE_CVE' ||
      (feed.authType === 'NONE' &&
        feed.url === 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json'),
    {
      message: 'MITRE CVE requires the official CVE List deltaLog.json URL and no authentication',
      path: ['url'],
    },
  )
  .refine(
    (feed) =>
      feed.type !== 'OTX_API' ||
      (feed.authType === 'API_KEY' &&
        feed.url === 'https://otx.alienvault.com/api/v1/pulses/subscribed/'),
    {
      message: 'AlienVault OTX requires its subscribed-pulses API endpoint and an API key',
      path: ['url'],
    },
  )
  .refine(
    (feed) =>
      feed.type !== 'OSV_API' ||
      (feed.authType === 'NONE' && feed.url === 'https://api.osv.dev/v1/querybatch'),
    {
      message: 'OSV requires the official querybatch API endpoint without authentication',
      path: ['url'],
    },
  )
  .refine(
    (feed) =>
      feed.type !== 'GITHUB_ADVISORIES' ||
      (feed.authType === 'NONE' && feed.url === 'https://api.github.com/advisories'),
    {
      message: 'GitHub advisories require the official global advisories endpoint without authentication',
      path: ['url'],
    },
  );
/** Bulk import shape: adds the stable identifier and the stored sync metadata. */
export const feedImportSchema = z
  .array(
    feedSchema.safeExtend({
      id: idSchema,
      lastSync: z.iso.datetime({ offset: true }).nullable().optional(),
      etag: z.string().max(200).optional(),
      itemCountLastRun: z.number().int().min(0).optional(),
      latencyMs: z.number().int().min(0).optional(),
    }),
  )
  .max(100);
// Wildcard vendor or product would match every CVE sharing the product
// string (or every CVE, if product is also wildcarded) in the correlation
// engine, defeating the specificity the matching pipeline relies on to avoid
// a false-positive flood. This mirrors the client-side check in
// src/utils/watchlist.ts's registrationAssetsFromCpes, which only runs on
// one of several save paths — this is the one check every save path passes
// through, so it's the authoritative guard.
const isNonWildcardCpe = (s: string) => {
  const parsed = parseCPE23(s);
  return parsed.isValid && !['*', '?', '-'].includes(parsed.vendor) && !['*', '?', '-'].includes(parsed.product);
};
const assetShape = z.object({
  vendor: shortText,
  product: shortText,
  version: z.string().max(100).optional(),
  cpes: z
    .array(
      z
        .string()
        .max(1000)
        .refine((s) => parseCPE23(s).isValid, 'Invalid CPE 2.3')
        .refine(isNonWildcardCpe, 'CPE must have a specific vendor and product, not a wildcard'),
    )
    .max(100),
  purls: z
    .array(
      z
        .string()
        .max(1000)
        .regex(/^pkg:[a-z][a-z0-9.+-]*\/.+/),
    )
    .max(100)
    .optional(),
  targetHw: z.string().max(100).optional(),
  assetTag: shortText,
  ownerGroup: shortText,
  active: z.boolean(),
  notes: z.string().max(4000).optional(),
});
export const assetSchema = assetShape.refine(
  (a) => a.cpes.length > 0 || !!a.purls?.length,
  'At least one CPE or PURL is required',
);
/** Bulk upsert shape for monitored inventory; keeps identifiers stable across reseeds. */
export const watchlistImportSchema = z
  .array(
    assetShape.extend({
      id: idSchema,
      createdAt: z.iso.datetime({ offset: true }).optional(),
      exposure: z.enum(['INTERNET_FACING', 'INTERNAL_CRITICAL', 'DMZ', 'LOW']).optional(),
    }),
  )
  .max(1000);
export const aliasSchema = z.object({
  scope: z.enum(['VENDOR', 'PRODUCT']),
  canonical: shortText.transform((s) => s.toLowerCase()),
  aliases: z
    .array(shortText.transform((s) => s.toLowerCase()))
    .min(1)
    .max(50)
    .refine((list) => new Set(list).size === list.length, 'Duplicate alias entries'),
  notes: z.string().max(500).optional(),
});
export const recipientSchema = z.object({
  name: shortText,
  email: z
    .email()
    .max(254)
    .transform((s) => s.toLowerCase()),
  role: shortText,
  deliveryGroup: z.enum(['SECURITY_TEAM', 'EVERYONE']).default('SECURITY_TEAM'),
  subscriptionTier: z.enum(['ALL_SEVERITIES', 'CRITICAL_HIGH_ONLY', 'CISA_KEV_ONLY']),
  enabled: z.boolean(),
  dailyDigest: z.boolean().default(false),
});
export const webhookSchema = z
  .object({
    name: shortText,
    url: httpsUrl,
    provider: z.enum(['SLACK', 'TEAMS', 'GENERIC_HMAC']),
    secretToken: z.string().max(4096).default(''),
    enabled: z.boolean(),
    events: z
      .array(z.enum(['CRITICAL', 'CISA_KEV', 'ALL']))
      .min(1)
      .max(3),
  })
  // A blank secret on an edit keeps the stored credential (see
  // commands.ts `webhook.save`), so it is only invalid when there is nothing to
  // keep: a brand-new Generic HMAC endpoint with no secret, or a secret too
  // short to sign with. `hasStoredSecret` is supplied by the caller that knows
  // whether a row already exists; validation alone cannot.
  .refine(
    (value) =>
      value.provider !== 'GENERIC_HMAC' ||
      value.secretToken.length === 0 ||
      value.secretToken.length >= 32,
    'Generic HMAC webhook secrets must be at least 32 characters',
  );
export const rangeSchema = z.object({
  versionStartIncluding: z.string().max(100).optional(),
  versionStartExcluding: z.string().max(100).optional(),
  versionEndIncluding: z.string().max(100).optional(),
  versionEndExcluding: z.string().max(100).optional(),
});
export const cveSchema = z.object({
  cveId: z
    .string()
    .max(150)
    .trim()
    .toUpperCase()
    .regex(/^CVE-\d{4}-\d{4,}$/),
  title: z.string().min(1).max(500),
  description: z.string().max(30000),
  publishedDate: z.iso.datetime({ offset: true }),
  modifiedDate: z.iso.datetime({ offset: true }),
  // CVSS payloads are persisted verbatim. The base `score` is the source of
  // truth for severity and is range-validated (fail-closed: a non-finite or
  // out-of-range score aborts the source run); vector strings are intentionally
  // NOT structurally validated at ingest, because NVD/MITRE vectors can be
  // partial or truncated and rejecting them would discard otherwise matching
  // intelligence. `cvssVectorIsValid` (server/cvss.ts) is an advisory validator
  // retained for tooling and tests; it is deliberately not a schema gate.
  cvss: z.object({
    version: z.enum(['3.0', '3.1', '4.0', '2.0', 'UNKNOWN']),
    score: z.number().min(0).max(10),
    vector: z.string().max(300),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']),
  }),
  cwe: strings,
  cpeMatches: z.array(z.string().refine((s) => parseCPE23(s).isValid)).max(1000),
  applicabilityRequiresReview: z.boolean().optional(),
  applicabilityPolicy: z.enum(['REVIEW_ONLY']).optional(),
  cpeMatchDetails: z
    .array(
      z.object({ criteria: z.string().refine((s) => parseCPE23(s).isValid), range: rangeSchema.optional() }),
    )
    .max(1000)
    .optional(),
  versionRange: rangeSchema.optional(),
  purls: strings.optional(),
  vex: z
    .object({
      status: z.enum(['affected', 'not_affected', 'fixed', 'under_investigation']),
      justification: z.string().max(4000).optional(),
      impactStatement: z.string().max(4000).optional(),
      source: z.string().max(300).optional(),
      scope: z
        .object({
          cpe: z.string().max(600).optional(),
          purl: z.string().max(600).optional(),
          vendor: z.string().max(200).optional(),
          product: z.string().max(200).optional(),
        })
        .optional(),
      signed: z.boolean().optional(),
      timestamp: z.iso.datetime({ offset: true }).optional(),
    })
    .optional(),
  vexStatements: z
    .array(
      z.object({
        status: z.enum(['affected', 'not_affected', 'fixed', 'under_investigation']),
        justification: z.string().max(4000).optional(),
        impactStatement: z.string().max(4000).optional(),
        source: z.string().max(300).optional(),
        scope: z
          .object({
            cpe: z.string().max(600).optional(),
            purl: z.string().max(600).optional(),
            vendor: z.string().max(200).optional(),
            product: z.string().max(200).optional(),
          })
          .optional(),
        signed: z.boolean().optional(),
        timestamp: z.iso.datetime({ offset: true }).optional(),
      }),
    )
    .max(100)
    .optional(),
  sourceFeeds: strings,
  epss: z.object({ score: z.number().min(0).max(1), percentile: z.number().min(0).max(1) }),
  cisaKev: z.object({
    isKev: z.boolean(),
    dateAdded: z.string().optional(),
    dueDate: z.string().optional(),
    requiredAction: z.string().max(4000).optional(),
    knownRansomwareCampaignUse: z.enum(['Known', 'Unknown']).optional(),
  }),
  exploitStatus: z.enum(['Active Weaponized', 'POC Available', 'Reported In Wild', 'None']),
  remediation: z.object({
    patchUrl: referenceUrl,
    vendorAdvisoryRef: referenceUrl,
    immediateActions: strings,
    workarounds: strings,
    rollbackPlan: z.string().max(4000),
    stepByStep: strings,
  }),
});
export const emailConfigSchema = z
  .object({
    provider: z.enum(EMAIL_PROVIDERS),
    fromEmail: z.union([z.email().max(254), z.literal('')]),
    fromName: z
      .string()
      .trim()
      .max(100)
      .regex(/^[^\r\n]*$/),
    replyTo: z
      .string()
      .trim()
      .max(254)
      .regex(/^[^\r\n]*$/)
      .default(''),
    unsubscribeUrl: z
      .string()
      .trim()
      .max(2048)
      .regex(/^[^\r\n]*$/)
      .default(''),
    apiKey: z
      .string()
      .trim()
      .max(4096)
      .regex(/^[^\r\n]*$/)
      .default(''),
    apiEndpoint: z.string().trim().max(2048).default(''),
    apiHeaderKey: z
      .string()
      .trim()
      .max(100)
      .regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/)
      .default('Authorization'),
    apiAuthPrefix: z
      .string()
      .trim()
      .max(40)
      .regex(/^[A-Za-z0-9._~-]*$/)
      .default('Bearer'),
    apiSourceDomain: z
      .string()
      .trim()
      .max(253)
      .regex(/^[a-zA-Z0-9.-]*$/)
      .default(''),
    smtpHost: z
      .string()
      .trim()
      .toLowerCase()
      .max(253)
      .regex(/^$|^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/)
      .default(''),
    smtpPort: z.number().int().min(1).max(65535).default(587),
    smtpSecurity: z.enum(['IMPLICIT_TLS', 'STARTTLS']).default('STARTTLS'),
    smtpUsername: z
      .string()
      .trim()
      .max(254)
      .regex(/^[^\r\n]*$/)
      .default(''),
    smtpPassword: z
      .string()
      .max(4096)
      .regex(/^[^\r\n]*$/)
      .default(''),
    mailtrapMode: z.enum(['LIVE', 'SANDBOX']),
    mailtrapInboxId: z
      .string()
      .max(20)
      .regex(/^$|^[1-9]\d*$/),
    postmarkMessageStream: z
      .string()
      .trim()
      .max(100)
      .regex(/^[a-zA-Z0-9_-]+$/),
    mailjetApiSecret: z
      .string()
      .trim()
      .max(4096)
      .regex(/^[^\r\n]*$/)
      .default(''),
  })
  .superRefine((value, ctx) => {
    if (value.provider !== 'SMTP' && !value.fromEmail)
      ctx.addIssue({ code: 'custom', path: ['fromEmail'], message: 'A verified sender email is required' });
    if ((SMTP_EMAIL_PROVIDERS as readonly string[]).includes(value.provider)) {
      if (!value.smtpHost)
        ctx.addIssue({ code: 'custom', path: ['smtpHost'], message: 'SMTP host is required' });
      const presetRequiresAuth = value.provider !== 'SMTP_CUSTOM';
      if (presetRequiresAuth && !value.smtpUsername)
        ctx.addIssue({ code: 'custom', path: ['smtpUsername'], message: 'SMTP username is required' });
    }
    if (value.provider === 'API') {
      if (!value.apiEndpoint)
        ctx.addIssue({ code: 'custom', path: ['apiEndpoint'], message: 'API endpoint is required' });
      if (value.apiEndpoint) {
        try {
          const endpoint = new URL(value.apiEndpoint.replaceAll('{domain}', 'source-domain'));
          if (
            endpoint.protocol !== 'https:' ||
            endpoint.username ||
            endpoint.password ||
            (endpoint.port && endpoint.port !== '443')
          )
            throw new Error('invalid endpoint');
        } catch {
          ctx.addIssue({
            code: 'custom',
            path: ['apiEndpoint'],
            message: 'Use an HTTPS URL on port 443 without URL credentials',
          });
        }
      }
      if (value.apiEndpoint.includes('{domain}') && !value.apiSourceDomain)
        ctx.addIssue({
          code: 'custom',
          path: ['apiSourceDomain'],
          message: 'Source / Domain is required when the endpoint contains {domain}',
        });
      if (
        [
          'content-type',
          'host',
          'content-length',
          'transfer-encoding',
          'connection',
          'user-agent',
          'accept',
          'accept-encoding',
        ].includes(value.apiHeaderKey.toLowerCase())
      )
        ctx.addIssue({ code: 'custom', path: ['apiHeaderKey'], message: 'This header name is reserved' });
    }
    if (value.provider === 'SMTP' && !value.smtpHost && (value.smtpUsername || value.smtpPassword))
      ctx.addIssue({
        code: 'custom',
        path: ['smtpHost'],
        message: 'Set an SMTP host to use custom SMTP credentials',
      });
    if (value.provider === 'MAILTRAP' && value.mailtrapMode === 'SANDBOX' && !value.mailtrapInboxId)
      ctx.addIssue({
        code: 'custom',
        path: ['mailtrapInboxId'],
        message: 'Mailtrap sandbox inbox ID is required',
      });
  });
export const settingsSchema = z
  .object({
    scopeHours: z.number().int().min(1).max(2880),
    schedulerIntervalMinutes: z.number().int().min(5).max(10080),
    schedulerEnabled: z.boolean(),
    advisoryPrefix: z.string().regex(/^[A-Za-z0-9_-]{1,30}$/),
    autoDispatchEnabled: z.boolean(),
    emailEnabled: z.boolean().default(true),
    autoDispatchConfidenceThreshold: z.number().int().min(0).max(100).default(90),
    reviewConfidenceThreshold: z.number().int().min(0).max(100).default(0),
    // Unverifiable matches are review-only by design. Opt-in releases them so the
    // confidence threshold governs them too — pair with a threshold of 0 to
    // auto-dispatch every finding.
    autoDispatchUnverifiableMatches: z.boolean().default(false),
    // News evidence auto-dispatch is opt-in so existing deployments keep their
    // review-only behavior for intelligence matches.
    autoDispatchNewsToSecurityTeam: z.boolean().default(false),
    reviewUnverifiableMatches: z.boolean().default(false),
    // Everyone-group recipients are held for operator review until a Security-team
    // delivery is confirmed accepted, then queued with the same payload for live
    // editing and approval. Opt-in: existing deployments keep simultaneous dispatch.
    deferEveryoneUntilSecurityDelivered: z.boolean().default(false),
    // Batch alert bursts by default; an explicit false remains an operator opt-out.
    digestBatchingEnabled: z.boolean().default(true),
    digestWindowMinutes: z.number().int().min(1).max(1440).default(5),
    // Retries are on by default; one attempt disables automatic retry while
    // keeping the initial delivery. Delays are bounded to avoid a runaway queue.
    emailRetryEnabled: z.boolean().default(true),
    emailRetryMaxAttempts: z.number().int().min(1).max(20).default(6),
    emailRetryInitialDelayMinutes: z.number().int().min(1).max(1440).default(1),
    emailRetryMaxDelayMinutes: z.number().int().min(1).max(10080).default(60),
    webhookSigningSecret: z.literal(''),
    authorityPrecedence: z.array(z.enum(['VENDOR_PSIRT', 'CISA_KEV', 'FIRST_EPSS', 'NVD_BATCH'])).max(4),
    ssrfProtection: z.object({
      blockPrivateIps: z.literal(true),
      blockLoopback: z.literal(true),
      allowRedirects: z.boolean().default(true),
    }),
    securityPolicy: z.object({
      sessionTimeoutMins: z.number().int().min(5).max(60).default(30),
      csrfProtection: z.literal(true),
      minPasswordLen: z.number().int().min(14).max(128).default(14),
      maxLoginAttempts: z.number().int().min(1).max(20).default(5),
      lockoutMins: z.number().int().min(1).max(60).default(15),
    }),
    // Defaults to 'standard' so an older client that omits the field cannot
    // silently switch an installation into high-volume forensic logging.
    logVerbosity: z.enum(['standard', 'verbose']).default('standard'),
    selfHealing: z
      .object({
        enabled: z.boolean().default(true),
        cooldownMinutes: z.number().int().min(1).max(1440).default(30),
        emailNotifications: z.boolean().default(true),
      })
      .default({ enabled: true, cooldownMinutes: 30, emailNotifications: true }),
    ntpConfig: z
      .object({
        enabled: z.literal(false),
        server: z.literal(''),
        driftToleranceMs: z.number().min(0).max(1000),
      })
      .default({ enabled: false, server: '', driftToleranceMs: 50 }),
    // Defaults keep settings stored before retention was configurable valid.
    retentionConfig: z
      .object({
        enabled: z.boolean(),
        retentionHours: z.number().int().min(1).max(8760),
        cleanupIntervalMinutes: z.number().int().min(1).max(1440),
        maxArchivedRecords: z.number().int().min(1000).max(1000000),
        autoCleanup: z.boolean(),
        retentionMode: z.enum(['strict', 'rolling', 'checkpoints']),
      })
      .default({
        enabled: false,
        retentionHours: 24,
        cleanupIntervalMinutes: 60,
        maxArchivedRecords: 10000,
        autoCleanup: true,
        retentionMode: 'rolling',
      }),
    timezone: z.string().min(1).max(100).default(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'),
    dailyDigest: z
      .object({
        enabled: z.boolean().default(true),
        time: z
          .string()
          .regex(/^([01]\d|2[0-3]):[0-5]\d$/)
          .default('09:00'),
        includeHealthReport: z.boolean().default(true),
      })
      .default({ enabled: true, time: '09:00', includeHealthReport: true }),
  })
  .superRefine((value, ctx) => {
    if (value.emailRetryMaxDelayMinutes < value.emailRetryInitialDelayMinutes)
      ctx.addIssue({
        code: 'custom',
        path: ['emailRetryMaxDelayMinutes'],
        message: 'Maximum backoff must be at least the initial backoff',
      });
  });
export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const templateSchema = z.object({
  fontFamily: z.enum(['sans', 'mono', 'serif', 'system']),
  fontColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  headingColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  accentColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  canvasBg: z.string().regex(/^#[0-9a-f]{6}$/i),
  cardBg: z.string().regex(/^#[0-9a-f]{6}$/i),
  headerBg: z.string().regex(/^#[0-9a-f]{6}$/i),
  badgeStampColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  badgeStampText: z.string().max(200),
  showStamp: z.boolean(),
  showClassificationBanner: z.boolean(),
  classificationText: z.string().max(300),
  borderStyle: z.enum(['solid', 'dashed', 'none']),
  borderRadius: z.string().regex(/^\d{1,3}(?:px|rem|%)$/),
});
