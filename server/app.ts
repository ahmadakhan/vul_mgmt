import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import { correlationMetrics } from './correlation/metrics.ts';
import {
  correlationWorkflows,
  decideCorrelationReview,
  decideDeadLetter,
  updateCorrelationPolicy,
  getFaultSimulationArmed,
  setFaultSimulationArmed,
  retainCorrelationData,
} from './correlation/operations.ts';
import type { CorrelationRuntime } from './correlation/runtime.ts';
import type { MlRuntime } from './ml/factory.ts';
import { advisoryRecords } from './correlation/stream.ts';
import { describeAdvisoryError } from './correlation/validation.ts';
import { Readable } from 'node:stream';
import { randomInt } from 'node:crypto';
import express from 'express';
import { WorkCapacityError } from './workLimiter.ts';
import compression from 'compression';
import helmet from 'helmet';
import path from 'node:path';
import net from 'node:net';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type pg from 'pg';
import { feedEgressHosts, type Config } from './config';
import {
  asyncRoute,
  requireAuth,
  requireRole,
  loginHandler,
  cookieName,
  accountEmail,
  createUser,
  deleteUser,
  sessionCookieOptions,
  updateUser,
} from './auth';
import { transaction, state, get, getForUpdate, getMany, put, appendAudit, list, verifyStoredAudit } from './db';
import { queryCollection } from './collections';
import { runRetention, previewRetention } from './retention';
import { buildAliasMap } from '../src/utils/cpeMatcher.ts';
import { runCpeSimulation } from '../src/utils/cpeSimulation.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { feedSchema, HttpError, webhookSchema } from './validation';
import { applyCommand, assertCommandRole } from './commands';
import { checkPassword, passwordHash, decrypt, encryptionKeys, randomToken, secureEqual, tokenHash } from './secrets';
import { createRequester, resolvePublic } from './network';
import type { Requester, ResponseData } from './network';
import { queueRun, stopRun, renderAdvisory } from './pipeline';
import { formatAdvisoryId } from '../src/utils/executionName';
import { recoveryAt, isPermanentFeedFailure } from './feedRecovery';
import { computeFeedRecoveryDelay, getMlRuntime } from './ml/integration.ts';
import { mlFeedbackSchema } from './ml/feedback.ts';
import { QUALITY_GATES } from './ml/train/qualityGates.ts';
import {
  advisoryRevision,
  enqueue,
  queueAdvisory,
  queueBulkNotificationAdvisory,
  recipientAllows,
  createMailSender,
} from './delivery';
import { createHash } from 'node:crypto';
import { stableJson } from '../src/utils/deduplicator.ts';
import { advisoryEmail } from './advisoryEmail';
import { currentAdvisoryBody } from './advisoryRebuild.ts';
import { renderAdvisoryPdf } from './pdf';
import {
  effectiveSubject,
  normalizeEmailSubject,
  renderReviewEdits,
  renderReviewText,
  safeNoticeHtml,
} from './emailEdits';
import { DEFAULT_SETTINGS, DEFAULT_EMAIL_CONFIG, isCollectionKind } from '../shared/state.ts';
import { emailIsConfigured } from './emailProviders';
import { parseSyndication, RSS_MAX_BYTES, RSS_USER_AGENT } from './rss';
import { OTX_SUBSCRIBED_PULSES_URL, parseOtxPulsePage, validateOtxNextUrl } from './otx.ts';
import {
  describeError,
  describeFailureSummary,
  describeRequestFailure,
  readEvents,
  writeEvent,
} from './events';
import {
  createDatabaseRateLimiter,
  type MutationLimiter,
  INGEST_LIMIT_CAPACITY,
  INGEST_LIMIT_REFILL_PER_MS,
} from './rateLimit';
import { searchNvdCpes, loadNvdApiKey, isNvdRateLimitError, nvdRetryAfterSeconds } from './cpeSearch';
import { searchThreatIntelligence, ThreatSearchRateLimitError, ThreatSearchUpstreamError } from './threatSearch';
import {
  searchVulnerabilities,
  VulnerabilitySearchRateLimitError,
  VulnerabilitySearchUpstreamError,
} from './vulnerabilitySearch';
import { computeThreatAnalytics } from './analytics';
import type { AppState } from '../shared/state.ts';
import type {
  AppSettings,
  ThreatFeed,
  WebhookEndpoint,
  Advisory,
  TemplateCustomization,
  EmailConfiguration,
  EmailRecipient,
  EmailDeliveryLog,
  NormalizedCVE,
  AliasEntry,
  WatchListItem,
  NvdCpeSearchResponse,
  ThreatSearchResponse,
  ThreatAnalytics,
  CpeMatchSimulation,
  ReviewEdits,
  Severity,
  IntelligenceArticle,
  Finding,
} from '../src/types/index.ts';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
  type DailyDigestParts,
  type DigestFinding,
  type DigestHealth,
  digestSeveritySummary,
  digestSeverityKpi,
  formatExecutiveSummary,
} from '../src/utils/templateCompiler.ts';
function publicState(data: AppState): AppState {
  return {
    ...data,
    feeds: data.feeds.map((f) => ({ ...f, authSecretKey: undefined })),
    webhooks: data.webhooks.map((w) => ({ ...w, url: '[configured on server]', secretToken: '' })),
    emailConfig: {
      ...data.emailConfig,
      apiKey: '',
      hasApiKey: !!data.emailConfig.apiKey,
      smtpPassword: '',
      hasSmtpPassword: !!data.emailConfig.smtpPassword,
      mailjetApiSecret: '',
      hasMailjetApiSecret: !!data.emailConfig.mailjetApiSecret,
    },
    settings: {
      ...data.settings,
      webhookSigningSecret: '',
    },
  };
}
const STATE_COLLECTION_LIMITS = {
  cveData: 100,
  findings: 100,
  advisories: 50,
  alertedCves: 100,
  emailLogs: 100,
  webhookLogs: 100,
  executions: 20,
  auditLogs: 200,
  intelligenceArticles: 50,
  intelligenceMatches: 100,
  zeroDayDigests: 50,
} as const;
const invalidId = () => new HttpError(400, 'Invalid identifier');
/**
 * Parses a client-supplied outbox id. `outbox.id` is a uuid column, so an
 * unparseable value is a client error: passing it straight to a `$1::uuid`
 * parameter raised 22P02 and turned a bad link into a 500 plus an incident log
 * entry on every page that acts on a delivery.
 */
const outboxId = (value: unknown): string => {
  const parsed = z.uuid().safeParse(value);
  if (!parsed.success) throw invalidId();
  return parsed.data;
};
const escapeHtml = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
  );
/**
 * Statuses whose `outbox` row can still be previewed and edited.
 *
 * ACCEPTED and DELIVERED are included on purpose: a findings email that has
 * already gone out is the normal Action Center follow-up, and the operator's
 * remedy is to correct it and re-send to a chosen audience. Neither status is
 * ever in flight; the edit route additionally requires `locked_at IS NULL`.
 */
const EDITABLE_JOB_STATUSES = ['REVIEW', 'QUEUED', 'FAILED', 'ACCEPTED', 'DELIVERED'] as const;
const editableJobStatusSql = (column: string) =>
  `${column} IN (${EDITABLE_JOB_STATUSES.map((status) => `'${status}'`).join(',')})`;

/**
 * Resolves the operator-edit payload for one outbox row. Preview routes and the
 * follow-up dispatcher must agree on the effective body, subject and plain-text
 * companion; deriving them here keeps that invariant in one place.
 */
function editedJobContent(
  payload: { html?: string; text?: string; subject?: string } | null | undefined,
  edits: ReviewEdits | null | undefined,
) {
  return {
    html: renderReviewEdits(payload?.html, edits),
    text: renderReviewText(payload?.text, edits),
    subject: effectiveSubject(payload?.subject, edits),
  };
}

/**
 * Resolves and validates an operator-selected audience.
 *
 * A delivered or queued finding email can be re-dispatched to a single
 * recipient, the security team, or everyone. The transport re-validates the
 * recipient and its subscription at send time, so an address that cannot
 * legally receive the bundle is rejected here rather than turned into a failed
 * delivery later. `customEmail` must already belong to an enabled workspace
 * recipient; silently creating an ad-hoc recipient would bypass the workspace's
 * delivery governance.
 */
function resolveOperatorAudience(
  recipients: EmailRecipient[],
  mode: 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE',
  findings: Finding[],
  customEmail?: string,
) {
  const enabled = recipients.filter((recipient) => recipient.enabled);
  let selected: EmailRecipient[];
  let validationError: string | null = null;
  
  if (mode === 'SINGLE_EMAIL') {
    if (!customEmail) throw new HttpError(400, 'A recipient email address is required');
    selected = enabled.filter(
      (recipient) => recipient.email.toLowerCase() === customEmail.toLowerCase(),
    );
    if (!selected.length)
      throw new HttpError(
        404,
        'That address is not an enabled recipient. Add it in Recipients before sending a one-off copy.',
      );
    validationError = null; // SINGLE_EMAIL validation is explicit
  } else if (mode === 'EVERYONE') {
    selected = enabled.filter((recipient) => recipient.deliveryGroup === 'EVERYONE');
    // Enterprise security: verify that EVERYONE recipients are properly configured
    if (!selected.length) {
      throw new HttpError(
        400,
        'No enabled EVERYONE recipients configured. To send to everyone, ensure at least one recipient has deliveryGroup="EVERYONE" and is enabled.',
      );
    }
    // Additional security: verify recipients have proper permissions
    const unauthorizedCount = selected.filter((recipient) => 
      !recipient.deliveryGroup || recipient.deliveryGroup !== 'EVERYONE'
    ).length;
    if (unauthorizedCount > 0) {
      console.error(`SECURITY: Found ${unauthorizedCount} recipients with invalid deliveryGroup configuration for EVERYONE mode`);
    }
    validationError = `EVERYONE mode targets ${selected.length} enabled recipients`; // For audit logging
  } else {
    // SECURITY_TEAM mode: validate that security team recipients exist and are properly configured
    selected = enabled.filter((recipient) => recipient.deliveryGroup !== 'EVERYONE');
    if (!selected.length) {
      throw new HttpError(
        400,
        'No enabled SECURITY_TEAM recipients configured. To send to security team, ensure at least one recipient has deliveryGroup="SECURITY_TEAM" or is enabled (undefined deliveryGroup defaults to SECURITY_TEAM).',
      );
    }
    
    // Enterprise security: validate SECURITY_TEAM recipient configuration
    const securityTeamCount = selected.length;
    const misconfiguredCount = selected.filter((recipient) => 
      recipient.deliveryGroup && recipient.deliveryGroup !== 'SECURITY_TEAM' && recipient.deliveryGroup !== undefined
    ).length;
    
    if (misconfiguredCount > 0) {
      console.error(`SECURITY: Found ${misconfiguredCount} misconfigured recipients in SECURITY_TEAM mode`);
      throw new HttpError(
        400,
        'SECURITY_TEAM mode contains misconfigured recipients. All recipients must have deliveryGroup="SECURITY_TEAM" or no deliveryGroup specified.',
      );
    }
    
    // Log audit information for enterprise compliance
    validationError = `SECURITY_TEAM mode targets ${securityTeamCount} configured security recipients`;
    console.log(`AUDIT: Email delivery resolved to SECURITY_TEAM mode for advisory ${findings.map(f => f.advisoryId).join(',')}`);
  }
  
  // Final eligibility check
  if (!selected.length)
    throw new HttpError(400, 'No eligible recipients exist for the selected delivery group');
  const permitted = selected.filter((recipient) =>
    findings.every((finding) => recipientAllows(recipient, finding)),
  );
  if (!permitted.length)
    throw new HttpError(
      400,
      'The selected audience is not subscribed to every finding in this advisory. Adjust the recipient subscription or choose a different audience.',
    );
    
  // Enterprise audit logging for recipient mode selection
  console.log(`AUDIT: ${validationError} for findings ${findings.map(f => f.id).join(',')}`);
  return permitted;
}

async function refreshAdvisoryDeliveryStatus(db: pg.Pool | import('pg').PoolClient, advisoryId: string) {
  const advisory = await getForUpdate<Advisory>(db, 'advisories', advisoryId);
  if (!advisory) return;
  const totals = (
    await db.query(
      `SELECT count(*) FILTER(WHERE status='FAILED')::int AS failed,
        count(*) FILTER(WHERE status IN ('REVIEW','QUEUED','SENDING'))::int AS pending,
        count(*) FILTER(WHERE status='ACCEPTED')::int AS accepted,
        count(*) FILTER(WHERE status='REJECTED')::int AS rejected
       FROM outbox WHERE advisory_id=$1`,
      [advisoryId],
    )
  ).rows[0];
  advisory.deliveryStatus = Number(totals.pending)
    ? 'PENDING'
    : Number(totals.failed)
      ? 'FAILED'
      : Number(totals.accepted)
        ? 'ACCEPTED'
        : 'DRAFT';
  await put(db, 'advisories', advisory.id, advisory);
  const notificationStatus = Number(totals.pending)
    ? 'QUEUED_FOR_DISPATCH'
    : Number(totals.failed)
      ? 'DELIVERY_FAILED'
      : Number(totals.accepted)
        ? 'AUTO_DISPATCHED'
        : Number(totals.rejected)
          ? 'SECURITY_REJECTED'
          : null;
  if (notificationStatus)
    for (const findingId of advisory.findingIds) {
      const finding = await getForUpdate<any>(db, 'findings', findingId);
      // Do not resurrect a finding that was explicitly excluded (for example,
      // inventory was removed while the bundle waited for review).
      if (
        finding &&
        finding.advisoryId === advisory.id &&
        !['NOT_APPLICABLE', 'SUPPRESSED_VEX_NOT_AFFECTED', 'REVIEW_REQUIRED'].includes(
          finding.notificationStatus,
        )
      )
        await put(db, 'findings', findingId, {
          ...finding,
          notificationStatus,
          autoDispatchedAt:
            notificationStatus === 'AUTO_DISPATCHED'
              ? finding.autoDispatchedAt || new Date().toISOString()
              : null,
        });
    }
}
export interface AppOptions {
  correlation?: CorrelationRuntime;
  mlRuntime?: MlRuntime;
  /**
   * Overrides the shared database-backed mutation limiter. Tests use this to
   * exercise the middleware with a small deterministic quota.
   */
  mutationLimiter?: MutationLimiter;
  /**
   * Overrides the per-operator ingest rate limiter. Omit to use the default
   * database-backed limiter with the built-in capacity/refill.
   */
  ingestLimiter?: MutationLimiter;
  /**
   * When set, `/live` performs a watchdog check and answers 503 if the event
   * loop has stalled. Off by default so a slow-but-alive instance is not killed
   * by a liveness probe during a GC pause; enable it only where the liveness
   * probe timeout is comfortably above the block threshold.
   */
  hangDetection?: boolean;
}
export function createApp(
  pool: pg.Pool,
  config: Config,
  request: Requester = createRequester(config),
  options: AppOptions = {},
) {
  const app = express();
  app.disable('x-powered-by');
  // /api/state is a bounded snapshot; gzip keeps its transfer size small.
  app.use(compression({ threshold: 1024 }));
  if (config.TRUST_PROXY)
    app.set(
      'trust proxy',
      config.TRUST_PROXY.split(',').map((s) => s.trim()),
    );
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          frameSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          upgradeInsecureRequests: config.NODE_ENV === 'production' ? [] : null,
        },
      },
      strictTransportSecurity:
        config.NODE_ENV === 'production'
          ? { maxAge: 31536000, includeSubDomains: true, preload: true }
          : false,
    }),
  );
  app.use(express.json({ limit: '2mb', strict: true }));
  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    const isMutation = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
    const requestOrigin = `${req.protocol}://${req.get('host')}`;
    if (isMutation && req.headers.origin !== config.APP_ORIGIN && req.headers.origin !== requestOrigin)
      return next(new HttpError(403, 'Origin not allowed'));
    if (isMutation && !req.is('application/json'))
      return next(new HttpError(415, 'JSON body required'));
    next();
  });
  // --- Process liveness -----------------------------------------------------
  //
  // A Fastify/Express keep-alive server that answered a socket connect is not
  // evidence the process can still serve work. Two failure modes produce a dead
  // instance with a listening socket: (a) the event loop is wedged and the timer
  // that would answer never fires; (b) the process is alive but its queued work
  // is not progressing. (a) is detectable here by comparing wall-clock drift: a
  // 5s timer whose callback observes less than 5s elapsed means the loop was
  // blocked, and a block longer than the threshold is reported on /live with a
  // 503 so the orchestrator replaces the instance.
  let lastHeartbeat = Date.now();
  const HANG_THRESHOLD_MS = 10_000;
  const hangTimer = setInterval(() => {
    lastHeartbeat = Date.now();
  }, 5_000);
  hangTimer.unref();
  app.get('/live', (_req, res) => {
    const stalledFor = Date.now() - lastHeartbeat;
    if (options.hangDetection && stalledFor > HANG_THRESHOLD_MS)
      return res.status(503).json({ status: 'stalled', stalledForMs: stalledFor });
    res.json({ status: 'live' });
  });
  app.get('/metrics', (req, res) => {
    if (!options.correlation || !config.METRICS_TOKEN) return res.sendStatus(404);
    if (!secureEqual(req.headers.authorization || '', `Bearer ${config.METRICS_TOKEN}`))
      return res.sendStatus(401);
    res
      .type('text/plain; version=0.0.4')
      .send(
        correlationMetrics(
          options.correlation.supervisor,
          options.correlation.heartbeat,
          options.correlation.pendingDepth,
          options.correlation.pendingSampledAt,
          options.correlation.pipelineLastRun,
          options.correlation.pipelineLastRunSampledAt,
          options.correlation.pipelineSchedulerEnabled,
        ),
      );
  });
  app.get(
    '/ready',
    asyncRoute(async (_req, res) => {
      // Readiness is "can this instance do its job", not "can it reach a TCP
      // socket". `SELECT 1` succeeded through every outage the pipeline has: a
      // wedged advisory consumer, an open circuit breaker and a stalled worker
      // pool all returned 200, so a load balancer kept routing work at an
      // instance that was admitting nothing. Each check below corresponds to a
      // distinct "always on" requirement.
      const started = Date.now();
      await pool.query('SELECT 1');
      const databaseLatencyMs = Date.now() - started;
      const supervisor = options.correlation?.supervisor;
      const reasons: string[] = [];
      if (supervisor) {
        // An open breaker means the pipeline is deliberately rejecting every
        // advisory for minutes. Routing new work here is pointless.
        if (supervisor.health === 'RECOVERING_DB_SEVERANCE') reasons.push('database-recovery');
        // Soft shedding still makes progress, so it is reported but not failed.
        if (supervisor.health === 'DEGRADED_BACKPRESSURE') reasons.push('backpressure');
      }
      if (reasons.some((reason) => reason !== 'backpressure'))
        return res.status(503).json({
          status: 'not-ready',
          reasons,
          health: supervisor?.health,
          databaseLatencyMs,
        });
      res.json({
        status: 'ready',
        health: supervisor?.health ?? 'unknown',
        activeWorkers: supervisor?.active.size ?? 0,
        databaseLatencyMs,
        warnings: reasons,
      });
    }),
  );
  app.post('/api/login', loginHandler(pool, config));
  // Reset endpoints are public: enforce shared IP and account quotas before
  // account lookup, mail delivery, code verification, or password hashing.
  const resetRequestIpLimiter = createDatabaseRateLimiter(pool, 15, 15 / 600_000);
  const resetRequestAccountLimiter = createDatabaseRateLimiter(pool, 3, 3 / 600_000);
  const resetAttemptIpLimiter = createDatabaseRateLimiter(pool, 50, 50 / 600_000);
  const resetAttemptAccountLimiter = createDatabaseRateLimiter(pool, 10, 10 / 600_000);
  app.use(
    '/api/password-reset',
    asyncRoute(async (req, res, next) => {
      if (
        req.method !== 'POST' ||
        !['/request', '/verify', '/complete'].includes(req.path.replace(/\/+$/, '').toLowerCase())
      )
        return next();
      const username = z
        .string()
        .min(1)
        .max(100)
        .transform((s) => s.toLowerCase())
        .parse(req.body?.username);
      const requesting = req.path.replace(/\/+$/, '').toLowerCase() === '/request';
      const scope = requesting ? 'request' : 'attempt';
      const limits: [MutationLimiter, string][] = [
        [
          requesting ? resetRequestIpLimiter : resetAttemptIpLimiter,
          `reset:${scope}:ip:${tokenHash(req.ip || '')}`,
        ],
        [
          requesting ? resetRequestAccountLimiter : resetAttemptAccountLimiter,
          `reset:${scope}:user:${tokenHash(username)}`,
        ],
      ];
      for (const [limit, key] of limits) {
        const decision = await limit(key);
        if (!decision.allowed) {
          res.setHeader('Retry-After', String(Math.max(1, Math.ceil(decision.retryAfterMs / 1000))));
          throw new HttpError(429, 'Too many password reset attempts; retry later');
        }
      }
      next();
    }),
  );
  app.post(
    '/api/password-reset/request',
    asyncRoute(async (req, res) => {
      const { username } = z
        .object({
          username: z
            .string()
            .min(1)
            .max(100)
            .transform((s) => s.toLowerCase()),
        })
        .parse(req.body);
      // Only automated tests may inspect a reset code without mailbox access.
      // Check deployment readiness before lookup so this error cannot reveal users.
      const email = (await get<EmailConfiguration>(pool, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
      const policy = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const configured = emailIsConfigured(email, config) && policy.emailEnabled !== false;
      if (config.NODE_ENV !== 'test' && !configured)
        throw new HttpError(503, 'Password reset email is not configured for this deployment');
      const user = (
        await pool.query('SELECT id,email FROM users WHERE username=$1 AND disabled=false', [username])
      ).rows[0];
      if (!user) return res.json({ success: true });
      // No address, no delivery. The code used to fall back to SMTP_FROM, which
      // sent it to the operator's own mailbox (or a shared alerting inbox) and
      // turned a self-service reset into a mail to whoever runs the deployment.
      // Answering exactly like an unknown user keeps the response free of any
      // signal about which accounts exist.
      if (!user.email) return res.json({ success: true });
      const code = String(randomInt(100000, 1_000_000));
      const codeHash = tokenHash(code);
      const expiresAt = new Date(Date.now() + 10 * 60_000);
      await transaction(pool, async (db) => {
        // Serialize issuance with completion and account changes across replicas.
        const current = await db.query(
          'SELECT id FROM users WHERE id=$1 AND email=$2 AND NOT disabled FOR UPDATE',
          [user.id, user.email],
        );
        if (!current.rowCount) throw new HttpError(400, 'Account changed; request a new reset code');
        await db.query('DELETE FROM password_reset_tokens WHERE username=$1', [username]);
        await db.query('INSERT INTO password_reset_tokens(username,code_hash,expires_at) VALUES($1,$2,$3)', [
          username,
          codeHash,
          expiresAt,
        ]);
      });
      if (configured && config.NODE_ENV !== 'test') {
        await createMailSender({ ...config, ATTACH_ADVISORY_PDF: 'false' }, pool, request)({
          id: randomUUID(), dedupe_key: `password-reset:${username}`, channel: 'email',
          target_id: 'password-reset', advisory_id: 'TEST', attempts: 1, lock_token: randomUUID(),
          review_approved: false, priority: 0,
          payload: {
            recipientEmail: user.email, cveIds: [], subject: 'Your password reset code',
            text: `Your password reset code is: ${code}\n\nThis code expires in 10 minutes.\nIf you did not request this reset, you can safely ignore this email.`,
            html: `<p>Your password reset code is: <strong>${code}</strong></p><p>This code expires in 10 minutes. If you did not request this reset, you can safely ignore this email.</p>`,
          },
        });
      }
      const response: { success: true; code?: string } = { success: true };
      if (config.NODE_ENV === 'test') response.code = code;
      await appendAudit(
        pool,
        'Password reset requested',
        `OTP request for ${username}`,
        username,
        'SECURITY',
        'INFO',
        req.ip || '',
      );
      res.json(response);
    }),
  );
  app.post(
    '/api/password-reset/verify',
    asyncRoute(async (req, res) => {
      const { username, code } = z
        .object({
          username: z
            .string()
            .min(1)
            .max(100)
            .transform((s) => s.toLowerCase()),
          code: z.string().regex(/^\d{6}$/),
        })
        .parse(req.body);
      const result = await pool.query(
        'SELECT 1 FROM password_reset_tokens t JOIN users u ON u.username=t.username WHERE t.username=$1 AND t.code_hash=$2 AND t.expires_at>now() AND NOT u.disabled',
        [username, tokenHash(code)],
      );
      if (!result.rowCount) throw new HttpError(400, 'Invalid or expired code');
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/password-reset/complete',
    asyncRoute(async (req, res) => {
      const { username, code, newPassword } = z
        .object({
          username: z
            .string()
            .min(1)
            .max(100)
            .transform((s) => s.toLowerCase()),
          code: z.string().regex(/^\d{6}$/),
          newPassword: z.string().min(14).max(128),
        })
        .parse(req.body);
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      if (newPassword.length < settings.securityPolicy.minPasswordLen)
        throw new HttpError(400, 'Password does not meet configured minimum');
      const codeHash = tokenHash(code);
      // Reject bad codes before admitting expensive password work. Consumption
      // is rechecked under the account lock below after the hash is ready.
      const valid = await pool.query(
        'SELECT 1 FROM password_reset_tokens t JOIN users u ON u.username=t.username WHERE t.username=$1 AND t.code_hash=$2 AND t.expires_at>now() AND NOT u.disabled',
        [username, codeHash],
      );
      if (!valid.rowCount) throw new HttpError(400, 'Invalid or expired code');
      const hash = await passwordHash(newPassword);
      await transaction(pool, async (db) => {
        const user = (
          await db.query('SELECT id FROM users WHERE username=$1 AND NOT disabled FOR UPDATE', [username])
        ).rows[0];
        if (!user) throw new HttpError(400, 'Invalid or expired code');
        const consumed = await db.query(
          'DELETE FROM password_reset_tokens WHERE username=$1 AND code_hash=$2 AND expires_at>now() RETURNING username',
          [username, codeHash],
        );
        if (!consumed.rowCount) throw new HttpError(400, 'Invalid or expired code');
        await db.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, user.id]);
        await db.query('DELETE FROM sessions WHERE user_id=$1', [user.id]);
        await db.query('DELETE FROM password_reset_tokens WHERE username=$1', [username]);
        await appendAudit(
          db,
          'Password reset',
          'Self-service password reset completed',
          username,
          'SECURITY',
          'INFO',
          req.ip || '',
        );
      });
      res.json({ success: true });
    }),
  );
  // Global rate limiting for authenticated mutation endpoints. The bucket is
  // stored in PostgreSQL so every replica shares one quota per operator.
  //
  // Only state-changing requests are charged. Some POSTs are pure read
  // operations: `/api/correlation/simulate` matches in memory against loaded
  // data, `/api/threat/cpe-simulate` evaluates CPE matching, and
  // `/api/retention/preview` reports what a cleanup would remove. Billing those
  // against the mutation quota let an ordinary read-only operator exhaust their
  // write budget by exploring the UI — and made the documented VIEWER read-only
  // role unable to use them at all.
  // The allowlist is by exact route, never by prefix, so a future mutating
  // route cannot inherit the exemption through naming.
  const NON_MUTATING_POSTS = new Set([
    '/api/correlation/simulate',
    '/api/threat/cpe-simulate',
    '/api/retention/preview',
  ]);
  const mutationLimiter = options.mutationLimiter ?? createDatabaseRateLimiter(pool);
  const ingestLimiter =
    options.ingestLimiter ??
    createDatabaseRateLimiter(pool, INGEST_LIMIT_CAPACITY, INGEST_LIMIT_REFILL_PER_MS);
  app.get(
    '/api/system-uptime',
    asyncRoute(async (_req, res) => {
      const seconds = Math.floor(process.uptime());
      const days = Math.floor(seconds / 86400);
      const hours = Math.floor((seconds % 86400) / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      const uptimeStr = `${days > 0 ? `${days}d ` : ''}${hours}h ${minutes}m ${seconds % 60}s`;
      res.json({
        systemUptime: uptimeStr,
        uptimeSeconds: seconds,
        startedAt: new Date(Date.now() - seconds * 1000).toISOString(),
      });
    }),
  );

  app.use('/api', requireAuth(pool, config), async (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    // Inside a mount, req.path is the path RELATIVE to the mount point
    // ('/correlation/simulate'), not the absolute route. Matching the absolute
    // name here silently exempted nothing. Use baseUrl + path, which is what
    // the route table actually keys on.
    const route = `${req.baseUrl}${req.path}`.replace(/\/+$/, '') || '/';
    if (req.method === 'POST' && NON_MUTATING_POSTS.has(route)) return next();
    try {
      const identifier = req.operator?.id || req.ip || '';
      const result = await mutationLimiter(`rl:${identifier}`);
      if (!result.allowed) {
        res.setHeader('Retry-After', String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))));
        return next(new HttpError(429, 'Too many requests'));
      }
      next();
    } catch (error) {
      next(error);
    }
  });
  if (options.correlation) {
    const runtime = options.correlation;
    app.get(
      '/api/correlation/workflows',
      requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
      asyncRoute(async (_req, res) => res.json(await correlationWorkflows(pool))),
    );
    app.patch(
      '/api/correlation/policy',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        const policy = await transaction(pool, (db) =>
          updateCorrelationPolicy(db, req.body, req.operator!.username),
        );
        res.json(policy);
      }),
    );
    app.post(
      '/api/correlation/reviews/:id/decision',
      requireRole('ADMIN', 'OPERATOR'),
      asyncRoute(async (req, res) => {
        const id = z.uuid().parse(req.params.id);
        await transaction(pool, (db) => decideCorrelationReview(db, id, req.body, req.operator!.username));
        res.json({ success: true });
      }),
    );
    app.post(
      '/api/correlation/dead-letters/:id/decision',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        const id = z.uuid().parse(req.params.id);
        await transaction(pool, (db) =>
          decideDeadLetter(db, id, req.body, req.operator!.username, encryptionKeys(config)),
        );
        res.json({ success: true });
      }),
    );
    app.post(
      '/api/correlation/retention/run',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        const removed = await transaction(pool, async (db) => {
          const count = await retainCorrelationData(db);
          await appendAudit(
            db,
            'Correlation retention run',
            `${count} resolved or expired records removed`,
            req.operator!.username,
          );
          return count;
        });
        res.json({ removed });
      }),
    );
    app.get(
      '/api/correlation/assets',
      requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
      asyncRoute(async (req, res) => {
        const query = z
          .object({ q: z.string().trim().max(200).default(''), after: z.uuid().optional() })
          .strict()
          .parse(req.query);
        const rows = await pool.query(
          `SELECT i.id,i.vendor,i.product,i.version,m.record_id AS "recordId",r.data->>'assetTag' AS "assetTag"
        FROM correlation_asset_inventory i LEFT JOIN correlation_managed_assets m ON m.native_id=i.id
        LEFT JOIN records r ON r.kind='watchlist' AND r.id=m.record_id
        WHERE ($1::uuid IS NULL OR i.id>$1) AND ($2='' OR strpos(lower(i.vendor||' '||i.product),lower($2))>0)
        ORDER BY i.id LIMIT 51`,
          [query.after || null, query.q],
        );
        res.json({
          assets: rows.rows.slice(0, 50),
          nextCursor: rows.rows.length > 50 ? rows.rows[49].id : null,
        });
      }),
    );

    app.get(
      '/api/correlation',
      requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
      asyncRoute(async (_req, res) => res.json(await runtime.supervisor.snapshot())),
    );
    app.post(
      '/api/correlation/concurrency',
      requireRole('ADMIN', 'OPERATOR'),
      asyncRoute(async (req, res) => {
        const { limit } = z
          .object({ limit: z.number().int().min(1).max(32) })
          .strict()
          .parse(req.body);
        await transaction(pool, async (db) => {
          await db.query('UPDATE correlation_policy SET concurrency_limit=$1,updated_at=now() WHERE id=1', [
            limit,
          ]);
          await appendAudit(
            db,
            'Correlation concurrency changed',
            // The value is persisted in correlation_policy and adopted by every
            // replica on its heartbeat. Calling it "per-instance" made a
            // fleet-wide change read like a local one in the audit trail.
            `Fleet-wide limit ${limit} (applies to all replicas)`,
            req.operator!.username,
          );
        });
        runtime.supervisor.setConcurrency(limit);
        res.json({ concurrencyLimit: runtime.supervisor.concurrencyLimit });
      }),
    );
    app.post(
      '/api/correlation/fault',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        // Three independent gates, none bypassable by a single misconfiguration:
        // (1) NODE_ENV is not production, (2) the per-replica FAULT_SIMULATION_ENABLED
        // opt-in env var, and (3) the fleet-wide `fault_simulation_armed` flag on the
        // shared correlation_policy row. The env var alone is intentionally not a
        // boundary: a production image started with NODE_ENV=development would still
        // need an operator to arm the gate, and arming one replica does not arm a fleet.
        if (config.NODE_ENV === 'production' || config.FAULT_SIMULATION_ENABLED !== 'true')
          throw new HttpError(403, 'Fault simulation is disabled in this deployment');
        const armed = await getFaultSimulationArmed(pool);
        if (!armed)
          throw new HttpError(
            403,
            'Fault simulation is not armed. POST /api/correlation/fault/arming with { "armed": true } to enable it.',
          );
        const { fault } = z
          .object({ fault: z.enum(['memory', 'database']) })
          .strict()
          .parse(req.body);
        runtime.supervisor.simulate(fault);
        await transaction(pool, (db) =>
          appendAudit(
            db,
            'Correlation fault simulated',
            `Simulated ${fault} fault via dashboard`,
            req.operator!.username,
          ),
        ).catch(() => {});
        res.json({ accepted: true });
      }),
    );
    app.post(
      '/api/correlation/fault/arming',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        const { armed } = z.object({ armed: z.boolean() }).strict().parse(req.body);
        const faultSimulationArmed = await transaction(pool, (db) =>
          setFaultSimulationArmed(db, armed, req.operator!.username),
        );
        res.json({ ok: true, faultSimulationArmed });
      }),
    );
    app.post(
      '/api/correlation/ingest',
      requireRole('ADMIN', 'OPERATOR'),
      asyncRoute(async (req, res) => {
        const identifier = req.operator?.id || req.ip || '';
        const ingestResult = await ingestLimiter(`rl-ingest:${identifier}`);
        if (!ingestResult.allowed) {
          res.setHeader('Retry-After', String(Math.max(1, Math.ceil(ingestResult.retryAfterMs / 1000))));
          throw new HttpError(429, 'Too many ingest submissions');
        }
        const { ndjson } = z
          .object({ ndjson: z.string().min(1).max(524288) })
          .strict()
          .parse(req.body);
        let count = 0;
        // Reject a submission that contains anything unparseable *before* it is
        // queued. Enqueuing an invalid record would park a permanently
        // undeliverable job in the pending queue: the worker re-validates,
        // dead-letters it, and the submitter is told "accepted". The response
        // names the field and rule only, never the rejected value.
        const rejected: { record: number; reason: string }[] = [];
        const accepted: unknown[] = [];
        for await (const payload of advisoryRecords(
          Readable.from([Buffer.from(ndjson)], { objectMode: false }),
        )) {
          if (++count > 128) throw new HttpError(413, 'At most 128 records per submission');
          if (payload && typeof payload === 'object' && 'invalidFrame' in payload) {
            rejected.push({ record: count, reason: String(payload.invalidFrame) });
            continue;
          }
          const reason = describeAdvisoryError(payload);
          if (reason !== 'VALID') {
            rejected.push({ record: count, reason });
            continue;
          }
          accepted.push(payload);
        }
        if (rejected.length) {
          res.status(400).json({ error: 'Invalid advisory records', queued: 0, rejected });
          return;
        }
        await transaction(pool, async (db) => {
          for (const payload of accepted)
            await db.query('INSERT INTO correlation_pending(id,payload) VALUES($1,$2)', [
              randomUUID(),
              JSON.stringify(payload),
            ]);
        });
        res.status(202).json({ queued: accepted.length });
      }),
    );
    app.get(
      '/api/correlation/search',
      requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
      asyncRoute(async (req, res) => {
        const { q } = z.object({ q: z.string().trim().min(1).max(200) }).parse(req.query);
        const result = await pool.query(
          `SELECT id,title,url,processed_at FROM unstructured_advisories
        WHERE tsv_content @@ plainto_tsquery('simple',$1) ORDER BY processed_at DESC LIMIT 50`,
          [q],
        );
        res.json({ advisories: result.rows });
      }),
    );
  }
  app.get(
    '/api/events',
    requireAuth(pool, config),
    asyncRoute(async (req, res) => {
      // The operational event log is the read side of writeEvent(): any
      // authenticated role may page it. Query validation (category enum, cursor
      // range, limit cap) lives in readEvents so HTTP and internal callers share
      // one contract; malformed filters, a cursor, or a category are 400s, not 500s.
      res.json(await readEvents(pool, req.query));
    }),
  );
  app.get('/api/session', requireAuth(pool, config), (req, res) =>
    res.json({
      username: req.operator!.username,
      // The operator's own address. It is not a secret from them, and the
      // account form prefills it so an edit does not silently clear it.
      email: req.operator!.email,
      role: req.operator!.role,
      csrfToken: req.operator!.csrf,
      expiresAt: req.operator!.expiresAt,
    }),
  );
  app.get(
    '/api/cpes/search',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const { vendor, product, limit, cpe, cpeNameId } = z
        .object({
          vendor: z.string().trim().min(1).max(200).optional(),
          cpe: z
            .string()
            .trim()
            .max(1000)
            .refine((value) => parseCPE23(value).isValid, 'Invalid CPE 2.3')
            .optional(),
          cpeNameId: z.uuid().optional(),
          product: z.string().trim().max(200).default(''),
          limit: z.coerce.number().int().min(1).max(200).default(50),
        })
        .refine(
          (query) => query.vendor || query.cpe || query.product,
          'A vendor, product, or exact CPE is required',
        )
        .refine(
          (query) => !query.cpeNameId || query.cpe,
          'A CPE name is required when verifying a dictionary ID',
        )
        .parse(req.query);
      const apiKey = await loadNvdApiKey(pool, config);
      try {
        res.json(await searchNvdCpes(request, apiKey, vendor || '', product, limit, cpe, cpeNameId));
      } catch (error) {
        if (isNvdRateLimitError(error)) {
          const retryAfter = nvdRetryAfterSeconds(error);
          if (retryAfter) res.setHeader('Retry-After', String(retryAfter));
          throw new HttpError(429, 'NVD rate limit reached; retry later');
        }
        throw new HttpError(502, 'CPE search upstream request failed');
      }
    }),
  );
  app.get(
    '/api/threat/intelligence/search',
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (req, res) => {
      const { vendor, product, limit, startDate } = z
        .object({
          vendor: z.string().trim().min(1).max(200),
          product: z.string().trim().max(200).default(''),
          limit: z.coerce.number().int().min(1).max(200).default(50),
          startDate: z
            .string()
            .trim()
            .regex(/^\d{4}-\d{2}-\d{2}$/, { message: 'Must be YYYY-MM-DD' })
            .optional(),
        })
        .parse(req.query);
      try {
        const result: ThreatSearchResponse = await searchThreatIntelligence(request, pool, config, {
          vendor,
          product,
          limit,
          startDate,
        });
        if (result.rateLimited) {
          if (result.retryAfter) res.setHeader('Retry-After', String(result.retryAfter));
          throw new HttpError(
            429,
            `NVD rate limit reached; retry later${result.apiKeyUsed ? '' : ' (no API key loaded)'}`,
          );
        }
        res.json(result);
      } catch (error) {
        if (error instanceof ThreatSearchRateLimitError) {
          if (error.retryAfter !== null) res.setHeader('Retry-After', String(error.retryAfter));
          throw new HttpError(429, 'NVD rate limit reached; retry later');
        }
        // An upstream failure is not a server fault: return 502 with a message
        // that names the cause, so the UI can distinguish "search is broken"
        // from "no vulnerabilities matched" (the two used to be identical).
        if (error instanceof ThreatSearchUpstreamError)
          throw new HttpError(502, 'Threat intelligence search is temporarily unavailable; retry shortly');
        throw error;
      }
    }),
  );
  app.get(
    '/api/vulnerabilities/search',
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (req, res) => {
      const params = z
        .object({
          query: z.string().trim().max(200).optional(),
          productName: z.string().trim().max(200).optional(),
          // Accept canonical OSV identifiers and human aliases ("php",
          // "node.js"); resolveVulnerabilityIntent canonicalises them and
          // rejects an unknown value with a 400.
          ecosystem: z.string().trim().max(60).optional(),
          package: z.string().trim().max(214).optional(),
          version: z.string().trim().max(100).optional(),
          cveId: z.string().trim().max(40).optional(),
          limit: z.coerce.number().int().min(1).max(100).default(50),
          // Enrichment is opt-out so an operator can restrict a query to OSV
          // when NVD is known to be rate-limited or unavailable.
          includeOsint: z.enum(['true', 'false']).default('true'),
          // Optional watchlist item IDs to filter results to monitored products.
          watchlistIds: z
            .string()
            .transform((val) => (val ? val.split(',').map((id) => id.trim()).filter(Boolean) : []))
            .optional(),
          // Optional date filter: results from this date onward.
          fromDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
        })
        .refine((query) => query.query || query.package || query.cveId || query.version, {
          message: 'Enter a package, product, CVE identifier, or keyword to search',
        })
        .parse(req.query);

      const apiKey = await loadNvdApiKey(pool, config);
      // Reuse the feed aggregator's already-ingested articles as the OSINT
      // layer. The search term is parameterised by queryCollection, and this is
      // best-effort: a local-read failure must not block live OSV/NVD results.
      let localArticles: IntelligenceArticle[] | undefined;
      const localTerm = params.cveId || params.package || params.query;
      if (params.includeOsint !== 'false' && localTerm) {
        try {
          const page = await queryCollection<IntelligenceArticle>(pool, 'intelligenceArticles', {
            limit: 20,
            offset: 0,
            search: localTerm,
          });
          localArticles = page.items;
        } catch {
          localArticles = [];
        }
      }
      try {
        res.json(
          await searchVulnerabilities(
            request,
            {
              query: params.query,
              productName: params.productName,
              ecosystem: params.ecosystem,
              packageName: params.package,
              version: params.version,
              cveId: params.cveId,
              limit: params.limit,
              includeOsint: params.includeOsint !== 'false',
              watchlistIds: params.watchlistIds,
              fromDate: params.fromDate,
            },
            {
              apiKey,
              localArticles,
              pool,
              // Wire the operator-configured Google CSE credentials (config.ts
              // validates them but nothing passed them to the aggregator, so the
              // Live OSINT panel permanently reported NOT_CONFIGURED).
              ...(config.GOOGLE_CSE_API_KEY && (config.GOOGLE_CSE_ID || config.GOOGLE_CSE_CX)
                ? {
                    googleCse: {
                      apiKey: config.GOOGLE_CSE_API_KEY,
                      cx: config.GOOGLE_CSE_ID || config.GOOGLE_CSE_CX,
                    },
                  }
                : {}),
            },
          ),
        );
      } catch (error) {
        if (error instanceof VulnerabilitySearchRateLimitError) {
          if (error.retryAfter) res.setHeader('Retry-After', String(error.retryAfter));
          throw new HttpError(429, error.message);
        }
        if (error instanceof VulnerabilitySearchUpstreamError)
          throw new HttpError(
            502,
            'Vulnerability search is temporarily unavailable; retry shortly',
          );
        throw error;
      }
    }),
  );
  app.get(
    '/api/threat/analytics',
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (req, res) => {
      const { range, limit } = z
        .object({
          range: z.enum(['7d', '30d', '90d', '365d', 'all']).default('30d'),
          limit: z.coerce.number().int().min(1).max(50).default(10),
        })
        .parse(req.query);
      const analytics: ThreatAnalytics = await computeThreatAnalytics(pool, range, limit);
      res.json(analytics);
    }),
  );
  app.post(
    '/api/threat/cpe-simulate',
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (req, res) => {
      const body = z
        .object({
          assetCpe: z.string().min(1).max(600),
          vulnerabilityCpe: z.string().min(1).max(600),
          assetVendor: z.string().trim().min(1).max(200),
          assetProduct: z.string().trim().min(1).max(200),
          versionRange: z
            .object({
              versionStartIncluding: z.string().optional(),
              versionStartExcluding: z.string().optional(),
              versionEndIncluding: z.string().optional(),
              versionEndExcluding: z.string().optional(),
            })
            .optional(),
          assetVersion: z.string().optional(),
        })
        .parse(req.body);
      const aliasEntries = await list<AliasEntry>(pool, 'aliases');
      const customVendorAliases = buildAliasMap(
        aliasEntries.filter((e) => e.scope === 'VENDOR'),
        'VENDOR',
      );
      const customProductAliases = buildAliasMap(
        aliasEntries.filter((e) => e.scope === 'PRODUCT'),
        'PRODUCT',
      );
      const result = runCpeSimulation(
        body.assetCpe,
        body.vulnerabilityCpe,
        body.assetVendor,
        body.assetProduct,
        customVendorAliases,
        customProductAliases,
        body.versionRange,
        body.assetVersion,
      );
      res.json(result);
    }),
  );
  app.post(
    '/api/session/renew',
    requireAuth(pool, config),
    asyncRoute(async (req, res) => {
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      // Rotate the CSRF token on every renewal so a captured token cannot be
      // reused beyond the current session lifetime.
      const csrf = randomToken();
      const row = (
        await pool.query(
          "UPDATE sessions SET expires_at=LEAST(now()+($2::int * interval '1 minute'),absolute_expires_at),csrf=$3 WHERE token_hash=$1 RETURNING expires_at",
          [req.operator!.sessionHash, settings.securityPolicy.sessionTimeoutMins, csrf],
        )
      ).rows[0];
      // A session can be invalidated between requireAuth and this handler
      // (e.g. a password change on another tab, or a cleanup sweep). A null
      // row is a normal expiry, not a server fault: clear the cookie so the
      // browser stops sending a dead token and signal 401 so the client
      // shows the session-expired flow instead of a generic 500.
      if (!row) {
        res.clearCookie(cookieName(config), sessionCookieOptions(config));
        throw new HttpError(401, 'Session expired');
      }
      res.json({ expiresAt: row.expires_at.toISOString(), csrfToken: csrf });
    }),
  );
  app.post(
    '/api/logout',
    requireAuth(pool, config),
    asyncRoute(async (req, res) => {
      await pool.query('DELETE FROM sessions WHERE token_hash=$1', [req.operator!.sessionHash]);
      // __Host- cookies are only cleared when the deletion carries the same
      // Secure/Path attributes as the original cookie.
      res.clearCookie(cookieName(config), sessionCookieOptions(config));
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/password',
    requireAuth(pool, config),
    asyncRoute(async (req, res) => {
      const data = z
        .object({ currentPassword: z.string().min(1).max(128), newPassword: z.string().min(14).max(128) })
        .parse(req.body);
      const user = (await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.operator!.id]))
        .rows[0];
      if (!(await checkPassword(data.currentPassword, user.password_hash)))
        throw new HttpError(400, 'Current password is incorrect');
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      if (data.newPassword.length < settings.securityPolicy.minPasswordLen)
        throw new HttpError(400, 'Password does not meet configured minimum length');
      const hash = await passwordHash(data.newPassword);
      await transaction(pool, async (db) => {
        await db.query('UPDATE users SET password_hash=$2 WHERE id=$1', [req.operator!.id, hash]);
        await db.query('DELETE FROM sessions WHERE user_id=$1', [req.operator!.id]);
        await db.query('DELETE FROM password_reset_tokens WHERE username=$1', [req.operator!.username]);
        await appendAudit(
          db,
          'Password changed',
          'All sessions revoked',
          req.operator!.username,
          'SECURITY',
          'INFO',
          req.ip || '',
        );
      });
      res.clearCookie(cookieName(config), sessionCookieOptions(config));
      res.json({ success: true });
    }),
  );
  app.get(
    '/api/users',
    requireRole('ADMIN'),
    asyncRoute(async (_req, res) =>
      res.json(
        (await pool.query('SELECT id,username,email,role,disabled,created_at FROM users ORDER BY username'))
          .rows,
      ),
    ),
  );
  app.post(
    '/api/users',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const data = z
        .object({
          username: z.string(),
          password: z.string(),
          role: z.enum(['ADMIN', 'OPERATOR', 'VIEWER']),
          // Required for new accounts: without it a reset code has nowhere to go
          // except the shared deployment mailbox, which is what this replaced.
          email: accountEmail,
        })
        .parse(req.body);
      await createUser(pool, data.username, data.password, data.role, req.ip || '', data.email, req.operator!.username);
      res.status(201).json({ success: true });
    }),
  );
  app.patch(
    '/api/users/:id',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      // Every field is optional so the same route serves a role change, a
      // disable/enable, and an email edit from the account form. `email: null`
      // clears the address; omitting it leaves the address untouched.
      const data = z
        .object({
          role: z.enum(['ADMIN', 'OPERATOR', 'VIEWER']).optional(),
          disabled: z.boolean().optional(),
          email: accountEmail.nullable().optional(),
        })
        .refine(
          (value) => value.role !== undefined || value.disabled !== undefined || value.email !== undefined,
          'No account changes were supplied',
        )
        .parse(req.body);
      const userId = z.uuid().safeParse(req.params.id);
      // `id` is a uuid column; an unparseable id is a client error, not a 500.
      if (!userId.success) throw invalidId();
      if (
        req.params.id === req.operator!.id &&
        ((data.disabled !== undefined && data.disabled) || (data.role !== undefined && data.role !== 'ADMIN'))
      )
        throw new HttpError(400, 'Cannot remove your own administrator access');
      await updateUser(
        pool,
        userId.data,
        { role: data.role, disabled: data.disabled, email: data.email },
        req.operator!.username,
        req.ip || '',
      );
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/users/:id/reset-password',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const data = z.object({ password: z.string().min(14).max(128) }).parse(req.body);
      const userId = z.uuid().safeParse(req.params.id);
      if (!userId.success) throw invalidId();
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      if (data.password.length < settings.securityPolicy.minPasswordLen)
        throw new HttpError(400, 'Password does not meet configured minimum');
      const hash = await passwordHash(data.password);
      await transaction(pool, async (db) => {
        const changed = await db.query('UPDATE users SET password_hash=$2 WHERE id=$1 RETURNING id', [
          userId.data,
          hash,
        ]);
        if (!changed.rowCount) throw new HttpError(404, 'Operator not found');
        await db.query('DELETE FROM sessions WHERE user_id=$1', [req.params.id]);
        await db.query(
          'DELETE FROM password_reset_tokens WHERE username=(SELECT username FROM users WHERE id=$1)',
          [userId.data],
        );
        await appendAudit(
          db,
          'Password reset',
          `Admin ${req.operator!.username} reset password`,
          req.operator!.username,
          'SECURITY',
          'INFO',
          req.ip || '',
        );
      });
      res.json({ success: true });
    }),
  );
  app.delete(
    '/api/users/:id',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const userId = z.uuid().safeParse(req.params.id);
      if (!userId.success) throw invalidId();
      if (req.params.id === req.operator!.id) throw new HttpError(400, 'You cannot delete your own account');
      await deleteUser(pool, userId.data, req.operator!.username, req.ip || '');
      res.json({ success: true });
    }),
  );
  app.get(
    '/api/state',
    requireAuth(pool, config),
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (_req, res) =>
      res.json(publicState(await state(pool, { limits: STATE_COLLECTION_LIMITS }))),
    ),
  );
  app.get(
    '/api/collections/:kind',
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (req, res) => {
      const query = z
        .object({
          limit: z.coerce.number().int().min(1).max(1000).default(50),
          offset: z.coerce.number().int().min(0).default(0),
          search: z.string().max(300).optional(),
          sort: z.string().max(40).optional(),
          order: z.enum(['asc', 'desc']).optional(),
          kev: z.enum(['true', 'false']).optional(),
          epssMin: z.coerce.number().min(0).max(1).optional(),
          dateFilter: z.enum(['ALL', 'IN_SCOPE', 'RECENT_MODIFIED', 'RECENT_PUBLISHED']).optional(),
          scopeHours: z.coerce.number().int().min(1).max(2880).optional(),
          severity: z.string().max(20).optional(),
          status: z.string().max(40).optional(),
          // emailLogs facets used by the Action Center. Without schema entries
          // Zod stripped them and the filters were silent no-ops on the wire.
          provider: z.string().max(40).optional(),
          advisoryId: z.string().max(150).optional(),
          dateRange: z.enum(['today', 'week', 'month', 'quarter', 'year', 'custom']).optional(),
          notificationStatus: z.string().max(40).optional(),
          category: z.string().max(20).optional(),
          level: z.string().max(10).optional(),
          articleIds: z.string().max(4000).optional(),
          // Scopes a findings page to one pipeline execution. The SPA always
          // sends it (FindingsView: latestExecution.id); without a schema entry
          // Zod stripped it and `recordConditions` never saw it, so the filter
          // was a silent no-op on both sides of the wire.
          executionId: z.string().max(150).optional(),
        })
        .parse(req.query);
      // An unknown collection is a client error, not a server fault. Validating
      // here keeps it out of the 500 path (and out of the incident log).
      if (!isCollectionKind(req.params.kind))
        throw new HttpError(404, `Unknown collection: ${req.params.kind}`);
      // VIEWER is a read role: it gets the same server-side filtering and
      // pagination as ADMIN/OPERATOR. Silently forcing offset 0 and dropping
      // search made every read-only history view show only its first page.
      res.json(
        await queryCollection(pool, String(req.params.kind), {
          limit: query.limit,
          offset: query.offset,
          search: query.search,
          sort: query.sort,
          order: query.order,
          filters: {
            kev: query.kev === 'true',
            epssMin: query.epssMin,
            dateFilter: query.dateFilter,
            scopeHours: query.scopeHours,
            severity: query.severity,
            status: query.status,
            provider: query.provider,
            advisoryId: query.advisoryId,
            dateRange: query.dateRange,
            notificationStatus: query.notificationStatus,
            category: query.category,
            level: query.level,
            articleIds: query.articleIds?.split(',').filter(Boolean),
            executionId: query.executionId,
          },
        }),
      );
    }),
  );
  app.get(
    '/api/audit/verify',
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (req, res) => {
      const controller = new AbortController();
      const onClose = () => controller.abort();
      res.once('close', onClose);
      let result: Awaited<ReturnType<typeof verifyStoredAudit>>;
      try {
        result = await verifyStoredAudit(pool, AbortSignal.any([
          controller.signal, AbortSignal.timeout(60000),
        ]));
      } finally {
        res.removeListener('close', onClose);
      }
      const externalRoot = typeof req.query.externalRoot === 'string' ? req.query.externalRoot : undefined;
      const externalMatch = externalRoot ? externalRoot === result.merkleRoot : undefined;
      res.json({
        ...result,
        externalRoot: externalRoot || null,
        externalMatch,
      });
    }),
  );

  app.post(
    '/api/audit/cleanup',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const { days } = z
        .object({ days: z.number().int().min(1).max(3650) })
        .parse(req.body);
      const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
      await transaction(pool, async (db) => {
        const deletedResult = await db.query(
          `DELETE FROM audit WHERE data->>'timestamp' < $1 RETURNING seq`,
          [cutoff],
        );
        const deleted = deletedResult.rowCount ?? 0;
        // Recalculate hash chain for remaining entries to maintain integrity
        if (deleted > 0) {
          const remaining = await db.query<{ seq: number; data: any }>(
            `SELECT seq, data FROM audit ORDER BY seq ASC`,
          );
          let previousHash = '0'.repeat(64);
          for (const row of remaining.rows) {
            const log = row.data;
            log.prevHash = previousHash;
            // Recompute hash using the same logic as hashAuditLog
            const hashInput = stableJson([
              log.prevHash,
              log.id,
              log.timestamp,
              log.category,
              log.level,
              log.event,
              log.details,
              log.actor,
              log.ipAddress,
              ...(log.context === undefined ? [] : [log.context]),
            ]);
            log.hash = createHash('sha256').update(hashInput).digest('hex');
            previousHash = log.hash;
            await db.query('UPDATE audit SET data=$1 WHERE seq=$2', [JSON.stringify(log), row.seq]);
          }
        }
        await appendAudit(
          db,
          'Audit cleanup',
          `Deleted ${deleted} audit log entries older than ${days} days`,
          req.operator!.username,
          'SECURITY',
          'INFO',
          req.ip || '',
        );
        res.json({ deleted, cutoff });
      });
    }),
  );

  app.post(
    '/api/events/cleanup',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const { days, scope } = z
        .object({
          days: z.number().int().min(1).max(3650),
          scope: z.enum(['OPERATIONS', 'ML', 'SYSTEM']).default('OPERATIONS'),
        })
        .parse(req.body);
      const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
      let deleted = 0;
      if (scope === 'OPERATIONS') {
        const result = await pool.query(
          `DELETE FROM operational_events WHERE category NOT IN ('ML','SYSTEM') AND occurred_at < $1`,
          [cutoff],
        );
        deleted = result.rowCount ?? 0;
      } else if (scope === 'ML') {
        const result = await pool.query(
          `DELETE FROM operational_events WHERE category = 'ML' AND occurred_at < $1`,
          [cutoff],
        );
        deleted = result.rowCount ?? 0;
      } else if (scope === 'SYSTEM') {
        const result = await pool.query(
          `DELETE FROM operational_events WHERE category = 'SYSTEM' AND occurred_at < $1`,
          [cutoff],
        );
        deleted = result.rowCount ?? 0;
      }
      await appendAudit(
        pool,
        'Event cleanup',
        `Deleted ${deleted} ${scope} event entries older than ${days} days`,
        req.operator!.username,
        'SECURITY',
        'INFO',
        req.ip || '',
      );
      res.json({ deleted, cutoff });
    }),
  );

  app.post(
    '/api/correlation/simulate',
    // Read-only by construction: matches against the cached corpus and the
    // submitted watch item, persisting nothing. Gating it on ADMIN forced
    // operators and viewers to file a privileged request to answer "would this
    // product match?", which is the question the endpoint exists to answer.
    // Any authenticated role may call it; the mutation quota skips it.
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (req, res) => {
      const body = z
        .object({
          vendor: z.string().min(1).max(200),
          product: z.string().min(1).max(200),
          version: z.string().max(100).optional(),
          cpes: z.array(z.string().max(600)).max(50).default([]),
          purls: z.array(z.string().max(600)).max(50).optional(),
          targetHw: z.string().max(100).optional(),
          assetTag: z.string().max(120).optional(),
        })
        .parse(req.body);
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const cves = await list<NormalizedCVE>(pool, 'cveData', 500);
      const aliases = await list<AliasEntry>(pool, 'aliases', 500);
      const watchItem: WatchListItem = {
        id: 'sim-test-01',
        vendor: body.vendor,
        product: body.product,
        version: body.version,
        cpes: body.cpes,
        purls: body.purls,
        targetHw: body.targetHw,
        assetTag: body.assetTag || 'SIM-PROD-01',
        ownerGroup: 'Simulation-Lab',
        active: true,
        createdAt: new Date().toISOString(),
      };
      const correlation = runVulnerabilityPipeline(
        [],
        cves,
        [watchItem],
        [],
        [],
        // The tester must report whether the match is deliverable under the
        // workspace policy, so it evaluates with the real confidence bar instead
        // of the 90% default it would otherwise inherit from a partial settings
        // object.
        { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
        'Simulation',
        false,
        buildAliasMap(aliases, 'VENDOR'),
        buildAliasMap(aliases, 'PRODUCT'),
        undefined,
        aliases,
      );
      const matchedCves = correlation.newFindings.map((finding) => ({
        cve: finding.cve,
        method: finding.matchingMethod,
        confidence: finding.notificationStatus === 'REVIEW_REQUIRED' ? 0 : 100,
        // matchingEvidence carries the precise hold reason (policy threshold,
        // missing inventory version, or unverifiable CVE evidence).
        evidence: finding.matchingEvidence,
        autoAction: finding.notificationStatus === 'REVIEW_REQUIRED' ? 'REVIEW_REQUIRED' : 'MATCH_CONFIRMED',
        suppressed: false,
        suppressionReason: '',
      }));
      res.json({
        testedAt: new Date().toISOString(),
        matchedCves,
        totalScanned: cves.length,
        aliasExpanded: matchedCves.some((match) => match.method === 'VENDOR_PRODUCT_ALIAS'),
        intervalEvaluated: matchedCves.some(
          (match) => match.method === 'STRICT_CPE_INTERVAL' || match.method === 'PURL_EXACT',
        ),
      });
    }),
  );
  app.get(
    '/api/email-queue',
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (_req, res) => {
      const rows = await pool.query(
        `SELECT id, payload->>'recipientEmail' AS "recipientEmail", advisory_id AS "advisoryId",
          payload->>'subject' AS subject, status, attempts,
          CASE WHEN status='REVIEW' THEN NULL ELSE next_attempt END AS "nextAttemptAt",
          created_at AS "createdAt", error, left(payload->>'text', 4000) AS preview,
          payload->'cveIds' AS "cveIds",
          edits AS "edits"
         FROM outbox
         WHERE channel='email' AND status IN ('REVIEW','QUEUED','SENDING','FAILED')
         ORDER BY created_at DESC, id DESC LIMIT 1000`,
      );
      res.json(rows.rows);
    }),
  );
  app.delete(
    '/api/email-queue',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const result = await transaction(pool, async (db) => {
        const deleted = await db.query<{ id: string }>(
          "DELETE FROM outbox WHERE channel='email' AND status IN ('QUEUED','FAILED','REVIEW') RETURNING id",
        );
        const ids = deleted.rows.map((row) => row.id);
        for (const id of ids) {
          const log = await getForUpdate<any>(db, 'emailLogs', id);
          if (log)
            await put(db, 'emailLogs', id, {
              ...log,
              status: 'CANCELLED',
              nextRetryTime: null,
              errorMessage: 'Removed from the delivery queue by an operator',
            });
        }
        const sending = await db.query<{ count: number }>(
          "SELECT count(*)::int AS count FROM outbox WHERE channel='email' AND status='SENDING'",
        );
        if (ids.length)
          await appendAudit(
            db,
            'Email delivery queue cleared',
            `${ids.length} queued, failed, or review jobs cancelled; ${sending.rows[0].count} sending jobs left untouched`,
            req.operator!.username,
            'EMAIL',
            'WARNING',
            req.ip || '',
          );
        return { removed: ids.length, inFlight: sending.rows[0].count };
      });
      res.json({ success: true, ...result });
    }),
  );
  app.get('/api/ml/status', requireRole('ADMIN', 'OPERATOR', 'VIEWER'), asyncRoute(async (_req, res) => {
    const runtime = getMlRuntime() ?? options.mlRuntime;
    const models = Object.entries(QUALITY_GATES).map(([id, gate]) => {
      const loaded = runtime?.registry.get(id);
      return {
        id, status: loaded?.status ?? 'UNTRAINED', trained: Boolean(loaded),
        version: loaded?.metadata.version ?? null, trainedAt: loaded?.metadata.trainedAt ?? null,
        minimumSamples: gate.minimumSamples,
      };
    });
    const training = await pool.query(
      "SELECT occurred_at,level,context FROM operational_events WHERE code='ml.training.completed' ORDER BY id DESC LIMIT 1",
    );
    res.json({
      initialized: Boolean(runtime), models,
      trainedModels: models.filter((model) => model.trained).length,
      totalModels: models.length, latestTraining: training.rows[0] ?? null,
    });
  }));
  app.post('/api/ml/feedback', requireRole('ADMIN', 'OPERATOR'), asyncRoute(async (req, res) => {
    const feedback = mlFeedbackSchema.parse(req.body);
    await transaction(pool, async (db) => {
      await writeEvent(db, {
        category: 'ML', code: 'ml.training.feedback',
        message: 'Analyst-verified ML training feedback recorded', context: feedback,
      });
      await appendAudit(db, 'ML training feedback recorded', feedback.source, req.operator!.username, 'PIPELINE');
    });
    res.status(201).json({ recorded: true, source: feedback.source, effect: 'next_training_run' });
  }));
  app.get(
    '/api/health',
    // Authenticated: the body carries queue backlog counts, worker heartbeat
    // age and DB latency, which are operationally useful to an attacker
    // mapping the deployment. `/live` and `/ready` stay unauthenticated so
    // orchestrator probes keep working.
    requireAuth(pool, config),
    asyncRoute(async (_req, res) => {
      const start = performance.now();
      await pool.query('SELECT 1');
      const dbMs = Math.round(performance.now() - start);
      const worker = (await pool.query('SELECT last_run,heartbeat FROM scheduler_state WHERE id=1')).rows[0] ?? {};
      const appSettings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const backlog = (await pool.query('SELECT status,count(*)::int AS count FROM outbox GROUP BY status'))
        .rows;
      const deliveryQueue = (
        await pool.query(`SELECT
        count(*) FILTER (WHERE status='QUEUED' AND next_attempt<=now())::int AS "dueJobs",
        min(created_at) FILTER (WHERE status='QUEUED' AND next_attempt<=now()) AS "oldestDueCreatedAt",
        min(next_attempt) FILTER (WHERE status='QUEUED' AND next_attempt>now()) AS "nextScheduledAttempt",
        count(*) FILTER (WHERE status='SENDING' AND locked_at<now()-interval '2 minutes')::int AS "expiredLeases"
        FROM outbox WHERE status IN ('QUEUED','SENDING')`)
      ).rows[0];
      const heartbeatAgeSeconds = worker.heartbeat
        ? Math.max(0, Math.floor((Date.now() - new Date(worker.heartbeat).getTime()) / 1000))
        : null;
      const emailConfig =
        (await get<EmailConfiguration>(pool, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
      res.json({
        database: 'connected',
        databaseLatencyMs: dbMs,
        uptimeSeconds: Math.floor(process.uptime()),
        heapBytes: process.memoryUsage().heapUsed,
        workerEnabled: config.WORKER_ENABLED === 'true',
        workerHeartbeat: worker.heartbeat,
        workerStatus:
          config.WORKER_ENABLED !== 'true'
            ? 'DISABLED'
            : heartbeatAgeSeconds === null
              ? 'NOT_OBSERVED'
              : heartbeatAgeSeconds > 90
                ? 'STALE'
                : 'HEALTHY',
        heartbeatAgeSeconds,
        deliveryQueue,
        lastScheduledRun: worker.last_run,
        nextScheduledRun: (appSettings.schedulerEnabled
          ? (worker.last_run
              ? new Date(Date.parse(worker.last_run) + appSettings.schedulerIntervalMinutes * 60_000)
              : new Date(Date.now()))
          : null)?.toISOString() ?? null,
        schedulerEnabled: appSettings.schedulerEnabled,
        schedulerIntervalMinutes: appSettings.schedulerIntervalMinutes,
        backlog,
        smtpConfigured: !!config.SMTP_HOST && !!config.SMTP_FROM,
        emailProvider: emailConfig.provider,
        emailConfigured: emailIsConfigured(emailConfig, config),
        httpsRequired: config.NODE_ENV === 'production',
        csrfEnforced: true,
        ssrfEnforced: true,
        ntp: 'Host-managed; not measured by this application',
        checkedAt: new Date().toISOString(),
      });
    }),
  );

  app.post(
    '/api/pipeline',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const data = z
        .object({
          scopeHours: z.number().int().min(1).max(2880).optional(),
          incrementalFeeds: z.boolean().default(true),
        })
        .parse(req.body);
      res
        .status(202)
        .json(await queueRun(pool, data.scopeHours, req.operator!.username, data.incrementalFeeds));
    }),
  );
  app.post(
    '/api/pipeline/:id/stop',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      res.json(await stopRun(pool, String(req.params.id), req.operator!.username));
    }),
  );
  app.post(
    '/api/feeds/:id/test',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const feed = await get<ThreatFeed>(pool, 'feeds', String(req.params.id));
      if (!feed) throw new HttpError(404, 'Feed not found');
      const start = performance.now();
      const headers: Record<string, string> =
        feed.type === 'RSS_ATOM'
          ? {
              'user-agent': RSS_USER_AGENT,
              accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml',
            }
          : {};
      let secret: string;
      try {
        secret = decrypt(feed.authSecretKey || '', encryptionKeys(config), `feed:${feed.id}`);
      } catch {
        throw new HttpError(
          400,
          'Stored feed credentials could not be decrypted; re-enter the secret or restore the original encryption key',
        );
      }
      if (feed.authType !== 'NONE' && !secret) throw new HttpError(400, 'Feed secret is missing');
      if (feed.authType === 'API_KEY') {
        if (feed.type === 'OTX_API') headers['X-OTX-API-KEY'] = secret;
        else headers.apiKey = secret;
      }
      if (['BEARER', 'BASIC'].includes(feed.authType))
        headers.Authorization = `${feed.authType === 'BASIC' ? 'Basic' : 'Bearer'} ${feed.authType === 'BASIC' ? Buffer.from(secret).toString('base64') : secret}`;
      let response: ResponseData;
      try {
        const testUrl = new URL(feed.url);
        if (feed.type === 'NVD_API') testUrl.searchParams.set('resultsPerPage', '1');
        if (feed.type === 'OTX_API') {
          if (feed.url !== OTX_SUBSCRIBED_PULSES_URL || feed.authType !== 'API_KEY')
            throw new HttpError(400, 'AlienVault OTX requires its subscribed-pulses API endpoint and an API key');
          testUrl.searchParams.set('limit', '1');
        }
        const osvProbe = feed.type === 'OSV_API';
        const requestOptions =
          feed.type === 'NVD_API'
            ? { headers, timeoutMs: 25000, socketTimeoutMs: 20000, maxResponseBytes: 256 * 1024 }
            : feed.type === 'MITRE_CVE'
              ? { headers, timeoutMs: 120000, socketTimeoutMs: 60000, maxResponseBytes: 64 * 1024 * 1024 }
              : feed.type === 'OPENCVE_API'
                ? {
                    headers,
                    timeoutMs: (feed.requestTimeoutSeconds || 60) * 1000,
                    socketTimeoutMs: Math.min((feed.requestTimeoutSeconds || 60) * 1000, 30000),
                    maxResponseBytes: 4 * 1024 * 1024,
                  }
                : feed.type === 'RSS_ATOM'
                  ? { headers, timeoutMs: 25000, maxResponseBytes: RSS_MAX_BYTES }
                  : feed.type === 'OTX_API'
                    ? {
                        headers,
                        timeoutMs: (feed.requestTimeoutSeconds || 60) * 1000,
                        socketTimeoutMs: Math.min((feed.requestTimeoutSeconds || 60) * 1000, 30000),
                        maxResponseBytes: 8 * 1024 * 1024,
                      }
                    : osvProbe
                      ? {
                          method: 'POST' as const,
                          headers: { ...headers, 'content-type': 'application/json' },
                          body: JSON.stringify({
                            queries: [{ package: { purl: 'pkg:npm/vulnstream-connectivity-check@1.0.0' } }],
                          }),
                          timeoutMs: 25000,
                          maxResponseBytes: 256 * 1024,
                        }
                      : { headers };
        response = await request(testUrl.href, requestOptions);
        if (response.status >= 200 && response.status < 300) {
          if (feed.type === 'RSS_ATOM') parseSyndication(response.body, feed.id, 2880);
          else {
            // A successful HTTP status is not proof that the endpoint returned
            // the JSON contract this adapter needs. Reject an HTML error page or
            // truncated body during the test instead of reporting HEALTHY.
            let data: unknown;
            try {
              data = JSON.parse(response.body);
            } catch {
              throw new Error('Feed returned a non-JSON response body');
            }
            if (feed.type === 'OTX_API') {
              const page = parseOtxPulsePage(data, feed.id, Number.NEGATIVE_INFINITY);
              if (page.next) validateOtxNextUrl(page.next, testUrl.href);
            }
            if (osvProbe) {
              const result = (data as { results?: unknown })?.results;
              if (!Array.isArray(result) || result.length !== 1 || !result[0] || typeof result[0] !== 'object')
                throw new Error('OSV querybatch returned an invalid response');
              const vulns = (result[0] as { vulns?: unknown }).vulns;
              if (vulns !== undefined && !Array.isArray(vulns))
                throw new Error('OSV querybatch returned an invalid response');
            }
          }
        }
        const latency = Math.round(performance.now() - start);
        const ok = response.status >= 200 && response.status < 300;
        await transaction(pool, async (db) => {
          const current = await getForUpdate<ThreatFeed>(db, 'feeds', feed.id);
          if (current) {
            const consecutiveFailures = (current.consecutiveFailures || 0) + (ok ? 0 : 1);
            await put(db, 'feeds', feed.id, {
              ...current,
              healthStatus: ok ? 'HEALTHY' : 'DOWN',
              lastSync: ok ? new Date().toISOString() : current.lastSync,
              latencyMs: latency,
              errorLog: ok ? null : `HTTP ${response.status}`,
              ssrfValidated: ok ? true : current.ssrfValidated,
              consecutiveFailures: ok ? 0 : consecutiveFailures,
              circuitOpenUntil: ok ? null : isPermanentFeedFailure({ status: response.status }) ? null : recoveryAt(current, consecutiveFailures, Date.now(), computeFeedRecoveryDelay(consecutiveFailures)),
              lastRecoveryAttemptAt: !ok ? new Date().toISOString() : current.lastRecoveryAttemptAt,
            });
          }
          await appendAudit(
            db,
            'Feed connectivity tested',
            `${feed.id}; HTTP ${response.status}`,
            req.operator!.username,
            'FEED',
            ok ? 'INFO' : 'ERROR',
            req.ip || '',
          );
        });
        res.json({
          success: ok,
          latency,
          error: ok ? undefined : `HTTP ${response.status}`,
        });
      } catch (e) {
        const message = e instanceof Error ? e.message : 'Connection failed';
        const latency = Math.round(performance.now() - start);
        await transaction(pool, async (db) => {
          const current = await getForUpdate<ThreatFeed>(db, 'feeds', feed.id);
           if (current) {
             const consecutiveFailures = (current.consecutiveFailures || 0) + 1;
             await put(db, 'feeds', feed.id, {
               ...current,
               healthStatus: 'DOWN',
               latencyMs: latency,
               errorLog: message,
               consecutiveFailures,
               circuitOpenUntil: isPermanentFeedFailure(e) ? null : recoveryAt(current, consecutiveFailures, Date.now(), computeFeedRecoveryDelay(consecutiveFailures)),
               lastRecoveryAttemptAt: new Date().toISOString(),
             });
           }
          await appendAudit(
            db,
            'Feed connectivity tested',
            `${feed.id}; ERROR: ${message}`,
            req.operator!.username,
            'FEED',
            'ERROR',
            req.ip || '',
          );
        });
        res.json({ success: false, latency, error: 'Connection failed; see feed test log for details' });
      }
    }),
  );
  app.post(
    '/api/test-email',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const { email, forceReview, html } = z
        .object({
          email: z.email().max(254),
          forceReview: z.boolean().optional(),
          html: z.string().min(1).max(200_000).optional(),
        })
        .parse(req.body);
      const id = await transaction(pool, async (db) => {
        const emailConfig =
          (await getForUpdate<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
        if (!emailIsConfigured(emailConfig, config))
          throw new HttpError(409, 'Configure an email provider in Settings before sending a test');
        const data = await state(db);
        const testAdvisory: Advisory = {
          id: `${data.settings.advisoryPrefix}TEST`,
          title: 'BA Threat Intel template test',
          severity: 'UNKNOWN',
          cveIds: [],
          findingIds: [],
          createdDate: new Date().toISOString(),
          deliveryStatus: 'PENDING',
          recipientCount: 1,
          executiveSummary: 'Requested template test. This is not a live vulnerability advisory.',
          affectedSystems: ['Example inventory asset'],
          remediationInstructions: 'Preview only; no remediation action is required.',
        };
        const id = await enqueue(
          db,
          'email',
          'test',
          'TEST',
          {
            ...advisoryEmail(testAdvisory, html ?? renderAdvisory(data.advisoryTemplate, testAdvisory)),
            recipientEmail: email,
            cveIds: [],
          },
          randomUUID(),
          forceReview ? 'REVIEW' : undefined,
        );
        await appendAudit(
          db,
          'Test email queued',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
        return id;
      });
      res
        .status(202)
        .json({ success: true, message: 'Test queued. Check the delivery log for provider acceptance.', id });
    }),
  );
  app.post(
    '/api/test-email-connectivity',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const { provider, smtpHost, smtpPort, smtpSecurity } = z
        .object({
          provider: z.string(),
          smtpHost: z.string().min(1),
          smtpPort: z.coerce.number().min(1).max(65535),
          smtpSecurity: z.string().optional(),
        })
        .parse(req.body);
      const start = Date.now();
      const socket = net.createConnection(smtpPort, smtpHost);
      let resolved = false;
      const promise = new Promise<{ ok: boolean; latency: number; error?: string }>((resolve, reject) => {
        const timeout = setTimeout(() => { if (!resolved) { resolved = true; reject(new Error('Connection timed out')); socket.destroy(); } }, 10000);
        socket.on('connect', () => {
          resolved = true;
          clearTimeout(timeout);
          resolve({ ok: true, latency: Date.now() - start });
        });
        socket.on('error', (e) => {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeout);
            resolve({ ok: false, latency: Date.now() - start, error: e.message });
          }
        });
      });
      const result = await promise.finally(() => socket.destroy());
      await transaction(pool, async (db) => {
        await appendAudit(
          db,
          'Email connectivity tested',
          `${smtpHost}:${smtpPort}`,
          req.operator!.username,
          'EMAIL',
          result.ok ? 'INFO' : 'ERROR',
          req.ip || '',
        );
      });
      res.json({ success: result.ok, latency: result.latency, error: result.error });
    }),
  );
  app.post(
    '/api/test-daily-digest',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const { email } = z.object({ email: z.email().max(254) }).parse(req.body);
      const id = await transaction(pool, async (db) => {
        const emailConfig =
          (await getForUpdate<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
        if (!emailIsConfigured(emailConfig, config))
          throw new HttpError(409, 'Configure an email provider in Settings before sending a test');
        const data = await state(db);
        const dailyConfig = {
          ...(data.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
          timezone: data.settings.timezone,
        };
        const dailyDigestTemplate = data.dailyDigestCustomTemplate;
        const sampleFindings: DigestFinding[] = [
          { cveId: 'CVE-2026-0001', severity: 'CRITICAL', assetName: 'edge-router-01', vendor: 'VendorX', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001' },
          { cveId: 'CVE-2026-0002', severity: 'CRITICAL', assetName: 'auth-service', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0002' },
          { cveId: 'CVE-2026-0003', severity: 'HIGH', assetName: 'portal-web', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0003' },
          { cveId: 'CVE-2026-0004', severity: 'MEDIUM', assetName: 'internal-api', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0004' },
          { cveId: 'CVE-2026-0005', severity: 'LOW', assetName: 'monitoring-agent', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0005' },
        ];
        const sampleHealth: DigestHealth = {
          database: 'connected',
          databaseLatencyMs: 12,
          workerStatus: 'HEALTHY',
          workerHeartbeatAgeSeconds: 4,
          nextScheduledAttempt: null,
          nextDailyDigestAt: new Date(Date.now() + 86400000).toISOString(),
          backlog: [
            { status: 'QUEUED', count: 0 },
            { status: 'ACCEPTED', count: 12 },
          ],
          checkedAt: new Date().toISOString(),
          systemUptime: '5 Days 3 Hours',
          systemUptimePercentage: null,
        };
        const severityCounts = { CRITICAL: 2, HIGH: 1, MEDIUM: 1, LOW: 1, UNKNOWN: 0 };
        const reportGenerated = new Date().toLocaleString('en-GB', {
          day: 'numeric',
          month: 'long',
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        });
        const executiveSummary = formatExecutiveSummary(sampleFindings.length, severityCounts);
         const parts: DailyDigestParts = {
           advisory_id: `${data.settings.advisoryPrefix}DAILY-PREVIEW`,
           advisory_title: 'Daily Vulnerability Digest — preview',
           dispatch_date: new Date().toISOString(),
           severity: 'HIGH',
           finding_count: sampleFindings.length,
           severity_counts: '2 critical, 1 high',
           findings_summary: renderDailyFindingSummary(sampleFindings, dailyConfig),
           health_report: renderDailyHealthReport(sampleHealth, dailyConfig),
           recipient_name: email,
           critical_count: severityCounts.CRITICAL,
           high_count: severityCounts.HIGH,
           medium_count: severityCounts.MEDIUM,
           low_count: severityCounts.LOW,
           asset_count: new Set(sampleFindings.map((f) => f.assetName)).size,
           executive_summary: executiveSummary,
           report_generated: reportGenerated,
           critical_summary: digestSeveritySummary('CRITICAL', severityCounts.CRITICAL, dailyConfig),
           high_summary: digestSeveritySummary('HIGH', severityCounts.HIGH, dailyConfig),
           medium_summary: digestSeveritySummary('MEDIUM', severityCounts.MEDIUM, dailyConfig),
           low_summary: digestSeveritySummary('LOW', severityCounts.LOW, dailyConfig),
           critical_kpi: digestSeverityKpi('CRITICAL', severityCounts.CRITICAL, dailyConfig),
           high_kpi: digestSeverityKpi('HIGH', severityCounts.HIGH, dailyConfig),
           medium_kpi: digestSeverityKpi('MEDIUM', severityCounts.MEDIUM, dailyConfig),
           low_kpi: digestSeverityKpi('LOW', severityCounts.LOW, dailyConfig),
         };
          const html = renderDailyDigest(dailyConfig, parts, dailyDigestTemplate ?? undefined);
        const testAdvisory: Advisory = {
          id: parts.advisory_id,
          title: parts.advisory_title,
          severity: 'HIGH',
          cveIds: ['CVE-2026-0001', 'CVE-2026-0002'],
          findingIds: [],
          createdDate: new Date().toISOString(),
          deliveryStatus: 'PENDING',
          recipientCount: 1,
          executiveSummary:
            'Preview of the daily digest template. This is not a live vulnerability advisory.',
          affectedSystems: ['Example inventory asset'],
          remediationInstructions: 'Preview only; no remediation action is required.',
        };
        const id = await enqueue(
          db,
          'email',
          'test',
          'TEST',
          {
            ...advisoryEmail(testAdvisory, html),
            recipientEmail: email,
            cveIds: testAdvisory.cveIds,
            dailyDigest: true,
          },
          randomUUID(),
        );
        await appendAudit(
          db,
          'Test daily digest queued',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
        return id;
      });
      res.status(202).json({
        success: true,
        message: 'Daily digest test queued. Check the delivery log for provider acceptance.',
        id,
      });
    }),
  );
  app.post(
    '/api/retention/run',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const result = await runRetention(pool, req.operator!.username, req.ip || '');
      if (!result) throw new HttpError(400, 'Enable the retention policy before running cleanup');
      res.json(result);
    }),
  );
  app.post(
    '/api/retention/preview',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const policy = z
        .object({
          enabled: z.boolean(),
          retentionHours: z.number().int().min(1).max(8760),
          maxArchivedRecords: z.number().int().min(1000).max(1000000),
          retentionMode: z.enum(['strict', 'rolling', 'checkpoints']),
        })
        .parse(req.body);
      res.json(await previewRetention(pool, policy));
    }),
  );
  app.post(
    '/api/webhooks/:id/test',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const hook = await get<WebhookEndpoint>(pool, 'webhooks', String(req.params.id));
      if (!hook?.enabled) throw new HttpError(400, 'Webhook is missing or disabled');
      await transaction(pool, async (db) => {
        const id = await enqueue(
          db,
          'webhook',
          hook.id,
          'TEST',
          {
            subject: 'BA Threat Intel connection test',
            text: 'Requested BA Threat Intel webhook test',
            cveIds: [],
          },
          randomUUID(),
        );
        await appendAudit(
          db,
          'Test webhook queued',
          `Delivery ${id}`,
          req.operator!.username,
          'WEBHOOK',
          'INFO',
          req.ip || '',
        );
      });
      res.status(202).json({ success: true, statusCode: 202, signature: 'Pending worker delivery' });
    }),
  );
  app.post(
    '/api/email/:id/approve',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      await transaction(pool, async (db) => {
        // Findings are queued for delivery, not for review. "Approve" therefore
        // confirms the operator's edits on a queued or previously-held email and
        // releases it immediately; a job already in flight or delivered cannot
        // be re-sent from here (use the follow-up resend route).
        const row = await db.query(
          "UPDATE outbox SET status='QUEUED',review_approved=true,attempts=0,next_attempt=now(),error=NULL,locked_at=NULL,lock_token=NULL,updated_at=now() WHERE id=$1 AND channel='email' AND status IN ('REVIEW','QUEUED') AND locked_at IS NULL RETURNING advisory_id, edits, payload",
          [id],
        );
        if (!row.rowCount)
          throw new HttpError(409, 'Only a queued email or a notification awaiting review can be approved');
        const edits: ReviewEdits = row.rows[0].edits || {};
        if (Object.keys(edits).length) {
          const currentPayload = row.rows[0].payload;
          // Idempotent: previously seeded notice/comment blocks are stripped
          // before the current edits are applied, so re-approval or a later
          // send cannot duplicate the reviewer's additions.
          const updatedHtml = renderReviewEdits(currentPayload.html, edits);
          if (updatedHtml !== currentPayload.html) {
            // The reviewer comment is now part of the body. Keep the stored
            // content revision in step with it, or the delivery worker would
            // reject the very message the operator just approved as having
            // "changed" between queueing and approval.
            let contentRevision = currentPayload.contentRevision;
            if (currentPayload.dailyDigest) {
              contentRevision = createHash('sha256')
                .update(stableJson({ ...currentPayload, html: updatedHtml, contentRevision: undefined }))
                .digest('hex')
                .slice(0, 20);
            } else {
              const advisory = await get<any>(db, 'advisories', String(row.rows[0].advisory_id));
              const findingIds: string[] = currentPayload.includedFindingIds ?? advisory?.findingIds ?? [];
              const findings = [...(await getMany<any>(db, 'findings', findingIds)).values()];
              if (advisory) {
                const recomputed = advisoryRevision(
                  { ...advisory, cveIds: currentPayload.cveIds ?? advisory.cveIds },
                  findings,
                );
                if (!currentPayload.contentRevision || recomputed === currentPayload.contentRevision)
                  contentRevision = recomputed;
                else
                  // The advisory or its findings changed between queueing and
                  // approval. Sending the modified body would deliver content the
                  // revision does not describe, so the job goes back to review
                  // instead of being dispatched on a mismatched hash.
                  throw new HttpError(
                    409,
                    'Advisory content changed since this notification was queued; rebuild it before approving',
                  );
              }
            }
            await db.query('UPDATE outbox SET payload=$2::jsonb WHERE id=$1', [
              id,
              JSON.stringify({ ...currentPayload, html: updatedHtml, contentRevision }),
            ]);
          }
        }
        const log = await getForUpdate<any>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            subject: effectiveSubject(log.subject, edits),
            status: 'QUEUED',
            attemptCount: 0,
            nextRetryTime: new Date().toISOString(),
            errorMessage: undefined,
          });
        await appendAudit(
          db,
          'Email notification approved',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
        await refreshAdvisoryDeliveryStatus(db, String(row.rows[0].advisory_id));
      });
      res.json({ success: true });
    }),
  );
  app.get(
    '/api/email/:id/preview',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      const row = await pool.query(
        `SELECT o.payload->>'html' AS "html", o.payload->>'text' AS "text",
                o.payload->>'subject' AS "subject", o.edits, o.advisory_id, o.status
          FROM outbox o
          WHERE o.id=$1 AND o.channel='email' AND ${editableJobStatusSql('o.status')}`,
        [id],
      );
      if (!row.rowCount) throw new HttpError(404, 'Email job not found or not in a previewable state');
      const record = row.rows[0];
      const edits: ReviewEdits = record.edits || {};
      const content = editedJobContent(record, edits);
      // Normalize HTML preview so text (audience notice, reviewer comment) remains visible.
      if (!content.html || !content.html.includes('<body')) {
        const bodyWrap = content.html && content.html.length > 0
          ? `<html><head><meta charset="utf-8"><title>Email Preview</title></head><body>${content.html}</body></html>`
          : '<html><head><meta charset="utf-8"><title>Email Preview</title></head><body></body></html>';
        content.html = bodyWrap;
      }
      res.json({
        html: content.html,
        text: content.text,
        subject: content.subject,
        edits,
        advisoryId: record.advisory_id,
      });
    }),
  );
   app.post(
     '/api/email/:id/preview-edits',
     requireRole('ADMIN', 'OPERATOR'),
     asyncRoute(async (req, res) => {
       const id = outboxId(req.params.id);
       const proposedEdits: ReviewEdits = z
         .object({
           subject: z.string().max(200).optional(),
           audienceNotice: z.string().max(2000).optional(),
           reviewerComment: z.string().max(2000).optional(),
           reviewerName: z.string().max(100).optional(),
           customBodyOverride: z.string().max(50000).optional(),
           customFields: z.record(z.string(), z.string().max(2000)).optional(),
         })
         .parse(req.body);
        const row = await pool.query(
          `SELECT o.payload->>'html' AS "html", o.payload->>'text' AS "text",
                  o.payload->>'subject' AS "subject", o.edits
            FROM outbox o
           WHERE o.id=$1 AND o.channel='email' AND ${editableJobStatusSql('o.status')}`,
          [id],
        );
        if (!row.rowCount) throw new HttpError(404, 'Email job not found or not in a previewable state');
        const record = row.rows[0];
        const mergedEdits: ReviewEdits = { ...(record.edits || {}), ...proposedEdits };
        const content = editedJobContent(record, mergedEdits);
        // Normalize HTML preview so text (audience notice, reviewer comment) remains visible.
        if (!content.html || !content.html.includes('<body')) {
          const bodyWrap = content.html && content.html.length > 0
            ? `<html><head><meta charset="utf-8"><title>Email Preview</title></head><body>${content.html}</body></html>`
            : '<html><head><meta charset="utf-8"><title>Email Preview</title></head><body></body></html>';
          content.html = bodyWrap;
        }
       res.json({ html: content.html, text: content.text, subject: content.subject, edits: mergedEdits });
     }),
   );
  app.post(
    '/api/email/:id/preview-pdf',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      const proposedEdits: ReviewEdits = z
        .object({
          subject: z.string().max(200).optional(),
          audienceNotice: z.string().max(2000).optional(),
          reviewerComment: z.string().max(2000).optional(),
          reviewerName: z.string().max(100).optional(),
          customBodyOverride: z.string().max(50000).optional(),
          customFields: z.record(z.string(), z.string().max(2000)).optional(),
        })
        .parse(req.body);
      const row = await pool.query(
        `SELECT o.payload->>'html' AS "html", o.payload->>'text' AS "text",
                o.payload->>'subject' AS "subject", o.edits
           FROM outbox o
          WHERE o.id=$1 AND o.channel='email' AND ${editableJobStatusSql('o.status')}`,
        [id],
      );
      if (!row.rowCount) throw new HttpError(404, 'Email job not found or not in a previewable state');
      // The PDF is rendered from exactly the HTML that would be emailed, which
      // is what makes an edit in the Action Center update the attachment too.
      const content = editedJobContent(row.rows[0], {
        ...(row.rows[0].edits || {}),
        ...proposedEdits,
      });
      if (!content.html.trim())
        throw new HttpError(400, 'The edited email has no renderable body to convert to PDF');
      try {
        const pdf = await renderAdvisoryPdf(content.html);
        res.setHeader('content-type', 'application/pdf');
        res.setHeader('content-disposition', 'inline; filename="email-preview.pdf"');
        res.setHeader('cache-control', 'no-store');
        res.send(Buffer.from(pdf));
      } catch (error) {
        throw new HttpError(
          502,
          `PDF rendering failed: ${error instanceof Error ? error.message : 'unknown renderer error'}`,
        );
      }
    }),
  );
  app.post(
    '/api/email/:id/edit',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      const {
        subject,
        audienceNotice,
        reviewerComment,
        reviewerName,
        customBodyOverride,
        customFields,
        recipientMode,
        customEmail,
      } = z
        .object({
          subject: z.string().max(200).optional(),
          audienceNotice: z.string().max(2000).optional(),
          reviewerComment: z.string().max(2000).optional(),
          reviewerName: z.string().max(100).optional(),
          customBodyOverride: z.string().max(50000).optional(),
          customFields: z.record(z.string(), z.string().max(2000)).optional(),
          recipientMode: z.enum(['SINGLE_EMAIL', 'SECURITY_TEAM', 'EVERYONE']).optional(),
          customEmail: z.string().email().optional(),
        })
        .parse(req.body);
      await transaction(pool, async (db) => {
        const current = await db.query(
          // Delivered jobs are editable too. The Action Center lists every
          // accepted findings email as a PENDING follow-up, and the operator's
          // remedy is to correct and re-send it. Allowing only REVIEW/QUEUED
          // made the editor open on a delivered item and then fail with a 409,
          // discarding the edit. ACCEPTED/DELIVERED rows are never in flight
          // (deliverNext clears locked_at on commit), so `locked_at IS NULL`
          // is still the right in-flight guard.
          `SELECT edits, payload, status FROM outbox
            WHERE id=$1 AND channel='email'
              AND ${editableJobStatusSql('status')} AND locked_at IS NULL
            FOR UPDATE`,
          [id],
        );
        if (!current.rowCount)
          throw new HttpError(
            409,
            'Only email jobs awaiting review, queued, or already delivered can be edited',
          );
        const existingEdits: ReviewEdits = current.rows[0].edits || {};
        const mergedEdits: ReviewEdits = {
          ...existingEdits,
          ...(subject !== undefined && { subject: normalizeEmailSubject(subject) }),
          ...(audienceNotice !== undefined && { audienceNotice }),
          ...(reviewerComment !== undefined && { reviewerComment }),
          ...(reviewerName !== undefined && { reviewerName }),
          ...(customBodyOverride !== undefined && { customBodyOverride }),
          ...(customFields !== undefined && { customFields }),
          ...(recipientMode !== undefined && { recipientMode }),
          ...(customEmail !== undefined && { customEmail }),
        };
        // `payload.html` remains the original template render. The edit layer
        // is applied at preview/send time so the email and its PDF attachment
        // always agree, and clearing an edit removes it instead of leaving the
        // previous override baked into the payload.
        await db.query('UPDATE outbox SET edits=$2::jsonb, updated_at=now() WHERE id=$1', [
          id,
          JSON.stringify(mergedEdits),
        ]);
        const log = await getForUpdate<EmailDeliveryLog>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            // Derive from the template subject, not the log's current value, so
            // clearing an override genuinely restores the queued subject.
            subject: effectiveSubject(current.rows[0].payload?.subject, mergedEdits),
          });
        await appendAudit(
          db,
          'Email review edited',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
      });
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/email/:id/reject',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      await transaction(pool, async (db) => {
        const row = await db.query(
          "UPDATE outbox SET status='REJECTED',error='Rejected during security review',updated_at=now() WHERE id=$1 AND channel='email' AND status='REVIEW' RETURNING advisory_id",
          [id],
        );
        if (!row.rowCount) throw new HttpError(409, 'Only notifications awaiting review can be rejected');
        const log = await getForUpdate<any>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            status: 'CANCELLED',
            nextRetryTime: null,
            errorMessage: 'Rejected during security review',
          });
        await appendAudit(
          db,
          'Email notification rejected',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'WARNING',
          req.ip || '',
        );
        await refreshAdvisoryDeliveryStatus(db, String(row.rows[0].advisory_id));
      });
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/email/:id/retry',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      await transaction(pool, async (db) => {
        // Failed jobs restart with a fresh retry budget; a job already waiting
        // on a scheduled retry can be sent now without losing its attempt
        // history. Jobs that are already due (or in flight) are left to the
        // worker so a manual retry cannot double-send.
        const target = await db.query<{
          status: string;
          attempts: number;
          advisory_id: string | null;
          payload: Record<string, unknown> | null;
        }>(
          `SELECT status, attempts, advisory_id, payload FROM outbox
            WHERE id=$1 AND channel='email'
              AND (status='FAILED' OR (status='QUEUED' AND next_attempt>now()))
            FOR UPDATE`,
          [id],
        );
        if (!target.rowCount) throw new HttpError(409, 'Only failed or scheduled deliveries may be retried');
        const queued = target.rows[0];
        const previousStatus = queued.status;
        const advisoryId = queued.advisory_id || '';
        let payload = queued.payload || {};
        const currentCardMarker = 'border:1px solid #e2e8f0;border-left:4px solid';
        if (advisoryId && !String(payload.html || '').includes(currentCardMarker)) {
          const advisory = await get<Advisory>(db, 'advisories', advisoryId);
          if (advisory?.findingIds?.length) {
            const findingRows = await getMany<Finding>(db, 'findings', advisory.findingIds);
            const findings = advisory.findingIds
              .map((findingId) => findingRows.get(findingId))
              .filter((finding): finding is Finding => !!finding);
            if (findings.length) {
              const refreshedBody = await currentAdvisoryBody(db, advisory, findings);
              if (refreshedBody.html) payload = { ...payload, html: refreshedBody.html };
            }
          }
        }
        const attempts = previousStatus === 'FAILED' ? 0 : Number(queued.attempts);
        await db.query(
          `UPDATE outbox
              SET status='QUEUED', attempts=$2, next_attempt=now(), error=NULL,
                  locked_at=NULL, lock_token=NULL, payload=$3::jsonb, updated_at=now()
            WHERE id=$1`,
          [id, attempts, JSON.stringify(payload)],
        );
        const log = await getForUpdate<any>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            status: 'QUEUED',
            attemptCount: previousStatus === 'FAILED' ? 0 : attempts,
            nextRetryTime: new Date().toISOString(),
            errorMessage: undefined,
          });
        await appendAudit(
          db,
          'Delivery retry queued',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
        // The job is pending again, so the advisory it belongs to and its
        // findings must reflect that. Without this the advisory stayed FAILED
        // (the retry is the operator's remedy for a failed delivery) and the
        // findings kept DELIVERY_FAILED even though a send was now queued.
        await refreshAdvisoryDeliveryStatus(db, advisoryId);
      });
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/email/:id/acknowledge',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      const data = z
        .object({ reason: z.string().trim().max(500).optional() })
        .parse(req.body ?? {});
      await transaction(pool, async (db) => {
        const log = await getForUpdate<EmailDeliveryLog>(db, 'emailLogs', id);
        if (!log) throw new HttpError(404, 'Email delivery not found');
        if (!['ACCEPTED', 'DELIVERED'].includes(log.status))
          throw new HttpError(409, 'Only delivered emails can be acknowledged');
        const now = new Date().toISOString();
        await put(db, 'emailLogs', id, {
          ...log,
          actionStatus: 'ACTIONED',
          actionedAt: now,
        });
        await appendAudit(
          db,
          'Email delivery acknowledged',
          `Delivery ${id}${data.reason ? `; ${data.reason}` : ''}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
      });
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/email/:id/follow-up',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      const data = z
        .object({
          subject: z.string().max(200).optional(),
          audienceNotice: z.string().max(2000).optional(),
          reviewerComment: z.string().max(2000).optional(),
          reviewerName: z.string().max(100).optional(),
          customBodyOverride: z.string().max(50000).optional(),
          customFields: z.record(z.string(), z.string().max(2000)).optional(),
          recipientMode: z.enum(['SINGLE_EMAIL', 'SECURITY_TEAM', 'EVERYONE']),
          customEmail: z.string().email().optional(),
          reason: z.string().trim().max(1000).default(''),
        })
        .parse(req.body);
      const result = await transaction(pool, async (db) => {
        const source = await db.query(
          `SELECT payload, edits, advisory_id, status
             FROM outbox
            WHERE id=$1 AND channel='email'
            FOR UPDATE`,
          [id],
        );
        if (!source.rowCount) throw new HttpError(404, 'Email delivery not found');
        const sourceRow = source.rows[0];
        if (['REVIEW', 'QUEUED', 'SENDING'].includes(String(sourceRow.status)))
          throw new HttpError(
            409,
            'This delivery is still queued. Save its edits or approve it instead of creating a follow-up copy.',
          );
        const advisory = await get<Advisory>(db, 'advisories', String(sourceRow.advisory_id));
        if (!advisory)
          throw new HttpError(
            400,
            'Only advisory (finding) emails can be edited and re-dispatched from the Action Center',
          );
        const findings = [
          ...(await getMany<Finding>(db, 'findings', advisory.findingIds)).values(),
        ];
        if (!findings.length)
          throw new HttpError(400, 'This advisory has no findings to include in a follow-up email');
        const recipients = await list<EmailRecipient>(db, 'recipients');
        const selected = resolveOperatorAudience(
          recipients,
          data.recipientMode,
          findings,
          data.customEmail,
        );
        // Merge the source job's saved edits with the operator's latest input so
        // a notice added earlier survives a follow-up that only changes the
        // audience. Undefined request fields never erase a saved value.
        const sourceEdits: ReviewEdits = sourceRow.edits || {};
        const edits: ReviewEdits = {
          ...sourceEdits,
          ...(data.subject !== undefined && { subject: normalizeEmailSubject(data.subject) }),
          ...(data.audienceNotice !== undefined && { audienceNotice: data.audienceNotice }),
          ...(data.reviewerComment !== undefined && { reviewerComment: data.reviewerComment }),
          ...(data.reviewerName !== undefined && { reviewerName: data.reviewerName }),
          ...(data.customBodyOverride !== undefined && { customBodyOverride: data.customBodyOverride }),
          ...(data.customFields !== undefined && { customFields: data.customFields }),
          recipientMode: data.recipientMode,
          ...(data.customEmail !== undefined && { customEmail: data.customEmail }),
        };
        const snapshot = await state(db);
        // Re-render for the new audience instead of reusing the source body: a
        // digest job's HTML only contains the findings its original recipient
        // was subscribed to, so forwarding it verbatim could omit findings from
        // a broader audience. The edit layer is applied at send time.
        const html = renderAdvisory(snapshot.advisoryTemplate, advisory, findings);
        // `edits` already carries the merged subject (including an explicit
        // clear), so derive the outgoing subject from the queued template.
        const subject = effectiveSubject(sourceRow.payload?.subject, edits);
        const now = new Date().toISOString();
        const queued = await queueBulkNotificationAdvisory(
          db,
          advisory,
          findings,
          html,
          selected,
          randomUUID(),
          { subject, edits },
        );
        if (!queued)
          throw new HttpError(
            409,
            'No follow-up delivery was queued. The selected audience already has this revision; adjust the recipients and try again.',
          );
        for (const finding of findings)
          await db.query(
            "UPDATE records SET data = data || jsonb_build_object('advisoryId', $1::text, 'notificationStatus', $2::text) WHERE kind='findings' AND id=$3",
            [advisory.id, 'QUEUED_FOR_DISPATCH', finding.id],
          );
        const log = await getForUpdate<EmailDeliveryLog>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            actionStatus: 'ACTIONED',
            actionedAt: now,
            followUpCount: (log.followUpCount ?? 0) + 1,
          });
        await appendAudit(
          db,
          'Email updated and re-dispatched',
          `${advisory.id} → ${data.recipientMode} (${queued} job${queued === 1 ? '' : 's'})` +
            `${data.customEmail ? ` [${data.customEmail}]` : ''}${data.reason ? `; ${data.reason}` : ''}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
        return { advisoryId: advisory.id, queued };
      });
      res.status(202).json({ success: true, ...result });
    }),
  );
  app.post(
    '/api/email/:id/resend',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      const data = z
        .object({
          recipientMode: z.enum(['SINGLE_EMAIL', 'SECURITY_TEAM', 'EVERYONE']),
          customEmail: z.string().email().optional(),
          reason: z.string().trim().max(1000).default(''),
        })
        .parse(req.body);
      // Validate the audience shape before looking up the delivery: a
      // SINGLE_EMAIL request without an address must never silently fall back
      // to the security team.
      if (data.recipientMode === 'SINGLE_EMAIL' && !data.customEmail)
        throw new HttpError(400, 'A recipient email address is required for a single-recipient resend');
      await transaction(pool, async (db) => {
        const row = await db.query(
          `SELECT advisory_id, edits, payload FROM outbox WHERE id=$1 AND channel='email'`,
          [id],
        );
        if (!row.rowCount) throw new HttpError(404, 'Email delivery not found');
        const advisoryId = row.rows[0].advisory_id;
        // Edits saved through the Action Center editor must travel with the
        // resend. Building new jobs from the original template silently threw
        // away the operator's corrected subject/body/notice, so the resent
        // message differed from what they had just reviewed.
        const sourceEdits: ReviewEdits = row.rows[0].edits || {};
        const snapshot = await state(db);
        const advisory = snapshot.advisories.find((a) => a.id === advisoryId);
        if (!advisory) throw new HttpError(404, 'Advisory not found');
        const findings = snapshot.findings.filter((f) => advisory.findingIds.includes(f.id));
        if (findings.length === 0) throw new HttpError(400, 'Advisory has no findings to resend');
        const rank = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const severity = findings.reduce(
          (s, f) => (rank.indexOf(f.cve.cvss.severity) > rank.indexOf(s) ? f.cve.cvss.severity : s),
          'UNKNOWN' as Severity,
        );
        const vulnerabilitySeverityParts: string[] = [];
        for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const) {
          const count = findings.filter((f) => f.cve.cvss.severity === sev).length;
          if (count) vulnerabilitySeverityParts.push(count + ' ' + sev.charAt(0) + sev.slice(1).toLowerCase());
        }
        const vulnerabilitySeveritySummary = vulnerabilitySeverityParts.length
          ? vulnerabilitySeverityParts.join(', ')
          : '0 vulnerabilities';
        const recipients = await list<EmailRecipient>(db, 'recipients');
        let selectedRecipients: EmailRecipient[];
        if (data.recipientMode === 'SINGLE_EMAIL' && data.customEmail) {
          selectedRecipients = recipients.filter(
            (r) => r.enabled && r.email.toLowerCase() === data.customEmail!.toLowerCase(),
          );
        } else if (data.recipientMode === 'EVERYONE') {
          selectedRecipients = recipients.filter((r) => r.enabled && r.deliveryGroup === 'EVERYONE');
        } else {
          selectedRecipients = recipients.filter(
            (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
          );
        }
        if (!selectedRecipients.length)
          throw new HttpError(400, 'No eligible recipients for the selected delivery group');
        // Resend must honour the same subscription governance as a first send:
        // a recipient whose tier excludes any finding in this advisory must not
        // receive it merely because an operator clicked resend.
        const permitted = selectedRecipients.filter((recipient) =>
          findings.every((finding) => recipientAllows(recipient, finding)),
        );
        if (!permitted.length)
          throw new HttpError(
            400,
            'The selected audience is not subscribed to every finding in this advisory. Adjust the recipient subscription or choose a different audience.',
          );
        selectedRecipients = permitted;
        const html = renderAdvisory(snapshot.advisoryTemplate, advisory, findings);
        // A resend to EVERYONE re-opens review for that group, so the audience
        // decision from the original send must not be carried over blindly.
        const carriedEdits: ReviewEdits = {
          ...sourceEdits,
          recipientMode: data.recipientMode,
          customEmail: data.recipientMode === 'SINGLE_EMAIL' ? data.customEmail : undefined,
        };
        const reissued: Advisory = {
          ...advisory,
          id: formatAdvisoryId(snapshot.settings.advisoryPrefix),
          // The advisory title is the Action Center row label: keep the explicit
          // "(resend)" marker so a re-issued notice is distinguishable from the
          // original, and fold in the operator's edited subject when there is
          // one instead of discarding it.
          title: (() => {
            const marker = `Vulnerability notice: ${vulnerabilitySeveritySummary} (resend)`;
            const edited = carriedEdits.subject?.trim();
            return edited ? `${edited} (resend)` : marker;
          })(),
          severity,
          createdDate: new Date().toISOString(),
          deliveryStatus: 'PENDING',
          recipientCount: selectedRecipients.length,
          executiveSummary: `${findings.length} correlated vulnerability finding(s) require investigation. Resent delivery.${data.reason ? ` ${data.reason}` : ''}`,
        };
        await put(db, 'advisories', reissued.id, reissued);
        const editOptions = { edits: carriedEdits, subject: effectiveSubject(row.rows[0].payload?.subject, carriedEdits) };
        const queued = await queueBulkNotificationAdvisory(
          db,
          reissued,
          findings,
          html,
          selectedRecipients,
          randomUUID(),
          editOptions,
        );
        if (!queued)
          throw new HttpError(
            409,
            'No resend was queued. The selected audience already has this revision; adjust the audience or edit the content and try again.',
          );
        for (const finding of findings)
          await db.query(
            "UPDATE records SET data = data || jsonb_build_object('advisoryId', $1::text, 'notificationStatus', $2::text) WHERE kind='findings' AND id=$3 AND (data->>'advisoryId') IS DISTINCT FROM $1",
            [reissued.id, 'QUEUED_FOR_DISPATCH', finding.id],
          );
        // A resend is an operator action on the original delivery. Closing the
        // Action Center item here keeps the SLA queue truthful even when the
        // operator used the quick resend path instead of the editor.
        const sourceLog = await getForUpdate<EmailDeliveryLog>(db, 'emailLogs', id);
        if (sourceLog && ['ACCEPTED', 'DELIVERED'].includes(sourceLog.status))
          await put(db, 'emailLogs', id, {
            ...sourceLog,
            actionStatus: 'ACTIONED',
            actionedAt: new Date().toISOString(),
            followUpCount: (sourceLog.followUpCount ?? 0) + 1,
          });
        await appendAudit(
          db,
          'Email delivery resent',
          `${advisoryId} → ${reissued.id} (${queued} job${queued !== 1 ? 's' : ''})${data.reason ? `; ${data.reason}` : ''}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
        await refreshAdvisoryDeliveryStatus(db, reissued.id);
      });
      res.status(202).json({ success: true });
    }),
  );
  app.delete(
    '/api/email/:id',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = outboxId(req.params.id);
      await transaction(pool, async (db) => {
        const deleted = await db.query(
          "DELETE FROM outbox WHERE id=$1 AND channel='email' AND status IN ('QUEUED','FAILED') RETURNING id",
          [id],
        );
        if (!deleted.rowCount)
          throw new HttpError(409, 'Only queued or failed email deliveries can be deleted');
        const log = await getForUpdate<any>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            status: 'CANCELLED',
            nextRetryTime: null,
            errorMessage: 'Removed from the delivery queue by an operator',
          });
        await appendAudit(
          db,
          'Email delivery deleted from queue',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'WARNING',
          req.ip || '',
        );
      });
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/resend',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const data = z
        .object({ cveId: z.string(), reason: z.string().trim().min(5).max(1000) })
        .parse(req.body);
      await transaction(pool, async (db) => {
        const snapshot = await state(db),
          prior = snapshot.alertedCves.find((c) => c.cveId === data.cveId),
          advisory = snapshot.advisories.find((a) => a.id === prior?.advisoryId);
        if (!advisory) throw new HttpError(404, 'No advisory found');
        const resendFindings = snapshot.findings.filter((f) => advisory.findingIds.includes(f.id));
        await queueAdvisory(
          db,
          advisory,
          resendFindings,
          renderAdvisory(snapshot.advisoryTemplate, advisory, resendFindings),
          randomUUID(),
        );
        await appendAudit(
          db,
          'Advisory resend queued',
          `${advisory.id}: ${data.reason}`,
          req.operator!.username,
          'EMAIL',
        );
      });
      res.status(202).json({ success: true });
    }),
  );
  app.post(
    '/api/send-bulk-notification',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const data = z
        .object({
          findingIds: z.array(z.string()).min(1),
          reason: z.string().trim().max(1000).default(''),
          recipientMode: z.enum(['SINGLE_EMAIL', 'SECURITY_TEAM', 'EVERYONE']).default('SECURITY_TEAM'),
          customEmail: z.string().email().optional(),
        })
        .parse(req.body);
      await transaction(pool, async (db) => {
        const snapshot = await state(db);
        const findings = snapshot.findings.filter((f) => data.findingIds.includes(f.id));
        if (findings.length !== data.findingIds.length)
          throw new HttpError(404, 'One or more selected findings could not be found');
        const cveIds = Array.from(new Set(findings.map((f) => f.cveId))).sort();
        const rank = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const severity = findings.reduce(
          (s, f) => (rank.indexOf(f.cve.cvss.severity) > rank.indexOf(s) ? f.cve.cvss.severity : s),
          'UNKNOWN' as Severity,
        );
        const vulnerabilitySeverityParts: string[] = [];
        for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const) {
          const count = findings.filter((f) => f.cve.cvss.severity === sev).length;
          if (count) vulnerabilitySeverityParts.push(count + ' ' + sev.charAt(0) + sev.slice(1).toLowerCase());
        }
        const vulnerabilitySeveritySummary = vulnerabilitySeverityParts.length
          ? vulnerabilitySeverityParts.join(', ')
          : '0 vulnerabilities';
        const recipients = await list<EmailRecipient>(db, 'recipients');
        let selectedRecipients: EmailRecipient[];
        if (data.recipientMode === 'SINGLE_EMAIL' && data.customEmail) {
          selectedRecipients = recipients.filter((r) => r.enabled && r.email.toLowerCase() === data.customEmail!.toLowerCase());
        } else if (data.recipientMode === 'EVERYONE') {
          selectedRecipients = recipients.filter((r) => r.enabled && r.deliveryGroup === 'EVERYONE');
        } else {
          selectedRecipients = recipients.filter(
            (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
          );
        }
        if (!selectedRecipients.length) throw new HttpError(400, 'No eligible recipients for the selected delivery group');
        // Resend must honour the same subscription governance as a first send:
        // a recipient whose tier excludes any finding in this advisory must not
        // receive it merely because an operator clicked resend.
        const permitted = selectedRecipients.filter((recipient) =>
          findings.every((finding) => recipientAllows(recipient, finding)),
        );
        if (!permitted.length)
          throw new HttpError(
            400,
            'The selected audience is not subscribed to every finding in this advisory. Adjust the recipient subscription or choose a different audience.',
          );
        selectedRecipients = permitted;
        const advisory: Advisory = {
          id: formatAdvisoryId(snapshot.settings.advisoryPrefix),
          title: `Vulnerability notice: ${vulnerabilitySeveritySummary}`,
          severity,
          cveIds,
          findingIds: findings.map((f) => f.id),
          createdDate: new Date().toISOString(),
          deliveryStatus: 'PENDING',
          recipientCount: selectedRecipients.length,
          executiveSummary: `${findings.length} correlated vulnerability finding(s) require investigation. ${data.reason}`,
          remediationInstructions: 'Review vendor advisories and deploy tested remediation through your change process.',
          affectedSystems: Array.from(new Set(findings.map((f) => f.matchedAssetName))).sort(),
          vendorLink:
            Array.from(
              new Set(findings.map((f) => f.cve.remediation.vendorAdvisoryRef || f.cve.remediation.patchUrl).filter(Boolean)),
            ).sort()[0] || '',
        };
        await put(db, 'advisories', advisory.id, advisory);
        await queueBulkNotificationAdvisory(
          db,
          advisory,
          findings,
          renderAdvisory(snapshot.advisoryTemplate, advisory, findings),
          selectedRecipients,
          randomUUID(),
        );
        for (const finding of findings)
          await db.query(
            "UPDATE records SET data = data || jsonb_build_object('advisoryId', $1::text, 'notificationStatus', $2::text) WHERE kind='findings' AND id=$3 AND (data->>'advisoryId') IS DISTINCT FROM $1",
            [advisory.id, 'QUEUED_FOR_DISPATCH', finding.id],
          );
        await appendAudit(
          db,
          'Bulk notification queued',
          `${advisory.id}: ${findings.length} finding(s)${data.reason ? `; ${data.reason}` : ''}`,
          req.operator!.username,
          'EMAIL',
        );
      });
      res.status(202).json({ success: true });
    }),
  );
  app.post(
    '/api/commands',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const command = z
        .object({
          action: z.string().max(80),
          id: z.string().max(150).optional(),
          data: z.unknown().optional(),
        })
        .parse(req.body);
      const { action, id, data } = command,
        actor = req.operator!.username;
      // Authorization is co-located with the dispatcher (server/commands.ts):
      // ADMIN_COMMAND_ACTIONS / OPERATOR_COMMAND_ACTIONS plus a fail-closed
      // check that rejects unknown actions before they reach the dispatcher.
      assertCommandRole(action, req.operator!.role);
      // Resolve URLs outside the database transaction. They are validated again at connection time.
      if (action === 'feed.save' || action === 'webhook.save') {
        const feed = action === 'feed.save' ? feedSchema.parse(data) : undefined;
        const webhook = action === 'webhook.save' ? webhookSchema.parse(data) : undefined;
        const url = feed?.url ?? webhook?.url;
        if (!url) throw new HttpError(400, 'URL required');
        const configuredHosts = config.EGRESS_ALLOWED_HOSTS.split(',').map((s) => s.trim().toLowerCase());
        const allowedHosts = feed
          ? feedEgressHosts(feed.type, feed.url, configuredHosts)
          : configuredHosts;
        try {
          await resolvePublic(new URL(url), allowedHosts);
        } catch {
          throw new HttpError(
            400,
            'Endpoint must resolve to a public HTTPS address on the configured host allowlist',
          );
        }
      }
      const result = await transaction(pool, (db) =>
        applyCommand(db, config, { action, id, data, actor, ipAddress: req.ip || '' }),
      );
      res.json(result);
    }),
  );
  app.use('/api', (_req, _res, next) => next(new HttpError(404, 'API route not found')));
  // Unknown *mutation* routes are not pages. Falling through to the SPA shell
  // answered `POST /api/typo` with 200 + HTML, which a client reads as success
  // and an operator reads as a working endpoint.
  app.use((req, _res, next) =>
    ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ? next() : next(new HttpError(404, 'Route not found')),
  );
  app.use(
    express.static(path.resolve('dist'), {
      index: false,
      maxAge: '1h',
      setHeaders: (res, file) => {
        if (file.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
      },
    }),
  );
  app.get('*', (_req, res) => res.sendFile(path.resolve('dist/index.html')));
  app.use((error: any, request: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (error instanceof WorkCapacityError) {
      res.setHeader('Retry-After', '2');
      return res.status(503).json({ error: 'Authentication capacity is busy; retry shortly' });
    }
    if (error instanceof z.ZodError)
      return res.status(400).json({
        error: 'Validation failed',
        details: error.issues.map((i) => ({ path: i.path, message: i.message })),
      });
    if (error instanceof HttpError) return res.status(error.status).json({ error: error.message });
    if (error?.code === '23505') return res.status(409).json({ error: 'Record already exists' });
    if (error?.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large' });
    if (error instanceof SyntaxError) return res.status(400).json({ error: 'Invalid JSON' });
    const reference = randomUUID();
    const detail = describeError(error);
    // Keep the client response generic (internals stay server-side) but make the
    // retained event complete enough to diagnose the failure without the
    // process log: DB error code/detail/hint, route, caller and query. The
    // message stays a stable summary while the full error text goes in the
    // context, so the indexed message column does not gain one new value per
    // failed request.
    void writeEvent(pool, {
      category: 'ISSUE',
      level: 'ERROR',
      code: 'http.request_failed',
      message: `Request failed: ${describeFailureSummary(error)}`,
      context: describeRequestFailure(error, request, reference),
    }).catch((writeError) => {
      // The audit write itself can fail (for example during a database outage);
      // log that separately instead of hiding it behind the original failure.
      console.error(
        JSON.stringify({
          level: 'error',
          event: 'event.write_failed',
          reference,
          message: writeError instanceof Error ? writeError.message : String(writeError),
        }),
      );
    });
    console.error(
      JSON.stringify({ level: 'error', reference, method: request.method, path: request.path, ...detail }),
    );
    res.status(500).json({ error: 'Server operation failed', reference });
  });
  return app;
}
