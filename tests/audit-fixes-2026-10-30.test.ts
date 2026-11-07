import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate, put, get } from '../server/db.ts';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { reconcileFindings } from '../src/engine/reconcileFindings.ts';
import { deliverNext, enqueue, queueAdvisory, queueDigestAdvisory } from '../server/delivery.ts';
import { isSmtpEmailProvider, type EmailProvider } from '../src/types/index.ts';
import { emailIsConfigured } from '../server/emailProviders.ts';
import { createUser } from '../server/auth.ts';
import { createApp } from '../server/app.ts';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  type DailyDigestParts,
} from '../src/utils/templateCompiler.ts';
import type {
  Advisory,
  EmailConfiguration,
  Finding,
  NormalizedCVE,
  WatchListItem,
} from '../src/types/index.ts';

/**
 * Regressions for the 30 October 2026 audit.
 *
 * Each case reproduces a defect that was confirmed against the previous
 * implementation before the corresponding fix was written.
 */

const database = process.env.TEST_DATABASE_URL;

// ---------------------------------------------------------------------------
// Pure logic: no database required.
// ---------------------------------------------------------------------------

test('reconciliation keeps a terminal DELIVERY_FAILED finding from being auto-requeued', () => {
  const cve = {
    cveId: 'CVE-2026-70001',
    title: 'Fixture',
    description: '',
    publishedDate: new Date().toISOString(),
    modifiedDate: new Date().toISOString(),
    cvss: { version: '3.1', score: 8, severity: 'HIGH', vector: '' },
    cwe: [],
    cpeMatches: [],
    sourceFeeds: [],
    epss: { score: 0, percentile: 0 },
    cisaKev: { isKev: false },
    exploitStatus: 'None',
    remediation: {},
  } as unknown as NormalizedCVE;
  const base = {
    id: 'finding',
    cveId: cve.cveId,
    cve,
    matchedAssetId: 'asset',
    matchedAssetName: 'edge (acme router)',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'router',
    matchedCpe: 'cpe:2.3:a:acme:router:1.0:*:*:*:*:*:*:*',
    matchingEvidence: 'Structured package/version correlation',
    status: 'MONITORED',
    autoDispatchedAt: null,
    timeline: [],
  } as unknown as Finding;
  const failed = { ...base, notificationStatus: 'DELIVERY_FAILED', advisoryId: 'ADV-1' } as Finding;
  // A pipeline candidate is freshly built and always starts as dispatchable.
  const candidate = {
    ...failed,
    id: 'new',
    advisoryId: null,
    notificationStatus: 'QUEUED_FOR_DISPATCH',
  } as Finding;
  assert.equal(
    reconcileFindings([failed], [candidate])[0].notificationStatus,
    'DELIVERY_FAILED',
    'a failed delivery must not become an automatic resend on the next pipeline run',
  );
  // A rebuild that re-queued the finding is still allowed to clear the failure.
  const rebuilt = { ...failed, advisoryId: null } as Finding;
  assert.equal(
    reconcileFindings([rebuilt], [candidate])[0].notificationStatus,
    'QUEUED_FOR_DISPATCH',
  );
  // A finding whose only advisory was a rejected bundle keeps recovering: the
  // pipeline clears `advisoryId` before reconciliation, which is the explicit
  // operator-visible re-queue path (see `staleBundles` in processPipeline).
  // NOTE: `autoDispatchedAt` must NOT be part of that decision. It is stamped by
  // the *first* successful acceptance, so a later failed re-delivery of a
  // finding that still carries its advisory used to satisfy the old
  // `autoDispatchedAt || advisoryId === null` fallback and was re-queued — a
  // duplicate email for unchanged content on the next run. That case is covered
  // by the first assertion above (`failed`, which has an advisory and no
  // autoDispatchedAt); this second one pins the cleared-advisory recovery path
  // even when the finding was once accepted.
  const failedAfterAcceptance = {
    ...failed,
    advisoryId: null,
    autoDispatchedAt: '2026-01-01T00:00:00.000Z',
  } as Finding;
  assert.equal(
    reconcileFindings([failedAfterAcceptance], [candidate])[0].notificationStatus,
    'QUEUED_FOR_DISPATCH',
    'a finding whose bundle was cleared for rebuild is re-queueable',
  );
});

test('reconciliation never turns an already-announced finding back into a resend', () => {
  // The matcher rebuilds its candidate set on every run, so a refreshed CVE
  // record re-derives the finding and the candidate always starts as
  // QUEUED_FOR_DISPATCH. `reviewNotifiedAt` is the durable record that the
  // finding was delivered in a consolidated email; without this guard the next
  // run queued the same finding again (a duplicate email for content the
  // recipient already had).
  const cve = {
    cveId: 'CVE-2026-70002',
    title: 'Fixture',
    description: '',
    publishedDate: new Date().toISOString(),
    modifiedDate: new Date().toISOString(),
    cvss: { version: '3.1', score: 8, severity: 'HIGH', vector: '' },
    cwe: [],
    cpeMatches: [],
    sourceFeeds: [],
    epss: { score: 0, percentile: 0 },
    cisaKev: { isKev: false },
    exploitStatus: 'None',
    remediation: {},
  } as unknown as NormalizedCVE;
  const announced = {
    id: 'finding-announced',
    cveId: cve.cveId,
    cve,
    matchedAssetId: 'asset',
    matchedAssetName: 'edge (acme router)',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'router',
    matchedCpe: 'cpe:2.3:a:acme:router:1.0:*:*:*:*:*:*:*',
    matchingEvidence: 'Structured package/version correlation',
    confidence: 70,
    notificationStatus: 'AUTO_DISPATCHED',
    status: 'MONITORED',
    autoDispatchedAt: '2026-01-01T00:00:00.000Z',
    reviewNotifiedAt: '2026-01-02T00:00:00.000Z',
    timeline: [],
  } as unknown as Finding;
  // The fresh candidate: same identity, stripped advisory, dispatchable status.
  const candidate = {
    ...announced,
    id: 'finding-regenerated',
    advisoryId: null,
    autoDispatchedAt: null,
    reviewNotifiedAt: null,
    notificationStatus: 'QUEUED_FOR_DISPATCH',
  } as Finding;
  for (const existing of [
    announced,
    { ...announced, advisoryId: 'ADV-1' } as Finding,
    { ...announced, notificationStatus: 'QUEUED_FOR_DISPATCH', advisoryId: null } as Finding,
  ]) {
    const [reconciled] = reconcileFindings([existing], [candidate]);
    assert.notEqual(
      reconciled.notificationStatus,
      'QUEUED_FOR_DISPATCH',
      'an announced finding must not be re-selected for dispatch',
    );
    assert.equal(reconciled.reviewNotifiedAt, '2026-01-02T00:00:00.000Z', 'the announcement stamp is preserved');
  }
});

const digestParts = (executiveSummary: string): DailyDigestParts => ({
  advisory_id: 'ADV-1',
  advisory_title: 'Daily',
  dispatch_date: new Date().toISOString(),
  severity: 'HIGH',
  finding_count: 1,
  severity_counts: '1 high',
  findings_summary: '',
  health_report: '',
  recipient_name: 'Team',
  critical_count: 0,
  high_count: 1,
  medium_count: 0,
  low_count: 0,
  asset_count: 1,
  executive_summary: executiveSummary,
  report_generated: 'now',
  critical_summary: '',
  high_summary: '',
  medium_summary: '',
  low_summary: '',
  critical_kpi: '',
  high_kpi: '',
  medium_kpi: '',
  low_kpi: '',
});

test('the digest executive summary keeps generated markup and escapes anything else', () => {
  const generated =
    'A total of <strong>1 vulnerability</strong> were identified during the latest monitoring cycle, including <strong>1 High</strong> severity findings across monitored assets. Immediate remediation of critical findings is recommended while medium and low severity items should be addressed according to established risk treatment and vulnerability management procedures.';
  assert.ok(
    renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, digestParts(generated)).includes(
      '<strong>1 vulnerability</strong>',
    ),
    'the generated sentence keeps its emphasis markup',
  );
  const injected = generated.replace('monitored assets', 'monitored assets <img src=x onerror=alert(1)>');
  assert.ok(
    !renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, digestParts(injected)).includes('<img src=x'),
    'operator-editable text cannot become live markup in a delivered email',
  );
});

test('the custom API provider is an HTTP channel, not an SMTP relay', () => {
  assert.equal(isSmtpEmailProvider('API' as EmailProvider), false);
  assert.equal(isSmtpEmailProvider('SENDGRID' as EmailProvider), false);
  assert.equal(isSmtpEmailProvider('SMTP' as EmailProvider), true);
  const api = {
    provider: 'API',
    apiEndpoint: 'https://relay.example.com/send',
    fromEmail: 'security@example.com',
    apiKey: 'encrypted',
  } as unknown as EmailConfiguration;
  const env = { SMTP_HOST: '', SMTP_FROM: '' };
  assert.equal(emailIsConfigured(api, env), true);
  // Without its endpoint the API provider is not usable and must not fall back
  // to the deployment SMTP relay.
  assert.equal(emailIsConfigured({ ...api, apiEndpoint: '' }, env), false);
});

// ---------------------------------------------------------------------------
// Database-backed delivery regressions.
// ---------------------------------------------------------------------------

test(
  'delivery audit fixes: operator approval, failure isolation, duplicate suppression and receipts',
  { skip: !database },
  async (t) => {
    const base = createPool(database!);
    const schema = 'audit_fixes_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://127.0.0.1:3997',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      WORKER_ENABLED: 'false',
      // The advisory body carries the delivery id, so a prior 200 is always
      // attributable; confirm-before-send stays on (its default).
      MAIL_CONFIRM_BEFORE_SEND: 'true',
      ATTACH_ADVISORY_PDF: 'false',
    });
    const cpe = 'cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*';
    const asset: WatchListItem = {
      id: 'asset',
      vendor: 'example',
      product: 'widget',
      version: '1.5',
      cpes: [cpe],
      assetTag: 'EDGE-1',
      ownerGroup: 'Security',
      active: true,
      createdAt: new Date().toISOString(),
    };
    const makeCve = (id: string): NormalizedCVE => ({
      cveId: id,
      title: 'Security update',
      description: 'Fixture',
      publishedDate: new Date().toISOString(),
      modifiedDate: new Date().toISOString(),
      cvss: { version: '3.1', score: 8, severity: 'HIGH', vector: '' },
      cwe: [],
      cpeMatches: [cpe],
      sourceFeeds: [],
      epss: { score: 0, percentile: 0 },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      remediation: {
        patchUrl: '',
        vendorAdvisoryRef: '',
        immediateActions: [],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    });
    const noNetwork = async () => {
      throw new Error('No network expected');
    };
    const reset = async () => {
      await pool.query('DELETE FROM records; DELETE FROM outbox');
      await put(pool, 'settings', 'main', {
        ...DEFAULT_SETTINGS,
        autoDispatchEnabled: false,
        // Retries must be permitted for a retry (and therefore its confirmation)
        // to be reachable at all.
        emailRetryEnabled: true,
        emailRetryMaxAttempts: 5,
      });
      await put(pool, 'watchlist', asset.id, asset);
    };
    const seedFinding = async (id: string) => {
      const cve = makeCve(id);
      await put(pool, 'cveData', cve.cveId, cve);
      const [finding] = runVulnerabilityPipeline(
        [],
        [cve],
        [asset],
        [],
        [],
        { ...DEFAULT_SETTINGS, scopeHours: 0 },
        'test',
        false,
      ).newFindings;
      assert.ok(finding);
      await put(pool, 'findings', finding.id, finding);
      return finding;
    };
    const advisoryFor = (finding: Finding): Advisory => ({
      id: 'ADV-' + randomUUID().slice(0, 8),
      title: `Notice ${finding.cveId}`,
      severity: 'HIGH',
      cveIds: [finding.cveId],
      findingIds: [finding.id],
      createdDate: new Date().toISOString(),
      deliveryStatus: 'PENDING',
      recipientCount: 1,
      executiveSummary: 'Fixture summary',
      remediationInstructions: 'Apply the vendor update.',
      affectedSystems: [finding.matchedAssetName],
    });

    try {
      await migrate(pool);

      await t.test('approval keeps the operator-pinned revision on a digest bundle', async () => {
        await reset();
        const high = await seedFinding('CVE-2026-71001');
        const lowCve = {
          ...makeCve('CVE-2026-71002'),
          cvss: { version: '3.1' as const, score: 2, severity: 'LOW' as const, vector: '' },
        };
        await put(pool, 'cveData', lowCve.cveId, lowCve);
        const [low] = runVulnerabilityPipeline(
          [],
          [lowCve],
          [asset],
          [],
          [],
          { ...DEFAULT_SETTINGS, scopeHours: 0 },
          'test',
          false,
        ).newFindings;
        await put(pool, 'findings', low.id, low);
        await put(pool, 'recipients', 'high-only', {
          id: 'high-only',
          name: 'high-only',
          email: 'high-only@example.invalid',
          enabled: true,
          // EVERYONE exercises the deferred-broadcast path. The job is queued for
          // delivery (there is no review queue); the editor and the approve route
          // work on a queued job, which is what this test pins.
          deliveryGroup: 'EVERYONE',
          subscriptionTier: 'CRITICAL_HIGH_ONLY',
        });
        // A mixed digest: the recipient's view is a strict subset of the union.
        const union = advisoryFor(high);
        union.findingIds = [high.id, low.id];
        union.cveIds = [high.cveId, low.cveId];
        const queued = await queueDigestAdvisory(pool, union, [high, low], () => '<html></html>');
        assert.equal(queued.jobs, 1, 'the subscriber receives exactly one job');
        const job = (await pool.query('SELECT id, payload FROM outbox')).rows[0];
        assert.deepEqual(job.payload.cveIds, [high.cveId], 'only the permitted finding is included');
        assert.ok(job.payload.contentRevision, 'the pinned revision is persisted with the payload');

        // A reviewer adds a comment, which changes the stored body.
        // An OPERATOR may edit a held advisory body; the admin role has no
        // review workflow surface of its own.
        await createUser(pool, 'audit-admin', 'Audit-fixes-password-2026!', 'OPERATOR');
        const app = createApp(pool, config, noNetwork);
        const agent = supertest.agent(app);
        const login = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username: 'audit-admin', password: 'Audit-fixes-password-2026!' });
        assert.equal(login.status, 200, JSON.stringify(login.body));
        const csrf = login.body.csrfToken as string;
        assert.ok(csrf, 'login must return a CSRF token');
        const edited = await agent
          .post(`/api/email/${job.id}/edit`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          .send({ reviewerComment: 'Reviewed by the security team' });
        assert.equal(edited.status, 200, JSON.stringify(edited.body));
        const approved = await agent
          .post(`/api/email/${job.id}/approve`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          .send({});
        assert.equal(approved.status, 200, JSON.stringify(approved.body));

        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'accepted-id';
        });
        assert.equal(sent, 1, 'an approved digest job reaches the transport');
        assert.equal(
          (await pool.query('SELECT status FROM outbox WHERE id=$1', [job.id])).rows[0].status,
          'ACCEPTED',
        );
      });

      await t.test('an unconfirmed earlier attempt is never re-sent', async () => {
        await reset();
        const finding = await seedFinding('CVE-2026-72001');
        await put(pool, 'recipients', 'ops', {
          id: 'ops',
          name: 'ops',
          email: 'ops@example.invalid',
          enabled: true,
          deliveryGroup: 'SECURITY_TEAM',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        const advisory = advisoryFor(finding);
        await put(pool, 'advisories', advisory.id, advisory);
        const jobId = await enqueue(
          pool,
          'email',
          'ops',
          advisory.id,
          {
            subject: 'Fixture',
            text: 'Fixture',
            cveIds: [advisory.cveIds[0]!],
            recipientEmail: 'ops@example.invalid',
            // The provider accepted the message but the receipt was never committed.
            unconfirmedProviderId: 'provider-message-1',
          },
          'audit-fixes-unconfirmed',
        );
        assert.ok(jobId);
        // This is the HTTP-provider case: the provider returned an id, so an
        // earlier attempt may have been accepted. Configure a queryable provider
        // (the lookup itself is exercised in tests/delivery-confirmation.test.ts).
        await put(pool, 'emailConfig', 'main', {
          provider: 'SENDGRID',
          apiKey: 'cipher',
          fromEmail: 'security@example.invalid',
          fromName: 'Security',
          replyTo: '',
          unsubscribeUrl: '',
        });
        // Make it look like a retry of an earlier attempt.
        await pool.query('UPDATE outbox SET attempts=2 WHERE id=$1', [jobId]);
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'second-copy';
        });
        assert.equal(sent, 0, 'a message that may already have been delivered is not sent again');
        // The outcome is unresolved rather than disproven, so the job stays
        // retryable and is re-confirmed on the next attempt instead of being
        // failed outright. (A provider verdict is covered in
        // tests/delivery-confirmation.test.ts.)
        assert.equal(
          (await pool.query('SELECT status FROM outbox WHERE id=$1', [jobId])).rows[0].status,
          'QUEUED',
        );
      });

      await t.test('a rejected HTTP attempt is retried rather than withheld', async () => {
        await reset();
        const finding = await seedFinding('CVE-2026-73001');
        const advisory = advisoryFor(finding);
        await put(pool, 'advisories', advisory.id, advisory);
        await put(pool, 'recipients', 'ops-2', {
          id: 'ops-2',
          name: 'ops-2',
          email: 'ops-2@example.invalid',
          enabled: true,
          deliveryGroup: 'SECURITY_TEAM',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        const jobId = await enqueue(
          pool,
          'email',
          'ops-2',
          advisory.id,
          {
            subject: 'Fixture',
            text: 'Fixture',
            html: '<p>Fixture</p>',
            cveIds: [advisory.cveIds[0]!],
            recipientEmail: 'ops-2@example.invalid',
          },
          'audit-fixes-rejected',
        );
        assert.ok(jobId);
        await put(pool, 'emailLogs', jobId!, {
          id: jobId,
          recipientEmail: 'ops-2@example.invalid',
          advisoryId: advisory.id,
          subject: 'Fixture',
          status: 'RETRYING',
          attemptCount: 1,
          retrySchedule: [],
          nextRetryTime: new Date().toISOString(),
          sentAt: '',
          errorMessage: 'SendGrid HTTP 503 unavailable',
        });
        await pool.query('UPDATE outbox SET attempts=2,next_attempt=now() WHERE id=$1', [jobId]);
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'accepted-later';
        });
        const after = JSON.stringify((await pool.query('SELECT status,error FROM outbox WHERE id=$1', [jobId])).rows);
        assert.equal(sent, 1, `a provably refused request may be retried (${after})`);
      });

      await t.test('a broken revalidation defers the job instead of losing the batch', async () => {
        await reset();
        const finding = await seedFinding('CVE-2026-74001');
        const advisory = advisoryFor(finding);
        await put(pool, 'advisories', advisory.id, advisory);
        const jobId = await enqueue(
          pool,
          'email',
          'ops-3',
          advisory.id,
          {
            subject: 'Fixture',
            text: 'Fixture',
            cveIds: advisory.cveIds,
            recipientEmail: 'ops-3@example.invalid',
            findingRevisions: { [finding.id]: 'r1' },
            cveRevisions: { [finding.cveId]: 'r1' },
            contentRevision: 'r1',
          },
          'audit-fixes-revalidation',
        );
        assert.ok(jobId);
        // Corrupt the stored inventory row so revalidation cannot run.
        await pool.query("UPDATE records SET data='null'::jsonb WHERE kind='watchlist' AND id=$1", [asset.id]);
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'must-not-send';
        });
        assert.equal(sent, 0, 'an unprovable bundle never reaches the transport');
        const row = (await pool.query('SELECT status,lock_token FROM outbox WHERE id=$1', [jobId])).rows[0];
        assert.notEqual(row.status, 'SENDING', 'the job must be committed, not left in flight');
        assert.equal(row.lock_token, null);
      });
      await t.test('EVERYONE recipients are deferred until Security-team delivery is accepted', async () => {
        await reset();
        await put(pool, 'settings', 'main', {
          ...DEFAULT_SETTINGS,
          autoDispatchEnabled: true,
          deferEveryoneUntilSecurityDelivered: true,
        });
        await put(pool, 'recipients', 'sec', {
          id: 'sec',
          name: 'Security Team',
          email: 'sec@example.invalid',
          enabled: true,
          deliveryGroup: 'SECURITY_TEAM',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await put(pool, 'recipients', 'everyone', {
          id: 'everyone',
          name: 'Everyone',
          email: 'everyone@example.invalid',
          enabled: true,
          deliveryGroup: 'EVERYONE',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        const finding = await seedFinding('CVE-2026-73001');
        const advisory = advisoryFor(finding);
        const html = '<html><body>Advisory body</body></html>';
        const count = await queueAdvisory(pool, advisory, [finding], html);
        assert.equal(count, 1, 'only SECURITY_TEAM recipient is queued; EVERYONE is deferred');

        const initialJobs = await pool.query('SELECT target_id, status FROM outbox');
        assert.equal(initialJobs.rowCount, 1, 'exactly one job queued');
        assert.equal(initialJobs.rows[0].target_id, 'sec');

        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'accepted';
        });
        assert.equal(sent, 1, 'security-team email is delivered');

        const everyoneJob = await pool.query(
          'SELECT target_id, status, payload FROM outbox WHERE target_id=$1',
          ['everyone'],
        );
        assert.equal(everyoneJob.rowCount, 1, 'EVERYONE job was queued after security delivery');
        assert.equal(everyoneJob.rows[0].status, 'QUEUED', 'EVERYONE job is queued for delivery, not review');
        assert.equal(everyoneJob.rows[0].payload.recipientEmail, 'everyone@example.invalid');
        assert.ok(everyoneJob.rows[0].payload.html.includes('Advisory body'), 'same email body as the security delivery');

        const secJob = await pool.query('SELECT status FROM outbox WHERE target_id=$1', ['sec']);
        assert.equal(secJob.rows[0].status, 'ACCEPTED');
      });
      await t.test('a deferred EVERYONE job is editable before its broadcast is delivered', async () => {
        await reset();
        await put(pool, 'settings', 'main', {
          ...DEFAULT_SETTINGS,
          autoDispatchEnabled: true,
          deferEveryoneUntilSecurityDelivered: true,
        });
        await put(pool, 'recipients', 'sec', {
          id: 'sec',
          name: 'Security Team',
          email: 'sec@example.invalid',
          enabled: true,
          deliveryGroup: 'SECURITY_TEAM',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await put(pool, 'recipients', 'everyone', {
          id: 'everyone',
          name: 'Everyone',
          email: 'everyone@example.invalid',
          enabled: true,
          deliveryGroup: 'EVERYONE',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        const finding = await seedFinding('CVE-2026-73003');
        const advisory = advisoryFor(finding);
        await queueAdvisory(pool, advisory, [finding], '<html><body>Original</body></html>');

        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'accepted';
        });
        assert.equal(sent, 1);

        // The deferred EVERYONE job is queued for delivery; an operator may still
        // apply live edits to it before the worker picks it up. A queued job is due
        // immediately, so this test pins it to the future to model "edited before
        // the broadcast worker ran" rather than depending on tick ordering.
        const reviewRow = await pool.query('SELECT id FROM outbox WHERE target_id=$1 AND status=$2', ['everyone', 'QUEUED']);
        assert.equal(reviewRow.rowCount, 1);
        await pool.query("UPDATE outbox SET next_attempt=now()+interval '1 hour' WHERE id=$1", [reviewRow.rows[0].id]);

        // Operator can edit the queued job with live changes
        await createUser(pool, 'everyone-admin', 'Everyone-test-password-2026!', 'OPERATOR');
        const app = createApp(pool, config, noNetwork);
        const agent = supertest.agent(app);
        const login = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username: 'everyone-admin', password: 'Everyone-test-password-2026!' });
        const csrf = login.body.csrfToken as string;

        const editRes = await agent
          .post(`/api/email/${reviewRow.rows[0].id}/edit`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          .send({ reviewerComment: 'Verified for broad distribution', reviewerName: 'Security Lead' });
        assert.equal(editRes.status, 200);

        const previewRes = await agent
          .get(`/api/email/${reviewRow.rows[0].id}/preview`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          .send();
        assert.equal(previewRes.status, 200);
        assert.ok(previewRes.body.html.includes('Verified for broad distribution'));

        const approved = await agent
          .post(`/api/email/${reviewRow.rows[0].id}/approve`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          .send({});
        assert.equal(approved.status, 200);

        // Approval confirms the edits and leaves the job queued and deliverable.
        const approvedRow = await pool.query('SELECT status FROM outbox WHERE id=$1', [reviewRow.rows[0].id]);
        assert.equal(approvedRow.rows[0].status, 'QUEUED');

        let broadcastSent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          broadcastSent++;
          return 'everyone-accepted';
        });
        assert.equal(broadcastSent, 1, 'EVERYONE email is sent after approval');
        const finalRow = await pool.query('SELECT status FROM outbox WHERE id=$1', [reviewRow.rows[0].id]);
        assert.equal(finalRow.rows[0].status, 'ACCEPTED');
      });
      await t.test('EVERYONE deferral does not queue when setting is disabled', async () => {
        await reset();
        await put(pool, 'settings', 'main', {
          ...DEFAULT_SETTINGS,
          autoDispatchEnabled: true,
          deferEveryoneUntilSecurityDelivered: false,
        });
        await put(pool, 'recipients', 'sec', {
          id: 'sec',
          name: 'Security Team',
          email: 'sec@example.invalid',
          enabled: true,
          deliveryGroup: 'SECURITY_TEAM',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await put(pool, 'recipients', 'everyone', {
          id: 'everyone',
          name: 'Everyone',
          email: 'everyone@example.invalid',
          enabled: true,
          deliveryGroup: 'EVERYONE',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        const finding = await seedFinding('CVE-2026-73004');
        const advisory = advisoryFor(finding);
        const count = await queueAdvisory(pool, advisory, [finding], '<html></html>');
        assert.equal(count, 2, 'both recipients are queued when deferral is off');

        const jobs = await pool.query('SELECT target_id, status FROM outbox ORDER BY target_id');
        assert.equal(jobs.rowCount, 2);
        const secJob = jobs.rows.find((r) => r.target_id === 'sec');
        const everyoneJob = jobs.rows.find((r) => r.target_id === 'everyone');
        assert.equal(secJob.status, 'QUEUED');
        assert.equal(everyoneJob.status, 'QUEUED');
      });
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);

