import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate, put, get, list } from '../server/db.ts';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import type { Advisory, Finding, NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;
test('POST /api/email/:id/resend re-queues a delivered advisory to one recipient / security team / everyone', { skip: !database }, async (t) => {
  const base = createPool(database!);
  const schema = 'resend_' + randomBytes(8).toString('hex');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema},public`);
  const pool = createPool(url.href);
  const config = loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: url.href,
    APP_ORIGIN: 'http://localhost',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    WORKER_ENABLED: 'false',
    ATTACH_ADVISORY_PDF: 'false',
  });
  const cpe = 'cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*';
  const asset: WatchListItem = {
    id: 'asset',
    vendor: 'example',
    product: 'widget',
    version: '1.5',
    cpes: [cpe],
    assetTag: 'widget',
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
  const settings = { ...DEFAULT_SETTINGS, autoDispatchEnabled: true, schedulerEnabled: false };
  const noNetwork = async () => {
    throw new Error('No network expected during resend');
  };
  const reset = async () => {
    await pool.query('DELETE FROM records; DELETE FROM outbox');
    await put(pool, 'settings', 'main', settings);
    await put(pool, 'template', 'main', { templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION });
    await put(pool, 'watchlist', asset.id, asset);
  };
  try {
    await migrate(pool);
    await t.test('404 when delivery does not exist', async () => {
      await reset();
      await createUser(pool, 'admin', 'Resend-test-password-2026!', 'ADMIN');
      const app = createApp(pool, config, noNetwork);
      const agent = supertest.agent(app);
      const logged = await agent
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: 'admin', password: 'Resend-test-password-2026!' });
      assert.equal(logged.status, 200, JSON.stringify(logged.body));
      const csrf = logged.body.csrfToken as string;
      const res = await agent
        .post('/api/email/00000000-0000-0000-0000-000000000000/resend')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ recipientMode: 'SECURITY_TEAM' });
      assert.equal(res.status, 404, `expected 404, got ${res.status}: ${JSON.stringify(res.body)}`);
    });
    await t.test('resend to security team creates new advisory and queued jobs', async () => {
      await reset();
      const findings = runVulnerabilityPipeline(
        [],
        [makeCve('CVE-2026-98201')],
        [asset],
        [],
        [],
        settings,
      ).newFindings;
      assert.equal(findings.length, 1);
      const finding = { ...findings[0], notificationStatus: 'DELIVERED' as const, advisoryId: null };
      await put(pool, 'findings', finding.id, finding);
      const advisoryId = 'ADV-' + randomUUID().slice(0, 8);
      const advisory: Advisory = {
        id: advisoryId,
        title: 'Notice',
        severity: 'HIGH',
        cveIds: ['CVE-2026-98201'],
        findingIds: [finding.id],
        createdDate: new Date().toISOString(),
        deliveryStatus: 'DELIVERED',
        recipientCount: 1,
        executiveSummary: 'Fixture',
        remediationInstructions: 'Apply the update.',
        affectedSystems: [finding.matchedAssetName],
      };
      await put(pool, 'advisories', advisory.id, advisory);
      await put(pool, 'recipients', 'sec-team', {
        id: 'sec-team',
        name: 'Security Team',
        email: 'sec@example.invalid',
        enabled: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      // Create a delivered email log + outbox job for the delivery being resent.
      const jobId = randomUUID();
      await pool.query(
        `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,attempts)
         VALUES($1,$2,'email','sec-team',$3,$4,'SENDING',1)`,
        [jobId, 'dedupe-' + randomUUID().slice(0, 8), advisoryId, JSON.stringify({ subject: 'Fixture', text: 'Fixture', html: '<p>Fixture</p>', recipientEmail: 'sec@example.invalid', cveIds: ['CVE-2026-98201'] })],
      );
      await put(pool, 'emailLogs', jobId, {
        id: jobId,
        recipientEmail: 'sec@example.invalid',
        advisoryId,
        subject: 'Fixture',
        provider: 'Mailtrap',
        status: 'DELIVERED',
        attemptCount: 1,
        retrySchedule: ['1m', '2m'],
        nextRetryTime: null,
        sentAt: new Date().toISOString(),
      });
      await createUser(pool, 'resend-admin-2', 'Resend-test-password-2026!', 'ADMIN');
      const app = createApp(pool, config, noNetwork);
      const agent = supertest.agent(app);
      const logged = await agent
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: 'resend-admin-2', password: 'Resend-test-password-2026!' });
      assert.equal(logged.status, 200, JSON.stringify(logged.body));
      const csrf = logged.body.csrfToken as string;
      const res = await agent
        .post(`/api/email/${jobId}/resend`)
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ recipientMode: 'SECURITY_TEAM', reason: 'regression resend' });
      assert.equal(res.status, 202, `expected 202, got ${res.status}: ${JSON.stringify(res.body)}`);
      assert.equal(res.body.success, true);
      // A new advisory was created.
      const newAdvisories = await pool.query<{ data: any }>(
        "SELECT data FROM records WHERE kind='advisories' ORDER BY (data->>'createdDate') DESC LIMIT 1",
      );
      assert.equal(newAdvisories.rowCount, 1, 'a new advisory record must be stored');
      const newAdv = newAdvisories.rows[0].data;
      assert.match(newAdv.id, /^ADV-/, 'new advisory id must carry the prefix');
      assert.ok(newAdv.title.includes('(resend)'), 'new advisory title must mark the resend');
      assert.equal(newAdv.deliveryStatus, 'PENDING', 'new advisory must be PENDING');
      // New outbox/emailLog jobs queued for the security team recipient.
      const newLogs = await pool.query<{ data: any }>(
        "SELECT data FROM records WHERE kind='emailLogs' AND (data->>'advisoryId') = $1",
        [newAdv.id],
      );
      assert.ok((newLogs.rowCount ?? 0) >= 1, 'new email log job(s) must be queued');
      const newLog = newLogs.rows[0].data;
      assert.equal(newLog.status, 'QUEUED', 'new email log must be QUEUED');
      assert.equal(newLog.recipientEmail, 'sec@example.invalid', 'new email log must target the security team recipient');
      // Finding linked to the new advisory.
      const updated = await get<Finding>(pool, 'findings', finding.id);
      assert.equal(updated?.advisoryId, newAdv.id, 'finding must be linked to the new advisory');
      assert.equal(updated?.notificationStatus, 'QUEUED_FOR_DISPATCH', 'finding must be queued for dispatch');
      // Audit entry written.
      const auditRows = await pool.query<{ data: any }>(
        "SELECT data FROM audit WHERE data->>'event' = 'Email delivery resent'",
      );
      assert.ok((auditRows.rowCount ?? 0) >= 1, 'audit log must record the resend');
    });
    await t.test('resend to single email requires a valid customEmail', async () => {
      await reset();
      await createUser(pool, 'resend-admin-3', 'Resend-test-password-2026!', 'ADMIN');
      const app = createApp(pool, config, noNetwork);
      const agent = supertest.agent(app);
      const logged = await agent
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: 'resend-admin-3', password: 'Resend-test-password-2026!' });
      assert.equal(logged.status, 200, JSON.stringify(logged.body));
      const csrf = logged.body.csrfToken as string;
      const res = await agent
        .post('/api/email/00000000-0000-0000-0000-000000000000/resend')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ recipientMode: 'SINGLE_EMAIL' });
      assert.equal(res.status, 400, `expected 400 for missing customEmail, got ${res.status}: ${JSON.stringify(res.body)}`);
    });
    await t.test('edits saved on a delivered email are accepted and carried into the resend', async () => {
      await reset();
      const generated = runVulnerabilityPipeline(
        [],
        [makeCve('CVE-2026-98201')],
        [asset],
        [],
        [],
        settings,
      ).newFindings;
      assert.equal(generated.length, 1);
      const finding = { ...generated[0], notificationStatus: 'DELIVERED' as const, advisoryId: null };
      await put(pool, 'findings', finding.id, finding);
      const advisoryId = 'ADV-' + randomUUID().slice(0, 8);
      const advisory: Advisory = {
        id: advisoryId,
        title: 'Notice',
        severity: 'HIGH',
        cveIds: ['CVE-2026-98201'],
        findingIds: [finding.id],
        createdDate: new Date().toISOString(),
        deliveryStatus: 'DELIVERED',
        recipientCount: 1,
        executiveSummary: 'Fixture',
        remediationInstructions: 'Apply the update.',
        affectedSystems: [finding.matchedAssetName],
      };
      await put(pool, 'advisories', advisory.id, advisory);
      await put(pool, 'recipients', 'sec-team', {
        id: 'sec-team',
        name: 'Security Team',
        email: 'sec@example.invalid',
        enabled: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      const jobId = randomUUID();
      await pool.query(
        `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,attempts)
         VALUES($1,$2,'email','sec-team',$3,$4,'ACCEPTED',1)`,
        [
          jobId,
          'dedupe-' + randomUUID().slice(0, 8),
          advisoryId,
          JSON.stringify({
            subject: 'Fixture',
            text: 'Fixture',
            html: '<p>Fixture</p>',
            recipientEmail: 'sec@example.invalid',
            cveIds: ['CVE-2026-98201'],
          }),
        ],
      );
      await put(pool, 'emailLogs', jobId, {
        id: jobId,
        recipientEmail: 'sec@example.invalid',
        advisoryId,
        subject: 'Fixture',
        provider: 'Mailtrap',
        status: 'DELIVERED',
        attemptCount: 1,
        retrySchedule: ['1m', '2m'],
        nextRetryTime: null,
        sentAt: new Date().toISOString(),
        actionStatus: 'PENDING',
      });
      await createUser(pool, 'resend-admin-4', 'Resend-test-password-2026!', 'ADMIN');
      const app = createApp(pool, config, noNetwork);
      const agent = supertest.agent(app);
      const logged = await agent
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: 'resend-admin-4', password: 'Resend-test-password-2026!' });
      assert.equal(logged.status, 200, JSON.stringify(logged.body));
      const csrf = logged.body.csrfToken as string;

      // A delivered findings email is the normal Action Center follow-up, so the
      // editor must accept the edit (it previously 409'd on ACCEPTED/DELIVERED).
      const edited = await agent
        .post(`/api/email/${jobId}/edit`)
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ subject: 'Corrected advisory subject', audienceNotice: 'DMZ patched already.' });
      assert.equal(edited.status, 200, `edit on a delivered email failed: ${JSON.stringify(edited.body)}`);

      const res = await agent
        .post(`/api/email/${jobId}/resend`)
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ recipientMode: 'SECURITY_TEAM', reason: 'carry edits' });
      assert.equal(res.status, 202, `expected 202, got ${res.status}: ${JSON.stringify(res.body)}`);

      // The queued follow-up job must carry the operator's edits, otherwise the
      // resent mail differs from what they just reviewed.
      const queued = await pool.query<{ edits: any; payload: any }>(
        `SELECT edits, payload FROM outbox WHERE channel='email' AND id<>$1 AND status IN ('QUEUED','REVIEW')`,
        [jobId],
      );
      assert.ok((queued.rowCount ?? 0) >= 1, 'a follow-up job must be queued');
      const edits = queued.rows[0].edits ?? {};
      assert.equal(edits.subject, 'Corrected advisory subject', 'edited subject must travel with the resend');
      assert.equal(edits.audienceNotice, 'DMZ patched already.', 'edited notice must travel with the resend');
      assert.equal(queued.rows[0].payload.subject, 'Corrected advisory subject', 'queued payload must use the edited subject');

      // The source delivery is closed as actioned so it leaves the PENDING SLA queue.
      const log = await get<{ actionStatus?: string; followUpCount?: number }>(pool, 'emailLogs', jobId);
      assert.equal(log?.actionStatus, 'ACTIONED');
      assert.equal(log?.followUpCount, 1);
    });
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await base.end();
  }
});
