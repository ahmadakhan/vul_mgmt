import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate, put, get } from '../server/db.ts';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { applyJobEdits, type Job } from '../server/delivery.ts';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import type {
  Advisory,
  EmailDeliveryLog,
  Finding,
  NormalizedCVE,
  WatchListItem,
} from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;
test(
  'delivered finding emails can be acknowledged or edited and re-sent from the Action Center',
  { skip: !database },
  async (t) => {
    const base = createPool(database!);
    const schema = 'followup_' + randomBytes(8).toString('hex');
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
      throw new Error('No network expected during Action Center action');
    };
    const now = () => new Date().toISOString();

    const seed = async (status: 'ACCEPTED' | 'QUEUED') => {
      await pool.query('DELETE FROM records; DELETE FROM outbox');
      await put(pool, 'settings', 'main', settings);
      await put(pool, 'template', 'main', { templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION });
      await put(pool, 'watchlist', asset.id, asset);
      const findings = runVulnerabilityPipeline(
        [],
        [makeCve('CVE-2026-77101')],
        [asset],
        [],
        [],
        settings,
      ).newFindings;
      assert.equal(findings.length, 1);
      const finding = findings[0];
      await put(pool, 'findings', finding.id, finding);
      const advisoryId = 'ADV-' + randomUUID().slice(0, 8);
      const advisory: Advisory = {
        id: advisoryId,
        title: 'Notice',
        severity: 'HIGH',
        cveIds: ['CVE-2026-77101'],
        findingIds: [finding.id],
        createdDate: now(),
        deliveryStatus: 'DELIVERED',
        recipientCount: 1,
        executiveSummary: 'Fixture summary',
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
        `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,attempts,next_attempt)
         VALUES($1,$2,'email','sec-team',$3,$4,$5,1,now())`,
        [
          jobId,
          'dedupe-' + randomUUID().slice(0, 8),
          advisoryId,
          JSON.stringify({
            subject: 'Original subject',
            text: 'Original plain text',
            html: '<html><body><p>Original body</p></body></html>',
            recipientEmail: 'sec@example.invalid',
            cveIds: ['CVE-2026-77101'],
          }),
          status,
        ],
      );
      await put(pool, 'emailLogs', jobId, {
        id: jobId,
        recipientEmail: 'sec@example.invalid',
        advisoryId,
        subject: 'Original subject',
        provider: 'Mailtrap',
        status: status === 'ACCEPTED' ? 'ACCEPTED' : 'QUEUED',
        attemptCount: 1,
        retrySchedule: ['1m', '2m'],
        nextRetryTime: null,
        sentAt: status === 'ACCEPTED' ? now() : '',
        ...(status === 'ACCEPTED' ? { actionStatus: 'PENDING' as const } : {}),
      } satisfies EmailDeliveryLog);
      return { jobId, advisoryId, finding };
    };

    try {
      await migrate(pool);
      await createUser(pool, 'followup-admin', 'Followup-test-password-2026!', 'ADMIN');
      const app = createApp(pool, config, noNetwork);
      const agent = supertest.agent(app);
      const logged = await agent
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: 'followup-admin', password: 'Followup-test-password-2026!' });
      assert.equal(logged.status, 200, JSON.stringify(logged.body));
      const csrf = logged.body.csrfToken as string;
      const post = (path: string, body: Record<string, unknown>) =>
        agent
          .post(path)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          .send(body);

      await t.test('acknowledge moves a delivered log from PENDING to ACTIONED', async () => {
        const { jobId } = await seed('ACCEPTED');
        const res = await post(`/api/email/${jobId}/acknowledge`, { reason: 'reviewed' });
        assert.equal(res.status, 200, JSON.stringify(res.body));
        const log = await get<EmailDeliveryLog>(pool, 'emailLogs', jobId);
        assert.equal(log?.actionStatus, 'ACTIONED');
        assert.ok(log?.actionedAt);
      });

      await t.test('acknowledge refuses a log that was never delivered', async () => {
        const { jobId } = await seed('QUEUED');
        const res = await post(`/api/email/${jobId}/acknowledge`, {});
        assert.equal(res.status, 409, JSON.stringify(res.body));
      });

      await t.test('follow-up re-renders, queues edited copies, and closes the source action', async () => {
        const { jobId, advisoryId } = await seed('ACCEPTED');
        const res = await post(`/api/email/${jobId}/follow-up`, {
          recipientMode: 'SECURITY_TEAM',
          subject: 'Updated subject',
          audienceNotice: 'Edited notice',
          reviewerComment: 'Edited comment',
          reviewerName: 'Ops',
          reason: 'correct the recipient list',
        });
        assert.equal(res.status, 202, JSON.stringify(res.body));
        assert.equal(res.body.queued, 1);

        const source = await get<EmailDeliveryLog>(pool, 'emailLogs', jobId);
        assert.equal(source?.actionStatus, 'ACTIONED');
        assert.equal(source?.followUpCount, 1);

        const jobs = await pool.query(
          `SELECT * FROM outbox WHERE channel='email' AND advisory_id=$1 AND id<>$2`,
          [advisoryId, jobId],
        );
        assert.equal(jobs.rowCount, 1, 'exactly one follow-up job must be queued');
        const job = jobs.rows[0] as Job;
        assert.equal(job.payload.subject, 'Updated subject');
        assert.equal(job.edits?.subject, 'Updated subject');
        assert.equal(job.edits?.audienceNotice, 'Edited notice');
        assert.equal(String(job.edits?.recipientMode), 'SECURITY_TEAM');
        // The stored payload stays the template render; the edit layer is only
        // applied when the job is handed to the transport, which keeps the
        // email body and its PDF attachment identical.
        assert.ok(!job.payload.html!.includes('Edited notice'));
        const effective = applyJobEdits(job);
        assert.ok(effective.payload.html!.includes('Edited notice'));
        assert.ok(effective.payload.html!.includes('Edited comment'));
        assert.equal(effective.payload.subject, 'Updated subject');
        assert.ok(effective.payload.text?.includes('Edited notice'));

        const followUpLog = await get<EmailDeliveryLog>(pool, 'emailLogs', job.id);
        assert.equal(followUpLog?.subject, 'Updated subject');
        assert.equal(followUpLog?.status, 'QUEUED');

        const auditRows = await pool.query(
          "SELECT count(*)::int AS count FROM audit WHERE data->>'event' = 'Email updated and re-dispatched'",
        );
        assert.equal(auditRows.rows[0].count, 1);
      });

      await t.test('follow-up refuses unknown recipients and still-queued deliveries', async () => {
        const delivered = await seed('ACCEPTED');
        const unknown = await post(`/api/email/${delivered.jobId}/follow-up`, {
          recipientMode: 'SINGLE_EMAIL',
          customEmail: 'nobody@example.invalid',
        });
        assert.equal(unknown.status, 404, JSON.stringify(unknown.body));

        const queued = await seed('QUEUED');
        const stillQueued = await post(`/api/email/${queued.jobId}/follow-up`, {
          recipientMode: 'SECURITY_TEAM',
        });
        assert.equal(stillQueued.status, 409, JSON.stringify(stillQueued.body));
      });
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await base.end();
    }
  },
);
