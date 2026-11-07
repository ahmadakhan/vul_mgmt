import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate, put, get, list } from '../server/db.ts';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { deliverNext, enqueue } from '../server/delivery.ts';
import { runDailyDigest } from '../server/dailyDigest.ts';
import { rebuildFromCurrentInventory, rebuildLegacyDeliveryPayload } from '../server/pipeline.ts';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import type { Advisory, Finding, NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;
test(
  'delivery audit: digest scope, policy, retry budgets and legacy content',
  { skip: !database },
  async (t) => {
    const base = createPool(database!);
    const schema = 'delivery_audit_' + randomBytes(8).toString('hex');
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
    });
    const cpe = 'cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*';
    const asset: WatchListItem = {
      id: 'asset',
      vendor: 'example',
      product: 'widget',
      version: '1.5',
      cpes: [cpe],
      assetTag: 'Production <img src=x onerror=alert(1)>',
      ownerGroup: 'Security',
      active: true,
      createdAt: new Date().toISOString(),
    };
    const makeCve = (id: string, kev = false, severity: 'HIGH' | 'LOW' = 'HIGH'): NormalizedCVE => ({
      cveId: id,
      title: 'Security update',
      description: 'Fixture',
      publishedDate: new Date().toISOString(),
      modifiedDate: new Date().toISOString(),
      cvss: { version: '3.1', score: severity === 'HIGH' ? 8 : 2, severity, vector: '' },
      cwe: [],
      cpeMatches: [cpe],
      sourceFeeds: [],
      epss: { score: 0, percentile: 0 },
      cisaKev: { isKev: kev },
      exploitStatus: 'None',
      remediation: {
        patchUrl: 'https://example.com/current-patch',
        vendorAdvisoryRef: '',
        immediateActions: [],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    });
    const settings = {
      ...DEFAULT_SETTINGS,
      autoDispatchEnabled: false,
      timezone: 'UTC',
      dailyDigest: { enabled: true, time: '00:00', includeHealthReport: false },
    };
    const recipient = (id: string, subscriptionTier = 'ALL_SEVERITIES') => ({
      id,
      name: id,
      email: `${id}@example.invalid`,
      enabled: true,
      dailyDigest: true,
      deliveryGroup: 'SECURITY_TEAM',
      subscriptionTier,
    });
    const noNetwork = async () => {
      throw new Error('No network expected');
    };
    const reset = async () => {
      await pool.query('DELETE FROM records; DELETE FROM outbox');
      await put(pool, 'settings', 'main', settings);
      await put(pool, 'watchlist', asset.id, asset);
    };
    const seed = async (cves: NormalizedCVE[]) => {
      for (const cve of cves) await put(pool, 'cveData', cve.cveId, cve);
      const findings = runVulnerabilityPipeline(
        [],
        cves,
        [asset],
        [],
        [],
        { ...settings, scopeHours: 0 },
        'test',
        false,
      ).newFindings;
      assert.equal(findings.length, cves.length);
      for (const f of findings) await put(pool, 'findings', f.id, f);
      return findings;
    };
    try {
      await migrate(pool);
      await t.test('legacy settings without emailEnabled still enqueue and deliver email', async () => {
        await reset();
        const { emailEnabled: legacyFlag, ...legacySettings } = settings;
        await put(pool, 'settings', 'main', legacySettings);
        const id = await enqueue(pool, 'email', 'test', 'TEST', {
          subject: 'Legacy settings', text: 'Test', cveIds: [],
        }, 'legacy-email-enabled');
        assert.ok(id);
        let sent = 0;
        assert.equal(await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'legacy-receipt';
        }), true);
        assert.equal(sent, 1);
        assert.equal((await pool.query('SELECT status FROM outbox WHERE id=$1', [id])).rows[0].status, 'ACCEPTED');
      });
      await t.test('disabled email remains unclaimed and resumes when enabled', async () => {
        await reset();
        const id = await enqueue(pool, 'email', 'test', 'TEST', {
          subject: 'Paused email', text: 'Test', cveIds: [],
        }, 'paused-email');
        await put(pool, 'settings', 'main', { ...settings, emailEnabled: false });
        const sender = async () => 'resumed-receipt';
        assert.equal(await deliverNext(pool, config, noNetwork, sender), false);
        const paused = (await pool.query('SELECT status,attempts,locked_at FROM outbox WHERE id=$1', [id])).rows[0];
        assert.equal(paused.status, 'QUEUED');
        assert.equal(paused.attempts, 0);
        assert.equal(paused.locked_at, null);
        assert.equal(await enqueue(pool, 'email', 'test', 'TEST', {
          subject: 'Disabled email', text: 'Test', cveIds: [],
        }, 'disabled-email'), null);
        await put(pool, 'settings', 'main', { ...settings, emailEnabled: true });
        assert.equal(await deliverNext(pool, config, noNetwork, sender), true);
        assert.equal((await pool.query('SELECT status FROM outbox WHERE id=$1', [id])).rows[0].status, 'ACCEPTED');
      });
      await t.test('an SMTP retry remains recoverable after switching to HTTPS', async () => {
        await reset();
        const id = await enqueue(pool, 'email', 'test', 'TEST', {
          subject: 'Transport recovery', text: 'Test', cveIds: [],
        }, 'smtp-to-https');
        await deliverNext(pool, config, noNetwork, async () => {
          throw Object.assign(new Error('read ECONNRESET'), { code: 'ESOCKET', command: 'CONN' });
        });
        const log = await get(pool, 'emailLogs', id!);
        await put(pool, 'emailLogs', id!, { ...log!, provider: 'SMTP_Relay' });
        await put(pool, 'emailConfig', 'main', { provider: 'SENDGRID' });
        await pool.query('UPDATE outbox SET next_attempt=now() WHERE id=$1', [id]);
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return { id: 'https-receipt', provider: 'SendGrid' };
        });
        assert.equal(sent, 1);
        assert.equal((await pool.query('SELECT status FROM outbox WHERE id=$1', [id])).rows[0].status, 'ACCEPTED');
      });
      await t.test('an ambiguous SMTP DATA outcome is never blindly resent', async () => {
        await reset();
        const id = await enqueue(pool, 'email', 'test', 'TEST', {
          subject: 'Unknown SMTP result', text: 'Test', cveIds: [],
        }, 'smtp-data-ambiguous');
        await deliverNext(pool, config, noNetwork, async () => {
          throw Object.assign(new Error('read ECONNRESET'), { code: 'ESOCKET', command: 'DATA' });
        });
        const previous = await get<{ transportRejected?: boolean }>(pool, 'emailLogs', id!);
        assert.equal(previous?.transportRejected, false);
        await pool.query('UPDATE outbox SET next_attempt=now() WHERE id=$1', [id]);
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => { sent++; return 'duplicate'; });
        assert.equal(sent, 0);
        assert.equal((await pool.query('SELECT status FROM outbox WHERE id=$1', [id])).rows[0].status, 'QUEUED');
      });
      await t.test('switching to SMTP cannot bypass confirmation of an ambiguous HTTP attempt', async () => {
        await reset();
        const id = await enqueue(pool, 'email', 'test', 'TEST', {
          subject: 'Unknown HTTP result', text: 'Test', cveIds: [],
        }, 'https-to-smtp');
        await deliverNext(pool, config, noNetwork, async () => {
          throw new Error('read ECONNRESET');
        });
        const log = await get(pool, 'emailLogs', id!);
        await put(pool, 'emailLogs', id!, { ...log!, provider: 'SendGrid' });
        await put(pool, 'emailConfig', 'main', { provider: 'SMTP_CUSTOM' });
        await pool.query('UPDATE outbox SET next_attempt=now() WHERE id=$1', [id]);
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'must-not-send';
        });
        assert.equal(sent, 0);
        assert.match((await get<{ errorMessage: string }>(pool, 'emailLogs', id!))!.errorMessage, /could not be confirmed/);
      });
      await t.test('daily digests render and deliver only the findings each subscriber permits', async () => {
        await reset();
        const high = makeCve('CVE-2026-98101'),
          lowKev = makeCve('CVE-2026-98102', true, 'LOW');
        await seed([high, lowKev]);
        for (const [id, tier] of [
          ['all', 'ALL_SEVERITIES'],
          ['high', 'CRITICAL_HIGH_ONLY'],
          ['kev', 'CISA_KEV_ONLY'],
        ])
          await put(pool, 'recipients', id, recipient(id, tier));
        assert.equal(await runDailyDigest(pool), 3);
        const jobs = (await pool.query('SELECT target_id,payload FROM outbox')).rows;
        for (const job of jobs) {
          const expected =
            job.target_id === 'high'
              ? [high.cveId]
              : job.target_id === 'kev'
                ? [lowKev.cveId]
                : [high.cveId, lowKev.cveId];
          assert.deepEqual(job.payload.cveIds, expected);
          for (const excluded of [high.cveId, lowKev.cveId].filter((id) => !expected.includes(id))) {
            assert.ok(!job.payload.html.includes(excluded));
            assert.ok(!job.payload.text.includes(excluded));
          }
        }
        let sent = 0;
        while (
          await deliverNext(pool, config, noNetwork, async () => {
            sent++;
            return 'accepted';
          })
        ) {}
        assert.equal(sent, 3);
      });
      await t.test('daily digest inventory content is escaped in the appended HTML summary', async () => {
        await reset();
        await seed([makeCve('CVE-2026-98103')]);
        await put(pool, 'recipients', 'all', recipient('all'));
        await runDailyDigest(pool);
        const html = (await pool.query('SELECT payload FROM outbox')).rows[0].payload.html;
        assert.ok(!html.includes('<img src=x'));
        assert.ok(html.includes('&lt;img src=x'));
      });
      await t.test('daily digest counts new subscribed findings, not the older open backlog', async () => {
        await reset();
        const [older, recent] = await seed([makeCve('CVE-2026-98201'), makeCve('CVE-2026-98202')]);
        await pool.query(
          "UPDATE records SET created_at=now()-interval '25 hours' WHERE kind='findings' AND id=$1",
          [older.id],
        );
        await put(pool, 'recipients', 'all', recipient('all'));
        assert.equal(await runDailyDigest(pool), 1);
        const payload = (await pool.query('SELECT payload FROM outbox')).rows[0].payload;
        assert.deepEqual(payload.includedFindingIds, [recent.id]);
        assert.ok(payload.html.includes('<strong>1 finding</strong> matched your subscriptions in the last 24 hours'));
        assert.ok(!payload.html.includes(older.cveId));
        assert.ok(!payload.html.includes('remediation of critical'));
      });
      await t.test('daily digest shows the next local daily schedule with no queued retries, including DST changes', async () => {
        for (const [timezone, instant, expected] of [
          ['Asia/Dubai', '2026-11-06T05:00:00Z', '07 Nov 2026 09:00 UTC+4'],
          ['Europe/Berlin', '2026-03-28T08:00:00Z', '29 Mar 2026 09:00 UTC+2'],
          ['Europe/Berlin', '2026-10-24T07:00:00Z', '25 Oct 2026 09:00 UTC+1'],
        ]) {
          await reset();
          await put(pool, 'settings', 'main', {
            ...settings, timezone,
            dailyDigest: { enabled: true, time: '09:00', includeHealthReport: true },
          });
          await put(pool, 'recipients', 'all', recipient('all'));
          const clock = t.mock.method(Date, 'now', () => Date.parse(instant));
          try {
            assert.equal(await runDailyDigest(pool), 1);
            const html = (await pool.query('SELECT payload FROM outbox')).rows[0].payload.html;
            assert.ok(html.includes(expected), `${timezone} next daily schedule: ${expected}`);
            assert.ok(html.includes('No future delivery attempt scheduled'));
            assert.ok(html.includes('<strong>0 findings</strong>'));
            assert.ok(!html.includes('remediation of critical'));
            assert.ok(!html.includes('unmeasured'));
          } finally {
            clock.mock.restore();
          }
        }
      });
      await t.test('a newly held verdict does not withhold an already-queued digest', async () => {
        await reset();
        const [f] = await seed([makeCve('CVE-2026-98104')]);
        await put(pool, 'recipients', 'all', recipient('all'));
        await runDailyDigest(pool);
        await put(pool, 'settings', 'main', { ...settings, autoDispatchConfidenceThreshold: 99 });
        await put(pool, 'findings', f.id, { ...f, notificationStatus: 'REVIEW_REQUIRED' });
        // A digest key used to exempt the bundle from the applicability verdict,
        // and a non-exempt bundle was failed as stale. Neither applies now: the
        // finding is delivered and its limitation is stated in the document.
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'accepted-held';
        });
        assert.equal(sent, 1, 'the queued digest reaches the transport');
        const row = (await pool.query("SELECT status,payload FROM outbox WHERE status='ACCEPTED'")).rows[0];
        assert.ok(row, 'the queued digest is accepted');
        assert.match(row.payload.html, /Low confidence/);
      });
      await t.test('worker recovery cannot bypass the retry budget of an approved email', async () => {
        await reset();
        await put(pool, 'settings', 'main', { ...settings, emailRetryMaxAttempts: 1 });
        const id = await enqueue(
          pool,
          'email',
          'test',
          'TEST',
          { subject: 'Test', text: 'Test', cveIds: [] },
          'approved-recovery',
        );
        await pool.query(
          "UPDATE outbox SET status='SENDING', attempts=1, review_approved=true, locked_at=now()-interval '3 minutes' WHERE id=$1",
          [id],
        );
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'must-not-send';
        });
        assert.equal(sent, 0);
        assert.equal(
          (await pool.query('SELECT status FROM outbox WHERE id=$1', [id])).rows[0].status,
          'FAILED',
        );
      });
      await t.test('approval starts a fresh transport budget after the review hold', async () => {
        await reset();
        await put(pool, 'settings', 'main', { ...settings, emailRetryMaxAttempts: 1 });
        const id = await enqueue(
          pool,
          'email',
          'test',
          'TEST',
          { subject: 'Test', text: 'Test', cveIds: [] },
          'approval-budget',
          'REVIEW',
        );
        await pool.query('UPDATE outbox SET attempts=1 WHERE id=$1', [id]);
        await createUser(pool, 'audit-admin', 'Audit-test-password-2026!', 'ADMIN');
        const app = createApp(pool, config, noNetwork),
          agent = supertest.agent(app);
        const logged = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username: 'audit-admin', password: 'Audit-test-password-2026!' });
        const approved = await agent
          .post(`/api/email/${id}/approve`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', logged.body.csrfToken)
          .send({});
        assert.equal(approved.status, 200);
        assert.equal((await pool.query('SELECT attempts FROM outbox WHERE id=$1', [id])).rows[0].attempts, 0);
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'approved';
        });
        assert.equal(sent, 1);
      });
      await t.test('review edits are persisted and applied on approval to email html', async () => {
        await reset();
        const id = await enqueue(
          pool,
          'email',
          'all',
          'TEST',
          {
            subject: 'Test',
            text: 'see html',
            html: '<html><body><p>Original</p></body></html>',
            cveIds: [],
          },
          'review-edits-apply',
          'REVIEW',
        );
        await createUser(pool, 'edit-admin', 'Edit-test-password-2026!', 'ADMIN');
        const app = createApp(pool, config, noNetwork),
          agent = supertest.agent(app);
        const logged = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username: 'edit-admin', password: 'Edit-test-password-2026!' });
        const editRes = await agent
          .post(`/api/email/${id}/edit`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', logged.body.csrfToken)
          .send({
            audienceNotice: 'Broad distribution notice',
            reviewerComment: 'Verified by admin',
            reviewerName: 'edit-admin',
          });
        assert.equal(editRes.status, 200);
        const saved = await pool.query('SELECT edits, payload FROM outbox WHERE id=$1', [id]);
        assert.deepEqual(saved.rows[0].edits, {
          audienceNotice: 'Broad distribution notice',
          reviewerComment: 'Verified by admin',
          reviewerName: 'edit-admin',
        });
        const previewRes = await agent
          .get(`/api/email/${id}/preview`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', logged.body.csrfToken)
          .send();
        assert.equal(previewRes.status, 200);
        assert.ok(previewRes.body.html.includes('Broad distribution notice'));
        assert.ok(previewRes.body.html.includes('Verified by admin'));
        const approved = await agent
          .post(`/api/email/${id}/approve`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', logged.body.csrfToken)
          .send({});
        assert.equal(approved.status, 200);
        const delivered = await pool.query('SELECT payload, status FROM outbox WHERE id=$1', [id]);
        const deliveredHtml = delivered.rows[0].payload.html;
        assert.ok(deliveredHtml.includes('Broad distribution notice'));
        assert.ok(deliveredHtml.includes('Verified by admin'));
        assert.equal(delivered.rows[0].status, 'QUEUED');
      });
      await t.test('review edits accepted for queued jobs that have not been locked', async () => {
        await reset();
        const id = await enqueue(
          pool,
          'email',
          'test',
          'TEST',
          { subject: 'Test', text: 'Test', cveIds: [] },
          'edit-non-review',
          'QUEUED',
        );
        await createUser(pool, 'edit-admin2', 'Edit-test-password-2026!', 'ADMIN');
        const app = createApp(pool, config, noNetwork),
          agent = supertest.agent(app);
        const logged = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username: 'edit-admin2', password: 'Edit-test-password-2026!' });
        const editRes = await agent
          .post(`/api/email/${id}/edit`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', logged.body.csrfToken)
          .send({ audienceNotice: 'Queued job notice' });
        assert.equal(editRes.status, 200);
        const saved = await pool.query('SELECT edits FROM outbox WHERE id=$1', [id]);
        assert.equal(saved.rows[0].edits.audienceNotice, 'Queued job notice');
      });
      await t.test('review edits escape XSS in preview and approval', async () => {
        await reset();
        const id = await enqueue(
          pool,
          'email',
          'all',
          'TEST',
          {
            subject: 'Test',
            text: 'see html',
            html: '<html><body><p>Original</p></body></html>',
            cveIds: [],
          },
          'review-xss',
          'REVIEW',
        );
        await createUser(pool, 'xss-admin', 'Xss-test-password-2026!', 'ADMIN');
        const app = createApp(pool, config, noNetwork),
          agent = supertest.agent(app);
        const logged = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username: 'xss-admin', password: 'Xss-test-password-2026!' });
        const editRes = await agent
          .post(`/api/email/${id}/edit`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', logged.body.csrfToken)
          .send({
            audienceNotice: '<img src=x onerror=alert(1)>',
            reviewerComment: '<script>alert(1)</script>',
          });
        assert.equal(editRes.status, 200);
        const previewRes = await agent
          .get(`/api/email/${id}/preview`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', logged.body.csrfToken)
          .send();
        assert.ok(!previewRes.body.html.includes('<img src=x'), 'XSS in audience notice must be escaped');
        assert.ok(!previewRes.body.html.includes('<script>'), 'XSS in reviewer comment must be escaped');
        const approved = await agent
          .post(`/api/email/${id}/approve`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', logged.body.csrfToken)
          .send({});
        assert.equal(approved.status, 200);
        const delivered = await pool.query('SELECT payload FROM outbox WHERE id=$1', [id]);
        const deliveredHtml = delivered.rows[0].payload.html;
        assert.ok(!deliveredHtml.includes('<img src=x'), 'XSS must be escaped in final delivered html');
        assert.ok(!deliveredHtml.includes('<script>'), 'XSS must be escaped in final delivered html');
      });
      await t.test('health-only digests retain an explicitly empty recipient subset', async () => {
        await reset();
        const cve = makeCve('CVE-2026-98106');
        await seed([cve]);
        await put(pool, 'settings', 'main', {
          ...settings,
          dailyDigest: { ...settings.dailyDigest, includeHealthReport: true },
        });
        await put(pool, 'recipients', 'kev', recipient('kev', 'CISA_KEV_ONLY'));
        assert.equal(await runDailyDigest(pool), 1);
        const queued = (await pool.query('SELECT payload FROM outbox')).rows[0].payload;
        assert.deepEqual(queued.cveIds, []);
        assert.deepEqual(queued.includedFindingIds, []);
        assert.ok(!queued.html.includes(cve.cveId));
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'health-only';
        });
        assert.equal(sent, 1);
      });
      await t.test('resolved findings cannot poison a daily digest containing current findings', async () => {
        await reset();
        const current = makeCve('CVE-2026-98107'),
          resolved = makeCve('CVE-2026-98108');
        const findings = await seed([current, resolved]);
        const stale = findings.find((f) => f.cveId === resolved.cveId)!;
        await put(pool, 'findings', stale.id, {
          ...stale,
          status: 'RESOLVED',
          notificationStatus: 'AUTO_DISPATCHED',
        });
        await put(pool, 'recipients', 'all', recipient('all'));
        assert.equal(await runDailyDigest(pool), 1);
        assert.deepEqual((await pool.query('SELECT payload FROM outbox')).rows[0].payload.cveIds, [
          current.cveId,
        ]);
        let sent = 0;
        await deliverNext(pool, config, noNetwork, async () => {
          sent++;
          return 'current-only';
        });
        assert.equal(sent, 1);
      });
      await t.test(
        'stale recovery preserves another worker sending lease and rebuilds current content',
        async () => {
          await reset();
          const cve = makeCve('CVE-2026-98109');
          const [finding] = await seed([cve]);
          const advisory: Advisory = {
            id: 'ADV-concurrent',
            title: 'Old notice',
            severity: 'HIGH',
            cveIds: [cve.cveId],
            findingIds: [finding.id],
            createdDate: new Date().toISOString(),
            deliveryStatus: 'PENDING',
            recipientCount: 2,
            executiveSummary: 'Old',
            affectedSystems: [finding.matchedAssetName],
            remediationInstructions: 'https://example.com/obsolete-patch',
          };
          await put(pool, 'advisories', advisory.id, advisory);
          const payload = {
            subject: 'Old',
            text: 'Old',
            html: '<body>https://example.com/obsolete-patch</body>',
            cveIds: [cve.cveId],
          };
          const active = await enqueue(pool, 'email', 'first', advisory.id, payload, 'active-lease');
          const waiting = await enqueue(pool, 'email', 'second', advisory.id, payload, 'waiting-rebuild');
          const token = randomUUID();
          await pool.query("UPDATE outbox SET status='SENDING',lock_token=$2,locked_at=now() WHERE id=$1", [
            active,
            token,
          ]);
          await rebuildFromCurrentInventory(pool, advisory.id, 'no longer applicable');
          const lease = (await pool.query('SELECT status,lock_token FROM outbox WHERE id=$1', [active]))
            .rows[0];
          assert.equal(lease.status, 'SENDING');
          assert.equal(lease.lock_token, token);
          const rebuilt = (await pool.query('SELECT payload FROM outbox WHERE id=$1', [waiting])).rows[0]
            .payload;
          assert.ok(!rebuilt.html.includes('obsolete-patch'));
          assert.ok(rebuilt.text.includes('current-patch'));
        },
      );
      await t.test(
        'invalidating a queued sibling updates its persisted delivery log atomically',
        async () => {
          await reset();
          const cve = makeCve('CVE-2026-98111');
          const [finding] = await seed([cve]);
          const advisory: Advisory = {
            id: 'ADV-invalid-log',
            title: 'Notice',
            severity: 'HIGH',
            cveIds: [cve.cveId],
            findingIds: [finding.id],
            createdDate: new Date().toISOString(),
            deliveryStatus: 'PENDING',
            recipientCount: 1,
            executiveSummary: 'Old',
            affectedSystems: [finding.matchedAssetName],
            remediationInstructions: 'Old',
          };
          await put(pool, 'advisories', advisory.id, advisory);
          const id = await enqueue(
            pool,
            'email',
            'all',
            advisory.id,
            { subject: 'Old', text: 'Old', cveIds: [cve.cveId] },
            'invalid-log',
          );
          await put(pool, 'watchlist', asset.id, { ...asset, active: false });
          await rebuildFromCurrentInventory(pool, advisory.id, 'no longer applicable');
          assert.equal(
            (await pool.query('SELECT status FROM outbox WHERE id=$1', [id])).rows[0].status,
            'FAILED',
          );
          const log = await get<any>(pool, 'emailLogs', id!);
          assert.equal(log.status, 'FAILED');
          assert.equal(log.errorMessage, 'no longer applicable');
          assert.equal(log.nextRetryTime, null);
        },
      );
      await t.test(
        'repeated recovery preserves accepted state and creates only one replacement',
        async () => {
          await reset();
          const cve = makeCve('CVE-2026-98110');
          const [finding] = await seed([cve]);
          await put(pool, 'recipients', 'all', recipient('all'));
          const advisory: Advisory = {
            id: 'ADV-idempotent',
            title: 'Notice',
            severity: 'HIGH',
            cveIds: [cve.cveId],
            findingIds: [finding.id],
            createdDate: new Date().toISOString(),
            deliveryStatus: 'FAILED',
            recipientCount: 1,
            executiveSummary: 'Old',
            affectedSystems: [finding.matchedAssetName],
            remediationInstructions: 'Old',
          };
          await put(pool, 'advisories', advisory.id, advisory);
          const id = await enqueue(
            pool,
            'email',
            'all',
            advisory.id,
            { subject: 'Old', text: 'Old', cveIds: [cve.cveId], recipientEmail: 'all@example.invalid' },
            'failed-original',
          );
          const duplicateId = await enqueue(
            pool,
            'email',
            'all',
            advisory.id,
            { subject: 'Old', text: 'Old', cveIds: [cve.cveId], recipientEmail: 'all@example.invalid' },
            'failed-original-duplicate',
          );
          await pool.query("UPDATE outbox SET status='FAILED',error='no longer applicable' WHERE id=ANY($1::uuid[])", [
            [id, duplicateId],
          ]);
          await rebuildFromCurrentInventory(pool, advisory.id, 'no longer applicable');
          const count = (await list<Advisory>(pool, 'advisories')).length;
          await rebuildFromCurrentInventory(pool, advisory.id, 'no longer applicable');
          assert.equal((await list<Advisory>(pool, 'advisories')).length, count);
          assert.equal(
            (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n,
            1,
          );
          let sent = 0;
          await deliverNext(pool, config, noNetwork, async () => {
            sent++;
            return 'replacement';
          });
          assert.equal(sent, 1);
          const accepted = await get<Finding>(pool, 'findings', finding.id);
          assert.equal(accepted?.notificationStatus, 'AUTO_DISPATCHED');
          await rebuildFromCurrentInventory(pool, advisory.id, 'no longer applicable');
          assert.equal(
            (await get<Finding>(pool, 'findings', finding.id))?.notificationStatus,
            'AUTO_DISPATCHED',
          );
          assert.equal((await list<Advisory>(pool, 'advisories')).length, count);
          assert.equal(
            (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n,
            0,
          );
        },
      );
      await t.test(
        'legacy rebuilding never blesses an old body with current-CVE revision evidence',
        async () => {
          await reset();
          const cve = makeCve('CVE-2026-98105');
          const [finding] = await seed([cve]);
          const advisory: Advisory = {
            id: 'ADV-legacy',
            title: 'Old notice',
            severity: 'HIGH',
            cveIds: [cve.cveId],
            findingIds: [finding.id],
            createdDate: new Date().toISOString(),
            deliveryStatus: 'PENDING',
            recipientCount: 1,
            executiveSummary: 'Old content',
            affectedSystems: [finding.matchedAssetName],
            remediationInstructions: 'Install obsolete patch https://example.com/obsolete-patch',
          };
          await put(pool, 'advisories', advisory.id, advisory);
          const id = await enqueue(
            pool,
            'email',
            'all',
            advisory.id,
            {
              subject: 'Old subject',
              text: 'Old text',
              html: '<html><body>Install obsolete patch https://example.com/obsolete-patch</body></html>',
              cveIds: [cve.cveId],
            },
            'legacy-body',
          );
          const job = (await pool.query('SELECT * FROM outbox WHERE id=$1', [id])).rows[0];
          const rebuilt = await rebuildLegacyDeliveryPayload(pool, job);
          if (rebuilt) {
            assert.ok(!job.payload.html?.includes('obsolete-patch'));
            assert.ok(!job.payload.text.includes('obsolete-patch'));
            assert.ok(
              job.payload.text.includes('current-patch') || job.payload.html?.includes('current-patch'),
            );
          } else {
            assert.equal(
              (await pool.query('SELECT payload FROM outbox WHERE id=$1', [id])).rows[0].payload.cveRevisions,
              undefined,
            );
          }
        },
      );
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
