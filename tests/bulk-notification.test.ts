import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate, put, get, list } from '../server/db.ts';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import type { Finding, NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;
test('POST /api/send-bulk-notification links findings to an advisory', { skip: !database }, async (t) => {
  const base = createPool(database!);
  const schema = 'bulk_' + randomBytes(8).toString('hex');
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
    throw new Error('No network expected during bulk notification');
  };
  const reset = async () => {
    await pool.query('DELETE FROM records; DELETE FROM outbox');
    await put(pool, 'settings', 'main', settings);
    await put(pool, 'template', 'main', { templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION });
    await put(pool, 'watchlist', asset.id, asset);
  };
  try {
    await migrate(pool);
    await t.test('held finding is linked to a new advisory and queued (not a 500)', async () => {
      await reset();
      const findings = runVulnerabilityPipeline(
        [],
        [makeCve('CVE-2026-98101')],
        [asset],
        [],
        [],
        settings,
      ).newFindings;
      assert.equal(findings.length, 1);
      const finding = { ...findings[0], notificationStatus: 'REVIEW_REQUIRED' as const, advisoryId: null };
      await put(pool, 'findings', finding.id, finding);
      await put(pool, 'recipients', 'sec-team', {
        id: 'sec-team',
        name: 'Security Team',
        email: 'sec@example.invalid',
        enabled: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await createUser(pool, 'admin', 'Bulk-test-password-2026!', 'ADMIN');
      const app = createApp(pool, config, noNetwork);
      const agent = supertest.agent(app);
      const logged = await agent
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: 'admin', password: 'Bulk-test-password-2026!' });
      assert.equal(logged.status, 200, JSON.stringify(logged.body));
      const csrf = logged.body.csrfToken as string;
      const res = await agent
        .post('/api/send-bulk-notification')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ findingIds: [finding.id], reason: 'regression', recipientMode: 'SECURITY_TEAM' });
      assert.equal(res.status, 202, `expected 202, got ${res.status}: ${JSON.stringify(res.body)}`);
      const recipients = await list<any>(pool, 'recipients');
      assert.ok(recipients.length, 'SECURITY_TEAM recipient must be configured');
      const updated = await get<Finding>(pool, 'findings', finding.id);
      assert.equal(updated?.notificationStatus, 'QUEUED_FOR_DISPATCH', 'finding must be linked to dispatch');
      assert.match(updated?.advisoryId ?? '', /^ADV-/, 'finding must be linked to a generated advisory');
      const advisoryRows = await pool.query<{ data: any }>(
        "SELECT data FROM records WHERE kind='advisories'",
      );
      assert.ok((advisoryRows.rowCount ?? 0) >= 1, 'an advisory record must be stored');
    });
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await base.end();
  }
});
