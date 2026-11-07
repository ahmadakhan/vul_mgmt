import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPool, migrate, put } from '../server/db.ts';
import { CronDataProvider, runScheduledTraining } from '../server/ml/train/cron.ts';
import { INITIAL_FINDINGS } from './fixtures/seedData.ts';

const database = process.env.TEST_DATABASE_URL;
test(
  'all ML collectors and a scheduled training cycle use the migrated application schema',
  { skip: !database },
  async () => {
    const base = createPool(database!);
    const schema = 'ml_provider_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    const directory = await mkdtemp(join(tmpdir(), 'vulnstream-ml-provider-'));
    try {
      await migrate(pool);
      const provider = new CronDataProvider();
      const empty = await provider.collectAll(pool);
      // One collector per trained model. The registry grew to 18 models
      // (zeroDayRateLimitOptimizer included); the assertion tracks it so adding a
      // model without wiring its collector fails here instead of silently
      // training on an empty source.
      assert.equal(Object.keys(empty).length, 18);
      assert.ok(Object.values(empty).every((rows) => Array.isArray(rows) && rows.length === 0));
      const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
      const finding = {
        ...structuredClone(INITIAL_FINDINGS[0]),
        id: 'training-finding',
        matchedCpe: cpe,
        status: 'PATCH_APPLIED' as const,
        confidence: 85,
        matchingMethod: 'VENDOR_PRODUCT_ALIAS',
        autoDispatchedAt: new Date().toISOString(),
      };
      await put(pool, 'findings', finding.id, finding);
      await put(pool, 'watchlist', 'product', { cpes: [cpe], vendor: 'example', product: 'widget' });
      // The native text matcher stores product names, not CPE expressions.
      await pool.query(
        "INSERT INTO correlation_matches(advisory_id,asset_id,vendor,product,confidence,reason) VALUES(gen_random_uuid(),gen_random_uuid(),'example','widget','HIGH','fixture')",
      );
      const populated = await provider.collectAll(pool);
      assert.deepEqual(populated.cpeStrings, [cpe]);
      assert.equal(populated.dispatchOutcomes?.length, 1);
      assert.equal(populated.dispatchOutcomes?.[0].foundTruePositive, true);
      assert.equal(populated.matchConfidenceSamples?.length, 1);
      assert.equal(populated.aliasConfidenceSamples?.length, 1);
      assert.deepEqual(populated.remediationFindings?.[0].playbook, finding.cve.remediation);
      // Updated/accepted delivery rows have no sent_at/status_code SQL columns.
      await pool.query(
        "INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,attempts,error) VALUES('00000000-0000-4000-8000-000000000001','ml-fixture','email','recipient','TEST','{}','QUEUED',2,'Provider HTTP 429')",
      );
      await put(pool, 'emailLogs', '00000000-0000-4000-8000-000000000001', { provider: 'SendGrid' });
      const errors = await provider.collectDeliveryErrorSamples(pool);
      assert.equal(errors[0].provider, 'SendGrid');
      assert.equal(errors[0].statusCode, 429);
      assert.equal(errors[0].isPermanent, false);
      await put(pool, 'findings', 'old', {
        ...finding,
        id: 'old',
        matchedCpe: cpe.replace(':widget:', ':old:'),
      });
      await pool.query(
        "UPDATE records SET updated_at=now()-interval '60 days' WHERE kind='findings' AND id='old'",
      );
      assert.deepEqual(await provider.collectCpeStrings(pool), [cpe]);
      const result = await runScheduledTraining(pool, { directory });
      // One training result per model in the registry (18).
      assert.equal(result.summary.total, 18);
      assert.equal(result.summary.failed, 0);
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
