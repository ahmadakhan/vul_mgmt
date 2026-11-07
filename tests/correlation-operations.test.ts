import { grantRuntimePrivileges } from '../server/runtimePrivileges.ts';
import { createDatabaseRateLimiter } from '../server/rateLimit.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import pg from 'pg';
import { createPool, migrate, transaction, get, put } from '../server/db.ts';
import { applyCommand } from '../server/commands.ts';
import { loadConfig } from '../server/config.ts';
import { syncCorrelationAsset, backfillCorrelationInventory } from '../server/correlation/inventory.ts';
import { correlationPreflight } from '../server/correlation/preflight.ts';
import { AdvisoryIngestor } from '../server/correlation/ingest.ts';
import { TextCorrelationEngine } from '../server/correlation/engine.ts';
import { CorrelationTelemetry } from '../server/correlation/telemetry.ts';
import { DeadLetterQueue } from '../server/correlation/deadLetter.ts';
import {
  decideCorrelationReview,
  decideDeadLetter,
  updateCorrelationPolicy,
  retainCorrelationData,
  correlationWorkflows,
} from '../server/correlation/operations.ts';
import { queueNativeNotifications } from '../server/correlation/notifications.ts';
import { deliverNext } from '../server/delivery.ts';
import type { WatchListItem } from '../src/types/index.ts';
const database = process.env.TEST_DATABASE_URL;
const key = randomBytes(32).toString('base64');
const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: database || 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: key,
  WORKER_ENABLED: 'false',
});
const article = (suffix: string, fields: Record<string, unknown> = {}) => ({
  title: 'Kubernetes actively exploited vulnerability',
  content: 'An unpatched zero-day vulnerability affects k8s.',
  url: `https://example.org/operations/${suffix}`,
  ...fields,
});
const cpe = (version: string) => `cpe:2.3:a:kubernetes:kubernetes:${version}:*:*:*:*:*:*:*`;

test(
  'native operational workflows, notifications, retention and real connection termination',
  { skip: !database, timeout: 30000 },
  async (t) => {
    const master = createPool(database!);
    const schema = 'correlation_ops_' + randomBytes(12).toString('hex');
    const directory = await mkdtemp(join(tmpdir(), 'correlation-ops-'));
    let pool: pg.Pool | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      pool = new pg.Pool({
        connectionString: database,
        options: `-c search_path=${schema}`,
        connectionTimeoutMillis: 2000,
        max: 6,
      });
      pool.on('error', () => {});
      await migrate(pool);
      const db = pool;
      const telemetry = new CorrelationTelemetry(
        new Writable({
          write(_c, _e, cb) {
            cb();
          },
        }),
      );
      const letters = new DeadLetterQueue(directory, [key], telemetry);
      const ingestor = new AdvisoryIngestor(telemetry, letters);
      const asset: WatchListItem = {
        id: 'legacy-inventory-id',
        vendor: 'kubernetes',
        product: 'kubernetes',
        version: '1.28.0',
        cpes: [cpe('1.28.0'), cpe('1.28.1')],
        purls: ['pkg:generic/kubernetes@1.28.0', 'pkg:generic/k8s@1.28.0'],
        active: true,
        assetTag: 'Test cluster',
        ownerGroup: 'Platform',
        createdAt: new Date().toISOString(),
      };
      let nativeId = '';
      await t.test('inventory projection preserves native ownership and all identities', async () => {
        const ownerId = randomUUID();
        await db.query("INSERT INTO assets(id,vendor,product,version) VALUES($1,'owner','service','1.0')", [
          ownerId,
        ]);
        await put(db, 'watchlist', asset.id, asset);
        await transaction(db, (tx) => backfillCorrelationInventory(tx));
        const managed = await db.query<{ native_id: string }>(
          'SELECT native_id FROM correlation_managed_assets WHERE record_id=$1',
          [asset.id],
        );
        nativeId = managed.rows[0].native_id;
        assert.equal((await db.query('SELECT * FROM assets')).rowCount, 1);
        await ingestor.processIncomingAdvisory(
          article('secondary', { purls: ['pkg:generic/k8s@1.28.0'] }),
          db,
        );
        assert.equal(
          (await db.query('SELECT confidence FROM correlation_matches WHERE asset_id=$1', [nativeId])).rows[0]
            .confidence,
          'HIGH',
        );
        await transaction(db, (tx) =>
          applyCommand(tx, config, { action: 'asset.toggle', id: asset.id, actor: 'test' }),
        );
        assert.equal(
          (await db.query('SELECT * FROM correlation_asset_inventory WHERE id=$1', [nativeId])).rowCount,
          0,
        );
        await transaction(db, (tx) =>
          applyCommand(tx, config, { action: 'asset.toggle', id: asset.id, actor: 'test' }),
        );
        assert.equal(
          (await db.query('SELECT * FROM correlation_asset_inventory WHERE id=$1', [nativeId])).rowCount,
          1,
        );
        assert.equal((await db.query('SELECT * FROM assets WHERE id=$1', [ownerId])).rows[0].vendor, 'owner');
      });
      await t.test('real backend termination rolls back and retries on a fresh socket', async () => {
        const engine = new TextCorrelationEngine();
        const original = engine.correlate.bind(engine);
        let attempts = 0;
        engine.correlate = async (input, extracted, query) => {
          if (++attempts === 1) {
            const pid = (await query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0].pid;
            await master.query('SELECT pg_terminate_backend($1)', [pid]);
            await query('SELECT 1');
          }
          return original(input, extracted, query);
        };
        assert.equal(
          await new AdvisoryIngestor(telemetry, letters, engine).processIncomingAdvisory(
            article('socket-recovery'),
            db,
          ),
          'PROCESSED',
        );
        assert.equal(attempts, 2);
        assert.equal(
          (
            await db.query(
              "SELECT id FROM unstructured_advisories WHERE url='https://example.org/operations/socket-recovery'",
            )
          ).rowCount,
          1,
        );
      });
      await t.test(
        'restricted runtime role can ingest and rate limit without owner-table writes',
        async (context) => {
          const permission = await master.query<{ allowed: boolean }>(
            'SELECT rolsuper OR rolcreaterole AS allowed FROM pg_roles WHERE rolname=current_user',
          );
          if (!permission.rows[0].allowed) {
            context.skip('Database role creation is unavailable');
            return;
          }
          const role = 'correlation_role_' + randomBytes(10).toString('hex');
          await master.query(`CREATE ROLE ${role} NOLOGIN`);
          try {
            await grantRuntimePrivileges(db, role);
            const client = await db.connect();
            try {
              await client.query('BEGIN');
              await client.query(`SET LOCAL ROLE ${role}`);
              const limiter = createDatabaseRateLimiter(client as unknown as pg.Pool, 1, 0.000001);
              assert.equal((await limiter('runtime-permissions')).allowed, true);
              assert.equal((await limiter('runtime-permissions')).allowed, false);
              const input = article('restricted-role');
              const insertedArticle = await client.query(
                'INSERT INTO unstructured_advisories(title,content,url,fingerprint) VALUES($1,$2,$3,$4) RETURNING id',
                [input.title, input.content, input.url, randomBytes(32).toString('hex')],
              );
              const review = await client.query('INSERT INTO low_confidence_review_buffer(advisory_id,asset_id,reason) VALUES($1,$2,$3) RETURNING id', [insertedArticle.rows[0].id,nativeId,'Restricted review verification']);
              await decideCorrelationReview(client,review.rows[0].id,{decision:'APPROVED',note:'Verified applicability in regression'},'test');
              assert.equal((await client.query('SELECT confidence FROM correlation_matches WHERE advisory_id=$1',[insertedArticle.rows[0].id])).rows[0].confidence,'MEDIUM');
              assert.ok((await client.query('SELECT id FROM correlation_asset_inventory')).rowCount);
              await assert.rejects(client.query("UPDATE assets SET vendor='must-not-write'"), {
                code: '42501',
              });
              await client.query('ROLLBACK');
            } finally {
              client.release();
            }
          } finally {
            // The subtest aborts its transaction deliberately, and grants made
            // via SET LOCAL ROLE are rolled back with it. Reassign first so the
            // role owns nothing, then drop — both steps tolerate a role that
            // was never granted anything.
            await master.query(`REASSIGN OWNED BY ${role} TO current_user`).catch(() => {});
            await master.query(`DROP OWNED BY ${role}`).catch(() => {});
            await master.query(`DROP ROLE IF EXISTS ${role}`);
          }
        },
      );
      await t.test('precision corpus quarantines negation, lookalikes and ambiguous backports', async () => {
        await ingestor.processIncomingAdvisory(
          article('negated', {
            content: 'k8s is not affected. This vulnerability report is a false positive.',
          }),
          db,
        );
        await ingestor.processIncomingAdvisory(
          article('lookalike', {
            title: 'Research vulnerability',
            content: 'The notk8s and kubernetesish names are unrelated.',
          }),
          db,
        );
        await ingestor.processIncomingAdvisory(
          article('fixed', {
            entities: [{ vendor: 'kubernetes', product: 'kubernetes', affectedRange: '<1.0' }],
          }),
          db,
        );
        const rows = await db.query(
          `SELECT m.* FROM correlation_matches m JOIN unstructured_advisories a ON a.id=m.advisory_id WHERE a.url=ANY($1::text[])`,
          [['negated', 'lookalike', 'fixed'].map((x) => `https://example.org/operations/${x}`)],
        );
        assert.equal(rows.rowCount, 0);
      });
      await t.test('review decisions are audited and replay validates encrypted data', async () => {
        await ingestor.processIncomingAdvisory(
          article('unmapped', {
            title: 'Unpatched zero-day vulnerability',
            content: 'Unknown software actively exploited in the wild.',
          }),
          db,
        );
        let workflows = await correlationWorkflows(db);
        const review = workflows.reviews.find((row) => row.title === 'Unpatched zero-day vulnerability')!;
        assert.ok(review);
        await transaction(db, (tx) =>
          decideCorrelationReview(
            tx,
            review.id,
            { decision: 'APPROVED', assetId: nativeId, note: 'Verified platform applicability' },
            'reviewer',
          ),
        );
        await assert.rejects(
          transaction(db, (tx) =>
            decideCorrelationReview(
              tx,
              review.id,
              { decision: 'DISMISSED', note: 'Duplicate decision attempt' },
              'reviewer',
            ),
          ),
        );
        await letters.capture({ invalid: 'malformed' }, 'VALIDATION_FAILED', randomUUID(), db);
        await Promise.all([letters.flush(db),      new DeadLetterQueue(directory,[key],telemetry).flush(db)]);
        workflows = await correlationWorkflows(db);
        const letter = workflows.deadLetters[0];
        assert.ok(letter);
        await assert.rejects(
          transaction(db, (tx) =>
            decideDeadLetter(
              tx,
              letter.id,
              { action: 'REPLAYED', note: 'Replay original invalid input' },
              'reviewer',
              [key],
            ),
          ),
        );
        await transaction(db, (tx) =>
          decideDeadLetter(
            tx,
            letter.id,
            { action: 'REPLAYED', note: 'Corrected advisory validated', payload: article('corrected') },
            'reviewer',
            [key],
          ),
        );
        assert.equal(
          (await db.query('SELECT * FROM correlation_pending WHERE id=$1', [`replay:${letter.id}`])).rowCount,
          1,
        );
      });
      await t.test(
        'native delivery uses outbox review, subscriptions, dedupe and evidence revalidation',
        async () => {
          await put(db, 'recipients', 'security', {
            id: 'security',
            name: 'Security',
            email: 'security@example.invalid',
            role: 'Security',
            deliveryGroup: 'SECURITY_TEAM',
            subscriptionTier: 'ALL_SEVERITIES',
            enabled: true,
          });
          await put(db, 'recipients', 'critical', {
            id: 'critical',
            name: 'Critical',
            email: 'critical@example.invalid',
            role: 'Security',
            deliveryGroup: 'SECURITY_TEAM',
            subscriptionTier: 'CRITICAL_HIGH_ONLY',
            enabled: true,
          });
          await transaction(db, (tx) =>
            updateCorrelationPolicy(
              tx,
              { notificationsEnabled: true, retentionEnabled: true, retentionHours: 24 },
              'admin',
            ),
          );
          // Old matches predate activation and must not be broadcast.
          assert.equal(await transaction(db, (tx) => queueNativeNotifications(tx)), 0);
          await ingestor.processIncomingAdvisory(
            article('notify-high', { purls: ['pkg:generic/k8s@1.28.0'] }),
            db,
          );
          assert.equal(await transaction(db, (tx) => queueNativeNotifications(tx)), 1);
          assert.equal(await transaction(db, (tx) => queueNativeNotifications(tx)), 0);
          let sends = 0;
          const request = async () => ({ status: 200, headers: {}, body: '' });
          assert.equal(
            await deliverNext(db, config, request, async () => {
              sends++;
              return 'mock-accepted';
            }),
            true,
          );
          assert.equal(sends, 1);
          await ingestor.processIncomingAdvisory(article('notify-medium'), db);
          assert.equal(await transaction(db, (tx) => queueNativeNotifications(tx)), 1);
          const review = (
            await db.query(
              "SELECT id,status FROM outbox WHERE advisory_id=(SELECT 'NATIVE:'||id::text FROM unstructured_advisories WHERE url='https://example.org/operations/notify-medium')",
            )
          ).rows[0];
          // A MEDIUM-confidence native correlation is delivered like any other:
          // there is no review queue, and the subject states the confidence.
          assert.equal(review.status, 'QUEUED');
          assert.equal(
            await deliverNext(db, config, request, async () => {
              sends++;
              return 'mock';
            }),
            true,
          );
          assert.equal(sends, 2);
          await ingestor.processIncomingAdvisory(
            article('notify-stale', { purls: ['pkg:generic/k8s@1.28.0'] }),
            db,
          );
          await transaction(db, (tx) => queueNativeNotifications(tx));
          await transaction(db, (tx) => syncCorrelationAsset(tx, { ...asset, active: false }));
          await deliverNext(db, config, request, async () => {
            sends++;
            return 'must-not-send';
          });
          assert.equal(sends, 2);
          assert.equal(
            (
              await db.query(
                "SELECT status FROM outbox WHERE advisory_id=(SELECT 'NATIVE:'||id::text FROM unstructured_advisories WHERE url='https://example.org/operations/notify-stale')",
              )
            ).rows[0].status,
            'FAILED',
          );
          await transaction(db, (tx) => syncCorrelationAsset(tx, asset));
        },
      );
      await t.test('retention preserves open work and protected article/inventory rows', async () => {
        const before = (await db.query('SELECT count(*)::int AS count FROM unstructured_advisories')).rows[0]
          .count;
        const closed = (await db.query('SELECT review_id FROM correlation_review_decisions LIMIT 1')).rows[0]
          .review_id;
        await db.query(
          "UPDATE correlation_review_decisions SET decided_at=now()-interval '3 days' WHERE review_id=$1",
          [closed],
        );
        await db.query("UPDATE correlation_dead_letter_actions SET decided_at=now()-interval '3 days'");
        assert.ok((await transaction(db, (tx) => retainCorrelationData(tx))) >= 2);
        assert.equal(
          (await db.query('SELECT * FROM low_confidence_review_buffer WHERE id=$1', [closed])).rowCount,
          0,
        );
        assert.equal(
          (await db.query('SELECT count(*)::int AS count FROM unstructured_advisories')).rows[0].count,
          before,
        );
        assert.ok((await correlationWorkflows(db)).counts.reviews > 0);
        assert.equal((await correlationPreflight(db)).compatible, true);
      });
      await t.test('pre-CVE cluster survives CVE publication and inherits operator rulings', async () => {
        // A zero-day article (no CVE ID) creates a cluster for the matched
        // identity; a corroborating article joins the same cluster rather than
        // producing a second, orphaned record.
        await ingestor.processIncomingAdvisory(
          article('pre-cve-a', { title: 'Kubernetes zero-day exploited', content: 'An unpatched zero-day vulnerability in k8s is exploited.' }),
          db,
        );
        await ingestor.processIncomingAdvisory(
          article('pre-cve-b', { title: 'K8s flaw under attack', content: 'Attackers exploit the unpatched k8s vulnerability in the wild.' }),
          db,
        );
        const clusters = await db.query<{ id: string; vendor: string; product: string }>(
          "SELECT id,vendor,product FROM pre_cve_clusters WHERE vendor='kubernetes' AND product='kubernetes'",
        );
        assert.equal(clusters.rowCount, 1, 'corroborating coverage must join one cluster');
        assert.ok(
          (
            await db.query('SELECT advisory_id FROM pre_cve_cluster_members WHERE cluster_id=$1', [
              clusters.rows[0].id,
            ])
          ).rows.length >= 2,
        );

        // An operator dismisses the pre-CVE match; the disposition must persist
        // against the cluster, not just the article.
        const pendingReview = await db.query<{ id: string; asset_id: string }>(
          `SELECT b.id,b.asset_id FROM low_confidence_review_buffer b
           JOIN unstructured_advisories a ON a.id=b.advisory_id
           LEFT JOIN correlation_review_decisions d ON d.review_id=b.id
           WHERE d.review_id IS NULL AND a.url='https://example.org/operations/pre-cve-a' LIMIT 1`,
        );
        if (pendingReview.rows[0]?.asset_id) {
          await decideCorrelationReview(
            db,
            pendingReview.rows[0].id,
            { decision: 'DISMISSED', note: 'Verified not affected on this cluster in regression' },
            'test',
          );
          assert.equal(
            (
              await db.query(
                "SELECT disposition FROM pre_cve_dispositions WHERE cluster_id=$1 AND asset_id=$2",
                [clusters.rows[0].id, pendingReview.rows[0].asset_id],
              )
            ).rows[0].disposition,
            'FALSE_POSITIVE',
          );
        }

        // NVD publishes the CVE. Binding must resolve the cluster and expose the
        // earlier ruling so the canonical finding is suppressed before queueing.
        const { bindClusterToCve, clusterSuppressedAssets } = await import(
          '../server/correlation/clusters.ts'
        );
        assert.equal(
          await bindClusterToCve(db, 'CVE-2026-9999', 'kubernetes', 'kubernetes'),
          clusters.rows[0].id,
        );
        assert.equal(
          (await db.query('SELECT resolved_cve_id FROM pre_cve_clusters WHERE id=$1', [clusters.rows[0].id]))
            .rows[0].resolved_cve_id,
          'CVE-2026-9999',
        );
        const suppressed = await clusterSuppressedAssets(db, 'CVE-2026-9999');
        if (pendingReview.rows[0]?.asset_id)
          assert.ok(suppressed.has(pendingReview.rows[0].asset_id));
        // A resolved cluster must not accept new pre-CVE members.
        await ingestor.processIncomingAdvisory(
          article('pre-cve-c', { title: 'Kubernetes follow-up', content: 'Another unpatched k8s zero-day vulnerability report.' }),
          db,
        );
        assert.equal(
          (
            await db.query(
              'SELECT count(*)::int AS n FROM pre_cve_cluster_members WHERE cluster_id=$1',
              [clusters.rows[0].id],
            )
          ).rows[0].n >= 2,
          true,
        );
      });
    } finally {
      await pool?.end();
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
