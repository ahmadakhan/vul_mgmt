import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
  createPool,
  get,
  getForUpdate,
  list,
  migrate,
  put,
  putMany,
  state,
  transaction,
  verifyStoredAudit,
  appendAudit,
} from '../server/db.ts';
import { chainAuditLogs, merkleRoot } from '../src/utils/cryptoChain.ts';
import { applyCommand } from '../server/commands.ts';
import { loadConfig } from '../server/config.ts';
import { queryCollection } from '../server/collections.ts';
import { advisoryRevision, queueAdvisory } from '../server/delivery.ts';
import {
  buildCandidatePairs,
  syncMatchIndex,
  versionOrdinal,
} from '../server/versionIndex.ts';
import type {
  Advisory,
  AuditLog,
  Finding,
  NormalizedCVE,
  WatchListItem,
} from '../src/types/index.ts';
import { INITIAL_NORMALIZED_CVES } from './fixtures/seedData';

const database = process.env.TEST_DATABASE_URL;
const cpe = (version: string, vendor = 'example', product = 'widget') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

const cve = (id: string, overrides: Partial<NormalizedCVE> = {}): NormalizedCVE => ({
  ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
  cveId: id,
  cpeMatches: [cpe('*')],
  versionRange: undefined,
  cpeMatchDetails: undefined,
  purls: undefined,
  vex: undefined,
  vexStatements: [],
  sourceFeeds: [],
  exploitationSources: [],
  cisaKev: { ...structuredClone(INITIAL_NORMALIZED_CVES[0].cisaKev), isKev: false },
  exploitStatus: 'None',
  ...overrides,
});

const finding = (value: NormalizedCVE, overrides: Partial<Finding> = {}): Finding => ({
  id: 'finding-1',
  cveId: value.cveId,
  cve: value,
  matchedAssetId: 'asset-1',
  matchedAssetName: 'Widget 1.5',
  matchedAssetVendor: 'example',
  matchedAssetProduct: 'widget',
  matchedCpe: cpe('1.5'),
  matchingMethod: 'CPE_EXACT',
  matchingEvidence: 'exact match',
  exploitRisk: 'STANDARD',
  notificationStatus: 'QUEUED_FOR_DISPATCH',
  status: 'MONITORED',
  autoDispatchedAt: null,
  advisoryId: null,
  reviewNotifiedAt: null,
  timeline: [],
  ...overrides,
});

const advisory = (id: string): Advisory => ({
  id,
  title: 'Vulnerability notice: CVE-2026-70001',
  severity: 'HIGH',
  cveIds: ['CVE-2026-70001'],
  findingIds: ['finding-1'],
  createdDate: '2026-10-25T00:00:00.000Z',
  deliveryStatus: 'PENDING',
  recipientCount: 0,
  executiveSummary: 'One inventory correlation requires investigation.',
  remediationInstructions: 'Review the vendor advisory and deploy tested remediation.',
  affectedSystems: ['Widget 1.5'],
  vendorLink: '',
});

const watch = (id: string, version: string | undefined, overrides: Partial<WatchListItem> = {}): WatchListItem => ({
  id,
  vendor: 'example',
  product: 'widget',
  version,
  cpes: [cpe(version ?? '1.5')],
  assetTag: 'TEST',
  ownerGroup: 'test',
  active: true,
  createdAt: '2026-10-25T00:00:00.000Z',
  ...overrides,
});

const outboxCount = async (pool: ReturnType<typeof createPool>) =>
  (await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count as number;

test('version ordinals encode only provably ordered numeric versions', () => {
  assert.equal(versionOrdinal('*'), null);
  assert.equal(versionOrdinal('-'), null);
  assert.equal(versionOrdinal(''), null);
  assert.equal(versionOrdinal('1.2.3-beta'), null);
  assert.equal(versionOrdinal('2.5-rc1'), null);
  assert.equal(versionOrdinal('1.2.3.4'), versionOrdinal('1.2.3.4'));
  assert.ok(versionOrdinal('1.2')! < versionOrdinal('1.10')!);
  assert.ok(versionOrdinal('1.10')! < versionOrdinal('2.0')!);
  assert.equal(versionOrdinal('1.2'), versionOrdinal('1.2.0'));
  assert.equal(versionOrdinal('10000'), null, 'components above the packing base stay unbounded');
});

test('advisory revision changes when CVE evidence changes but not for enrichment', () => {
  const base = cve('CVE-2026-70001', { description: 'original evidence' });
  const notice = advisory('adv-revision');
  const original = advisoryRevision(notice, [finding(base)]);

  // Same finding row, changed CVE content: this must be a new advisory revision
  // so the documented dedupe contract redelivers materially changed evidence.
  const changed = cve(base.cveId, { description: 'revised evidence' });
  assert.notEqual(original, advisoryRevision(notice, [finding(changed)]));

  const reviewOnly: NormalizedCVE = { ...base, applicabilityPolicy: 'REVIEW_ONLY' };
  assert.notEqual(original, advisoryRevision(notice, [finding(reviewOnly)]));

  // Enrichment-only changes are deliberately excluded from the content revision.
  const enriched: NormalizedCVE = {
    ...base,
    sourceFeeds: ['feed-a', 'feed-b'],
    modifiedDate: '2026-10-29T00:00:00.000Z',
  };
  assert.equal(original, advisoryRevision(notice, [finding(enriched)]));
});

test('enterprise hardening invariants', { skip: !database }, async (t) => {
  const base = createPool(database!);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA "${schema}"`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);
  const reset = async () => {
    await pool.query(
      'DELETE FROM records; DELETE FROM outbox; DELETE FROM match_asset_index; DELETE FROM match_cve_index',
    );
  };

  try {
    await migrate(pool);

    await t.test('outbox dedupe is content-derived and idempotent across random advisory IDs', async () => {
      await reset();
      await transaction(pool, (db) =>
        put(db, 'recipients', 'rec-a', {
          id: 'rec-a',
          name: 'Security',
          email: 'security@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
          deliveryGroup: 'SECURITY_TEAM',
        }),
      );
      const value = cve('CVE-2026-70001');
      const findings = [finding(value)];

      assert.equal(
        await transaction(pool, (db) => queueAdvisory(db, advisory('adv-1'), findings)),
        1,
      );
      // A rerun creates a new random advisory ID but the same content. It must
      // not produce a second delivery.
      assert.equal(
        await transaction(pool, (db) => queueAdvisory(db, advisory('adv-2'), findings)),
        0,
      );
      assert.equal(await outboxCount(pool), 1);

      // Volatile delivery/exploitability state is not content.
      const volatileFindings = [
        finding(value, {
          notificationStatus: 'AUTO_DISPATCHED',
          exploitability: {
            status: 'affected',
            conflictState: 'CONSISTENT',
            suppressed: false,
            requiresReview: false,
            reason: 'recomputed',
            sources: ['Vendor'],
            applicableStatements: 1,
            ignoredStatements: 0,
          },
        }),
      ];
      assert.equal(
        await transaction(pool, (db) => queueAdvisory(db, advisory('adv-3'), volatileFindings)),
        0,
      );
      assert.equal(await outboxCount(pool), 1);

      // How a match was spelled or evidenced is not content either: a corrected
      // evidence string or CPE spelling must not re-deliver the same advisory to
      // the same recipient.
      const respelled = [
        finding(value, { matchingEvidence: 'inventory was corrected', matchedCpe: cpe('1.5') }),
      ];
      assert.equal(
        await transaction(pool, (db) => queueAdvisory(db, advisory('adv-4'), respelled)),
        0,
      );
      assert.equal(await outboxCount(pool), 1);

      // A material correlation change (a different affected system) is a new
      // revision and may be delivered.
      const revised = [
        finding(value, { matchedAssetId: 'asset-2', matchedAssetName: 'Widget 2.0' }),
      ];
      const revisedAdvisory = { ...advisory('adv-5'), affectedSystems: ['Widget 2.0'] };
      assert.equal(
        await transaction(pool, (db) => queueAdvisory(db, revisedAdvisory, revised)),
        1,
      );
      assert.equal(await outboxCount(pool), 2);

      // An explicit operator dispatch key still overrides content dedupe.
      assert.equal(
        await transaction(pool, (db) =>
          queueAdvisory(db, advisory('adv-6'), findings, undefined, 'operator-resend'),
        ),
        1,
      );
      assert.equal(await outboxCount(pool), 3);
    });

    await t.test('editing recipients and webhooks preserves delivery health and credentials', async () => {
      await reset();
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: database!,
        APP_ORIGIN: 'http://127.0.0.1:8080',
        ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      });
      const recipientInput = {
        name: 'Security',
        email: 'security@example.invalid',
        role: 'security',
        subscriptionTier: 'ALL_SEVERITIES' as const,
        enabled: true,
      };
      await transaction(pool, (db) =>
        applyCommand(db, config, { action: 'recipient.save', data: recipientInput, actor: 'test' }),
      );
      const [recipient] = await list<{ id: string; deliverySuccessRate: number }>(
        pool,
        'recipients',
      );
      await transaction(pool, (db) =>
        put(db, 'recipients', recipient.id, { ...recipient, deliverySuccessRate: 73 }),
      );
      await transaction(pool, (db) =>
        applyCommand(db, config, {
          action: 'recipient.save',
          id: recipient.id,
          data: { ...recipientInput, name: 'Security Team' },
          actor: 'test',
        }),
      );
      const updatedRecipient = await get<{ name: string; deliverySuccessRate: number }>(
        pool,
        'recipients',
        recipient.id,
      );
      assert.equal(updatedRecipient?.name, 'Security Team');
      assert.equal(updatedRecipient?.deliverySuccessRate, 73);

      const webhookInput = {
        name: 'Slack',
        url: 'https://hooks.example.invalid/services/test',
        provider: 'SLACK' as const,
        secretToken: '',
        enabled: true,
        events: ['ALL' as const],
      };
      await transaction(pool, (db) =>
        applyCommand(db, config, { action: 'webhook.save', data: webhookInput, actor: 'test' }),
      );
      const [hook] = await list<{ id: string; secretToken: string; deliveryCount: number }>(
        pool,
        'webhooks',
      );
      await transaction(pool, (db) =>
        put(db, 'webhooks', hook.id, { ...hook, deliveryCount: 9 }),
      );
      await transaction(pool, (db) =>
        applyCommand(db, config, {
          action: 'webhook.save',
          id: hook.id,
          data: { ...webhookInput, name: 'Slack Updated' },
          actor: 'test',
        }),
      );
      const updatedHook = await get<{ name: string; secretToken: string; deliveryCount: number }>(
        pool,
        'webhooks',
        hook.id,
      );
      assert.equal(updatedHook?.name, 'Slack Updated');
      assert.equal(updatedHook?.deliveryCount, 9);
      assert.equal(
        updatedHook?.secretToken,
        hook.secretToken,
        'a blank secret edit must not silently rotate the stored credential',
      );
      // The blank-keeps rule applies to an existing row only. A brand-new
      // Generic HMAC endpoint with no secret, or one switched to Generic HMAC
      // without supplying a secret, would be stored unsigned while creation
      // reported success, so it must be refused.
      await assert.rejects(
        transaction(pool, (db) =>
          applyCommand(db, config, {
            action: 'webhook.save',
            data: { ...webhookInput, provider: 'GENERIC_HMAC' as const },
            actor: 'test',
          }),
        ),
        /shared secret/i,
        'a new Generic HMAC webhook requires an explicit secret',
      );
    });

    await t.test('concurrent recipient creates cannot both pass the uniqueness check', async () => {
      await reset();
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: database!,
        APP_ORIGIN: 'http://127.0.0.1:8080',
        ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      });
      const recipientInput = {
        name: 'Security',
        email: 'duplicate@example.invalid',
        role: 'security',
        subscriptionTier: 'ALL_SEVERITIES' as const,
        enabled: true,
      };
      const results = await Promise.allSettled([
        transaction(pool, (db) =>
          applyCommand(db, config, { action: 'recipient.save', data: recipientInput, actor: 'first' }),
        ),
        transaction(pool, (db) =>
          applyCommand(db, config, { action: 'recipient.save', data: recipientInput, actor: 'second' }),
        ),
      ]);
      assert.equal(
        results.filter((result) => result.status === 'fulfilled').length,
        1,
        'exactly one concurrent create must commit',
      );
      const rejected = results.find(
        (result): result is PromiseRejectedResult => result.status === 'rejected',
      );
      assert.ok(rejected);
      assert.match(String(rejected.reason?.message), /already exists/);
      assert.equal((await list(pool, 'recipients')).length, 1);
    });

    await t.test('collection search treats LIKE wildcards as literal text', async () => {
      await reset();
      await transaction(pool, async (db) => {
        await put(db, 'watchlist', 'asset-percent', {
          ...watch('asset-percent', '1.5'),
          assetTag: '100% coverage',
        });
        await put(db, 'watchlist', 'asset-underscore', {
          ...watch('asset-underscore', '1.5'),
          assetTag: '100_ coverage',
        });
      });
      const percent = await queryCollection<{ id: string }>(pool, 'watchlist', {
        limit: 20,
        offset: 0,
        search: '100%',
      });
      assert.deepEqual(percent.items.map((item) => item.id), ['asset-percent']);

      const underscore = await queryCollection<{ id: string }>(pool, 'watchlist', {
        limit: 20,
        offset: 0,
        search: '100_',
      });
      assert.deepEqual(underscore.items.map((item) => item.id), ['asset-underscore']);
    });

    await t.test('a malformed legacy payload cannot abort a paginated collection', async () => {
      await reset();
      const now = new Date().toISOString();
      await transaction(pool, async (db) => {
        await put(db, 'cveData', 'legacy-bad-payload', {
          ...cve('CVE-2026-83001'),
          publishedDate: 'not-a-date',
          modifiedDate: '',
          epss: { score: 'not-a-number', percentile: 0 },
          cisaKev: { ...cve('CVE-2026-83001').cisaKev, isKev: 'unknown' },
        });
        await put(db, 'cveData', 'legacy-good-payload', {
          ...cve('CVE-2026-83002'),
          publishedDate: now,
          modifiedDate: now,
          cisaKev: { ...cve('CVE-2026-83002').cisaKev, isKev: true },
        });
      });
      const sorted = await queryCollection<{ cveId: string }>(pool, 'cveData', {
        limit: 10,
        offset: 0,
        sort: 'modified',
        order: 'desc',
      });
      assert.equal(sorted.total, 2);
      assert.equal(sorted.items[0].cveId, 'CVE-2026-83002', 'unparseable dates sort last');

      const inScope = await queryCollection<{ cveId: string }>(pool, 'cveData', {
        limit: 10,
        offset: 0,
        filters: { dateFilter: 'IN_SCOPE', scopeHours: 24 },
      });
      assert.deepEqual(inScope.items.map((item) => item.cveId), ['CVE-2026-83002']);

      const kev = await queryCollection<{ cveId: string }>(pool, 'cveData', {
        limit: 10,
        offset: 0,
        filters: { kev: true },
      });
      assert.deepEqual(kev.items.map((item) => item.cveId), ['CVE-2026-83002']);

      const epss = await queryCollection<{ cveId: string }>(pool, 'cveData', {
        limit: 10,
        offset: 0,
        filters: { epssMin: 0.5 },
      });
      assert.deepEqual(epss.items.map((item) => item.cveId), ['CVE-2026-83002']);
    });

    await t.test('findings default order ranks by the newest of published and modified dates', async () => {
      await reset();
      // Each finding's "latest activity" is the more recent of its two CVE dates.
      // The page defaults to last-modified; selecting "Latest" instead orders by
      // GREATEST(published, modified). The two orderings diverge here (modified-first
      // puts b ahead of a, while GREATEST puts a ahead of b), which also guards that
      // a published-first default never creeps back in.
      const a = finding(cve('CVE-2026-90101', {
        publishedDate: '2026-10-26T13:00:00Z',
        modifiedDate: '2020-01-01T00:00:00Z',
      }));
      const b = finding(cve('CVE-2026-90202', {
        publishedDate: '2019-01-01T00:00:00Z',
        modifiedDate: '2026-10-26T12:00:00Z',
      }));
      const c = finding(cve('CVE-2026-90303', {
        publishedDate: '2021-06-01T00:00:00Z',
        modifiedDate: '2021-06-01T00:00:00Z',
      }));
      await put(pool, 'findings', 'finding-latest-a', a);
      await put(pool, 'findings', 'finding-latest-b', b);
      await put(pool, 'findings', 'finding-latest-c', c);

      const cveOrder = (rows: { cveId: string }[]) => rows.map((row) => row.cveId);

      // Default ordering is last-modified only: b (modified 12:00) > c (2021) > a (2020).
      const latest = await queryCollection<{ cveId: string }>(pool, 'findings', {
        limit: 10,
        offset: 0,
      });
      assert.deepEqual(cveOrder(latest.items), ['CVE-2026-90202', 'CVE-2026-90303', 'CVE-2026-90101']);

      // Latest (GREATEST of published+modified) is a distinct modifier: a (13:00) > b (12:00) > c (2021).
      const explicit = await queryCollection<{ cveId: string }>(pool, 'findings', {
        limit: 10,
        offset: 0,
        sort: 'latest',
        order: 'desc',
      });
      assert.deepEqual(cveOrder(explicit.items), ['CVE-2026-90101', 'CVE-2026-90202', 'CVE-2026-90303']);

      // Sort by published only: a (13:00) > c (2021) > b (2019).
      const published = await queryCollection<{ cveId: string }>(pool, 'findings', {
        limit: 10,
        offset: 0,
        sort: 'published',
        order: 'desc',
      });
      assert.deepEqual(cveOrder(published.items), ['CVE-2026-90101', 'CVE-2026-90303', 'CVE-2026-90202']);

      // Sort by modified only: b (12:00) > c (2021) > a (2020).
      const modified = await queryCollection<{ cveId: string }>(pool, 'findings', {
        limit: 10,
        offset: 0,
        sort: 'modified',
        order: 'desc',
      });
      assert.deepEqual(cveOrder(modified.items), ['CVE-2026-90202', 'CVE-2026-90303', 'CVE-2026-90101']);
    });

    await t.test('state slices are bounded while counts and summary stay exact', async () => {
      await reset();
      const critical = cve('CVE-2026-82001', {
        cvss: { ...structuredClone(INITIAL_NORMALIZED_CVES[0].cvss), severity: 'CRITICAL' },
      });
      const high = cve('CVE-2026-82002', {
        cvss: { ...structuredClone(INITIAL_NORMALIZED_CVES[0].cvss), severity: 'HIGH' },
      });
      const resolved = cve('CVE-2026-82003');
      await transaction(pool, async (db) => {
        for (const value of [critical, high, resolved])
          await put(db, 'cveData', value.cveId, value);
        await put(db, 'findings', 'finding-active-1', finding(critical, { id: 'finding-active-1' }));
        await put(db, 'findings', 'finding-active-2', finding(high, { id: 'finding-active-2' }));
        await put(
          db,
          'findings',
          'finding-resolved',
          finding(resolved, { id: 'finding-resolved', status: 'RESOLVED' }),
        );
      });

      const snapshot = await state(pool, {
        limits: { cveData: 1, findings: 2, auditLogs: 0 },
      });
      assert.equal(snapshot.cveData.length, 1, 'heavy collections must honor the slice limit');
      assert.equal(snapshot.findings.length, 2);
      assert.equal(snapshot.counts.cveData, 3, 'counts must describe the full table');
      assert.equal(snapshot.counts.findings, 3);
      assert.equal(snapshot.summary.activeFindings, 2);
      assert.equal(snapshot.summary.criticalFindings, 1);
      assert.equal(snapshot.auditLogs.length, 0);
    });

    await t.test('state counters follow bulk writes, updates, deletes, rollback and truncate', async () => {
      await reset();
      const value = cve('CVE-2026-82010', {
        cvss: { ...INITIAL_NORMALIZED_CVES[0].cvss, severity: 'CRITICAL' },
        cisaKev: { ...INITIAL_NORMALIZED_CVES[0].cisaKev, isKev: true },
      });
      await putMany(pool, 'findings', [
        { id: 'active', data: finding(value) },
        { id: 'resolved', data: finding(value, { status: 'RESOLVED' }) },
        { id: 'excluded', data: finding(value, { notificationStatus: 'NOT_APPLICABLE' }) },
      ]);
      await put(pool, 'emailLogs', 'accepted', { status: 'ACCEPTED' });
      let snapshot = await state(pool, { limits: { findings: 0, auditLogs: 0 } });
      assert.equal(snapshot.counts.findings, 3);
      assert.deepEqual(snapshot.summary, { activeFindings: 1, criticalFindings: 1, kevFindings: 1, deliveredEmails: 1 });
      const migration = await readFile(new URL('../server/migrations/036_state_metrics.sql', import.meta.url), 'utf8');
      await transaction(pool, async (db) => { await db.query(migration); });
      assert.deepEqual((await state(pool)).summary, snapshot.summary);
      assert.equal((await state(pool)).counts.findings, 3);
      await assert.rejects(transaction(pool, async (db) => {
        await put(db, 'findings', 'rollback', finding(value));
        throw new Error('rollback counter update');
      }), /rollback counter update/);
      await put(pool, 'findings', 'active', finding(value, { status: 'PATCH_APPLIED' }));
      await put(pool, 'emailLogs', 'accepted', { status: 'FAILED' });
      await pool.query("DELETE FROM records WHERE kind='findings' AND id='resolved'");
      snapshot = await state(pool, { limits: { findings: 0, auditLogs: 0 } });
      assert.equal(snapshot.counts.findings, 2);
      assert.deepEqual(snapshot.summary, { activeFindings: 0, criticalFindings: 0, kevFindings: 0, deliveredEmails: 0 });
      await pool.query('TRUNCATE records');
      assert.equal((await state(pool)).counts.findings, 0);
    });

    await t.test('structured audit entries are searchable, redacted and safe under concurrent appends', async () => {
      await reset();
      const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: url.href,
        APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
      await transaction(pool, (db) => applyCommand(db, config, {
        action: 'settings.save', data: { reviewConfidenceThreshold: 65, emailEnabled: false }, actor: 'audit-operator', ipAddress: '192.0.2.12',
      }));
      const settings = await queryCollection<AuditLog>(pool, 'auditLogs', { limit: 10, offset: 0, search: 'settings.save' });
      const saved = settings.items.find((log) => log.actor === 'audit-operator');
      assert.equal(saved?.event, 'Workspace settings updated');
      assert.equal(saved?.context?.resourceId, 'main');
      assert.equal(saved?.context?.outcome, 'SUCCESS');
      assert.deepEqual(saved?.context?.fields, ['emailEnabled', 'reviewConfidenceThreshold']);
      await Promise.all(Array.from({ length: 12 }, (_, index) => appendAudit(pool,
        'Feed credentials updated', `password=private-value; feed ${index}`, 'audit-operator', 'FEED', 'INFO', '192.0.2.12',
        { action: 'feed.save', resourceType: 'feed', resourceId: `source-${index}`, requestId: `request-audit-${index}`, outcome: 'SUCCESS' },
      )));
      const result = await queryCollection<AuditLog>(pool, 'auditLogs', { limit: 50, offset: 0, search: 'request-audit-' });
      assert.equal(result.total, 12);
      assert.ok(result.items.every((log) => !log.details.includes('private-value')));
      assert.equal(new Set(result.items.map((log) => log.hash)).size, 12);
      assert.equal((await queryCollection(pool, 'auditLogs', { limit: 10, offset: 0, search: 'source-11' })).total, 1);
      assert.equal((await verifyStoredAudit(pool)).verified, true);
    });

    await t.test('streamed audit verification preserves roots and detects tampering across batches', async () => {
      const before = (await pool.query<{ data: AuditLog }>('SELECT data FROM audit ORDER BY seq DESC')).rows.map((row) => row.data);
      assert.deepEqual(await verifyStoredAudit(pool), { verified: true, logCount: before.length, merkleRoot: merkleRoot(before.map((log) => log.hash)) });
      const logs = chainAuditLogs(Array.from({ length: 600 }, (_, index) => ({
        id: `audit-${index}`, timestamp: new Date(index * 1000).toISOString(),
        category: 'SECURITY', level: 'INFO', event: 'Verification fixture',
        details: String(index), actor: 'test', ipAddress: '', prevHash: '', hash: '',
      } as AuditLog)), before[0]?.hash);
      await pool.query('INSERT INTO audit(data) SELECT value FROM jsonb_array_elements($1::jsonb)', [JSON.stringify([...logs].reverse())]);
      assert.deepEqual(await verifyStoredAudit(pool), { verified: true, logCount: before.length + 600, merkleRoot: merkleRoot([...logs, ...before].map((log) => log.hash)) });
      assert.equal((await state(pool, { limits: { auditLogs: 0 } })).counts.auditLogs, before.length + 600);
      await pool.query('ALTER TABLE audit DISABLE TRIGGER audit_immutable');
      try {
        await pool.query("UPDATE audit SET data=jsonb_set(data,'{details}','\"tampered\"') WHERE data->>'id'='audit-300'");
        assert.equal((await verifyStoredAudit(pool)).verified, false);
      } finally {
        await pool.query('ALTER TABLE audit ENABLE TRIGGER audit_immutable');
      }
      await assert.rejects(verifyStoredAudit(pool, AbortSignal.abort()), /cancelled/);
    });

    await t.test('named transaction locks are scoped: unrelated domains proceed, same domain serializes', async () => {
      await reset();
      let alphaCommittedAt = 0;
      let betaFinishedAt = 0;
      const alpha = transaction(
        pool,
        async (db) => {
          await db.query('SELECT pg_sleep(0.5)');
          alphaCommittedAt = Date.now();
        },
        undefined,
        { locks: ['domain-alpha'] },
      );
      const beta = transaction(
        pool,
        async (db) => {
          await db.query('SELECT pg_sleep(0.02)');
          betaFinishedAt = Date.now();
        },
        undefined,
        { locks: ['domain-beta'] },
      );
      await Promise.all([alpha, beta]);
      assert.ok(
        betaFinishedAt < alphaCommittedAt - 250,
        `unrelated scoped lock waited for the other domain (${alphaCommittedAt - betaFinishedAt}ms)`,
      );

      let firstFinishedAt = 0;
      let secondAcquiredAt = 0;
      const first = transaction(
        pool,
        async (db) => {
          await db.query('SELECT pg_sleep(0.4)');
          firstFinishedAt = Date.now();
        },
        undefined,
        { locks: ['domain-shared'] },
      );
      await new Promise((resolve) => setTimeout(resolve, 75));
      const second = transaction(
        pool,
        async () => {
          secondAcquiredAt = Date.now();
        },
        undefined,
        { locks: ['domain-shared'] },
      );
      await Promise.all([first, second]);
      assert.ok(
        secondAcquiredAt >= firstFinishedAt,
        'the same named lock must serialize concurrent transactions',
      );
    });

    await t.test('row-level locks serialize read-modify-write without the global lock', async () => {
      await reset();
      await transaction(pool, (db) => put(db, 'locks', 'row-1', { value: 0 }));
      let firstFinishedAt = 0;
      let observed = -1;
      const first = transaction(pool, async (db) => {
        const current = await getForUpdate<{ value: number }>(db, 'locks', 'row-1');
        assert.ok(current);
        await new Promise((resolve) => setTimeout(resolve, 300));
        await put(db, 'locks', 'row-1', { value: current.value + 1 });
        firstFinishedAt = Date.now();
      });
      await new Promise((resolve) => setTimeout(resolve, 75));
      const second = transaction(pool, async (db) => {
        const current = await getForUpdate<{ value: number }>(db, 'locks', 'row-1');
        observed = current?.value ?? -1;
      });
      await Promise.all([first, second]);
      assert.ok(firstFinishedAt > 0, 'first transaction should complete');
      assert.equal(observed, 1, 'second reader must observe the committed row after waiting');
    });

    await t.test('version index generates a conservative candidate superset and removes stale rows', async () => {
      await reset();
      const inRange = watch('asset-in', '1.5');
      const outOfRange = watch('asset-out', '2.5');
      const nonNumeric = watch('asset-rc', '2.5-rc1');
      const packageAsset = watch('asset-pkg', undefined, {
        cpes: [],
        purls: ['pkg:npm/widget@1.5'],
      });

      const ranged = cve('CVE-2026-71001', {
        cpeMatches: [cpe('*')],
        versionRange: { versionEndExcluding: '2.0' },
        cpeMatchDetails: [{ criteria: cpe('*'), range: { versionEndExcluding: '2.0' } }],
      });
      const exact = cve('CVE-2026-71002', {
        cpeMatches: [cpe('1.5')],
        cpeMatchDetails: [{ criteria: cpe('1.5') }],
      });
      const packageCve = cve('CVE-2026-71003', {
        cpeMatches: [],
        purls: ['pkg:npm/widget'],
      });
      const wildcard = cve('CVE-2026-71004', {
        cpeMatches: [cpe('*')],
        cpeMatchDetails: [{ criteria: 'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*' }],
      });

      await syncMatchIndex(pool, [ranged, exact, packageCve, wildcard], [
        inRange,
        outOfRange,
        nonNumeric,
        packageAsset,
      ]);
      let pairs = await buildCandidatePairs(pool);

      assert.deepEqual([...(pairs.get('CVE-2026-71001') ?? [])].sort(), [
        'asset-in',
        'asset-rc',
      ]);
      assert.deepEqual([...(pairs.get('CVE-2026-71002') ?? [])].sort(), ['asset-in', 'asset-rc']);
      assert.deepEqual([...(pairs.get('CVE-2026-71003') ?? [])], ['asset-pkg']);
      assert.equal(
        pairs.has('CVE-2026-71004'),
        false,
        'a wildcard criterion must fall back to the full candidate set',
      );

      // Re-sync after the inventory and criterion set shrink. Stale asset and
      // criterion rows must disappear instead of widening future candidates.
      const narrowed = cve('CVE-2026-71001', {
        cpeMatches: [cpe('*')],
        versionRange: { versionEndExcluding: '2.0' },
        cpeMatchDetails: [{ criteria: cpe('*'), range: { versionEndExcluding: '2.0' } }],
      });
      await syncMatchIndex(pool, [narrowed], [inRange]);
      pairs = await buildCandidatePairs(pool);
      assert.deepEqual([...(pairs.get('CVE-2026-71001') ?? [])], ['asset-in']);
      assert.equal(pairs.has('CVE-2026-71002'), false);
      assert.equal(pairs.has('CVE-2026-71003'), false);
      assert.equal(
        (await pool.query('SELECT count(*)::int AS count FROM match_cve_index')).rows[0].count,
        1,
      );
      assert.equal(
        (await pool.query('SELECT count(*)::int AS count FROM match_asset_index')).rows[0].count,
        1,
      );
    });

    await t.test('built-in aliases expand candidate identities on both sides', async () => {
      await reset();
      const microsoft = watch('asset-ms', '1.0', {
        vendor: 'microsoft',
        product: 'windows_server_2022',
        cpes: [cpe('1.0', 'microsoft', 'windows_server_2022')],
      });
      const aliased = cve('CVE-2026-71501', {
        cpeMatches: [cpe('1.0', 'msft', 'windows_server_2022')],
        cpeMatchDetails: [{ criteria: cpe('1.0', 'msft', 'windows_server_2022') }],
      });
      await syncMatchIndex(pool, [aliased], [microsoft]);
      const pairs = await buildCandidatePairs(pool);
      assert.deepEqual([...(pairs.get('CVE-2026-71501') ?? [])], ['asset-ms']);
    });

    await t.test('per-CPE criteria do not borrow the product-level version range', async () => {
      await reset();
      // The detail criterion has no bounds, meaning "any version of this
      // product". The CVE-level range belongs to a different criterion and must
      // not exclude the 2.5 inventory item from the candidate superset.
      const outOfProductRange = watch('asset-out', '2.5');
      const detailOnly = cve('CVE-2026-73001', {
        cpeMatches: [cpe('*')],
        versionRange: { versionEndExcluding: '2.0' },
        cpeMatchDetails: [{ criteria: cpe('*') }],
      });
      await syncMatchIndex(pool, [detailOnly], [outOfProductRange]);
      const pairs = await buildCandidatePairs(pool);
      assert.deepEqual([...(pairs.get('CVE-2026-73001') ?? [])], ['asset-out']);
    });

    await t.test('punctuation-only identities are expanded in the candidate index', async () => {
      await reset();
      const asset = watch('asset-punctuation', '1.5', {
        product: 'widget_pro',
        cpes: [cpe('1.5', 'example', 'widget_pro')],
      });
      const advisoryCve = cve('CVE-2026-73002', {
        cpeMatches: [cpe('1.5', 'example', 'widget-pro')],
        cpeMatchDetails: [{ criteria: cpe('1.5', 'example', 'widget-pro') }],
      });
      await syncMatchIndex(pool, [advisoryCve], [asset]);
      const pairs = await buildCandidatePairs(pool);
      assert.deepEqual([...(pairs.get('CVE-2026-73002') ?? [])], ['asset-punctuation']);
    });

    await t.test('assets with conflicting identifier versions stay unbounded', async () => {
      await reset();
      // The same inventory row has CPEs for 1.0 and 2.0. A single ordinal cannot
      // represent both, so the index must keep the row unbounded and let the
      // matcher decide instead of dropping the 2.0 candidate.
      const multiVersion = watch('asset-multi', '1.0', {
        cpes: [cpe('1.0'), cpe('2.0')],
      });
      const exactTwo = cve('CVE-2026-73003', {
        cpeMatches: [cpe('2.0')],
        cpeMatchDetails: [{ criteria: cpe('2.0') }],
      });
      await syncMatchIndex(pool, [exactTwo], [multiVersion]);
      const pairs = await buildCandidatePairs(pool);
      assert.deepEqual([...(pairs.get('CVE-2026-73003') ?? [])], ['asset-multi']);
    });

    await t.test('multi-criterion CVEs keep every index row across a refresh', async () => {
      await reset();
      const widget = watch('asset-widget', '1.5');
      const gadget = watch('asset-gadget', '1.5', {
        product: 'gadget',
        cpes: [cpe('1.5', 'example', 'gadget')],
      });
      const multi = cve('CVE-2026-72001', {
        cpeMatches: [cpe('1.5', 'example', 'widget'), cpe('1.5', 'example', 'gadget')],
        cpeMatchDetails: [
          { criteria: cpe('1.5', 'example', 'widget') },
          { criteria: cpe('1.5', 'example', 'gadget') },
        ],
      });
      await syncMatchIndex(pool, [multi], [widget, gadget]);
      let pairs = await buildCandidatePairs(pool);
      assert.deepEqual([...(pairs.get('CVE-2026-72001') ?? [])].sort(), [
        'asset-gadget',
        'asset-widget',
      ]);
      assert.equal(
        (await pool.query('SELECT count(*)::int AS count FROM match_cve_index')).rows[0].count,
        2,
        'both criteria must survive the stale-row cleanup',
      );

      const gadgetOnly = cve('CVE-2026-72001', {
        cpeMatches: [cpe('1.5', 'example', 'gadget')],
        cpeMatchDetails: [{ criteria: cpe('1.5', 'example', 'gadget') }],
      });
      await syncMatchIndex(pool, [gadgetOnly], [widget, gadget]);
      pairs = await buildCandidatePairs(pool);
      assert.deepEqual([...(pairs.get('CVE-2026-72001') ?? [])], ['asset-gadget']);
      assert.equal(
        (await pool.query('SELECT count(*)::int AS count FROM match_cve_index')).rows[0].count,
        1,
        'the removed criterion must be cleaned up',
      );
    });
  } finally {
    await pool.end().catch(() => {});
    await base.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => {});
    await base.end().catch(() => {});
  }
});
