import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { verifyRegistrationAssets, verifyRegistrationCpes } from '../src/utils/watchlist.ts';
import { isProductWildcard, productWildcardCpe } from '../src/utils/registrationCpe.ts';
import { watchlistIdentity, watchlistDuplicateErrors } from '../shared/watchlistIdentity.ts';
import { createPool, migrate, transaction, list, get } from '../server/db.ts';
import { applyCommand } from '../server/commands.ts';
import { loadConfig } from '../server/config.ts';
import type { WatchListItem } from '../src/types/index.ts';

const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:x64:*';
const alias = cpe.replace(':example:', ':example_alias:');
const row = (id: string, product = 'widget'): WatchListItem => ({
  id,
  vendor: 'example',
  product,
  cpes: [cpe.replace(':widget:', `:${product}:`)],
  assetTag: id,
  ownerGroup: 'SOC',
  active: true,
  createdAt: '2026-10-01T00:00:00.000Z',
});

test('vendor correction never changes the requested architecture, update, or edition', async () => {
  for (const wrong of [
    cpe.replace(':x64:', ':x86:'),
    cpe.replace(':1.0:*:', ':1.0:update1:'),
    cpe.replace(':*:*:*:*:*:x64:', ':*:enterprise:*:*:*:x64:'),
  ]) {
    await assert.rejects(
      verifyRegistrationCpes([alias], async () => ({ results: [{ cpeName: wrong }] })),
      /not an active NVD/,
    );
  }
});

test('ambiguous vendor corrections require explicit dictionary selection', async () => {
  await assert.rejects(
    verifyRegistrationCpes([alias], async () => ({
      results: [{ cpeName: cpe }, { cpeName: cpe.replace(':example:', ':another_vendor:') }],
    })),
    /not an active NVD/,
  );
});

test('verified inventory rows retain ownership and IDs while saving canonical CPE metadata', async () => {
  const original = {
    ...row('keep-id'),
    vendor: 'example_alias',
    cpes: [alias],
    targetHw: 'obsolete',
    version: 'obsolete',
    purls: ['pkg:npm/widget@1.0'],
  };
  const [verified] = await verifyRegistrationAssets([original], async () => ({
    results: [{ cpeName: cpe }],
  }));
  assert.deepEqual(verified.cpes, [cpe]);
  assert.equal(verified.vendor, 'example');
  assert.equal(verified.version, '1.0');
  assert.equal(verified.targetHw, 'x64');
  assert.equal(verified.id, original.id);
  assert.equal(verified.createdAt, original.createdAt);
  assert.equal(verified.ownerGroup, original.ownerGroup);
  assert.deepEqual(verified.purls, original.purls);
  assert.deepEqual(original.cpes, [alias]);
});

test('batch verification reuses lookups and exposes canonical duplicates before import', async () => {
  let calls = 0;
  const items = await verifyRegistrationAssets(
    [
      { ...row('one'), vendor: 'example_alias', cpes: [alias] },
      { ...row('two'), vendor: 'example_alias', cpes: [alias] },
    ],
    async () => {
      calls++;
      return { results: [{ cpeName: cpe }] };
    },
  );
  assert.equal(calls, 1);
  assert.equal(watchlistDuplicateErrors(items, []).length, 1);
});

test('duplicate identities ignore repeated CPEs and tags without losing PURL case', () => {
  const first = row('one');
  const duplicate = { ...row('two'), cpes: [cpe, cpe.toUpperCase()] };
  assert.equal(watchlistIdentity(first), watchlistIdentity(duplicate));
  assert.equal(watchlistDuplicateErrors([duplicate], [first]).length, 1);
  assert.notEqual(
    watchlistIdentity({ ...first, purls: ['pkg:generic/Widget@1.0'] }),
    watchlistIdentity({ ...first, purls: ['pkg:generic/widget@1.0'] }),
  );
});

test('duplicate checks compare the final edited inventory and reject repeated IDs', () => {
  const first = row('one');
  const second = row('two', 'other');
  assert.deepEqual(watchlistDuplicateErrors([first], [first, second]), []);
  assert.equal(
    watchlistDuplicateErrors([{ ...first, product: second.product, cpes: second.cpes }], [first, second])
      .length,
    1,
  );
  assert.equal(watchlistDuplicateErrors([first, { ...second, id: first.id }], []).length, 1);
  assert.deepEqual(
    watchlistDuplicateErrors(
      [
        { ...second, id: first.id },
        { ...first, id: second.id },
      ],
      [first, second],
    ),
    [],
  );
});

test('wildcard scope cannot hide vendor/product patterns or escaped literal versions', () => {
  assert.equal(productWildcardCpe(cpe.replace(':example:', ':example*:')), null);
  assert.equal(productWildcardCpe(cpe.replace(':widget:', ':wid?et:')), null);
  assert.equal(isProductWildcard(String.raw`cpe:2.3:a:example:widget:\*:*:*:*:*:*:*:*`), false);
  assert.ok(productWildcardCpe(String.raw`cpe:2.3:a:example:widget\*:1.0:*:*:*:*:*:*:*`));
});

const database = process.env.TEST_DATABASE_URL;
test(
  'all inventory command paths reject duplicates atomically, including concurrent writes',
  { skip: !database },
  async (t) => {
    const base = createPool(database!);
    const schema = 'registration_audit_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    });
    const write = (action: string, data: unknown, id?: string) =>
      transaction(pool, (db) => applyCommand(db, config, { action, data, id, actor: 'registration-audit' }));
    const reset = async () => {
      await pool.query("DELETE FROM records WHERE kind='watchlist'");
      await pool.query('DELETE FROM correlation_managed_assets');
    };
    try {
      await migrate(pool);
      await t.test('single saves reject a duplicate even with another tag', async () => {
        await reset();
        await write('asset.save', row('one'));
        await assert.rejects(write('asset.save', row('two')), /already monitored/);
        assert.equal((await list(pool, 'watchlist')).length, 1);
      });
      await t.test(
        'bulk upserts remain idempotent but reject new-tag duplicates before writing',
        async () => {
          await reset();
          assert.equal((await write('asset.import', [row('one'), row('one')])).imported, 1);
          const first = (await list<WatchListItem>(pool, 'watchlist'))[0];
          await write('asset.import', [row('one')]);
          assert.equal((await list<WatchListItem>(pool, 'watchlist'))[0].id, first.id);
          const result = await write('asset.import', [row('unique', 'new'), row('two')]);
          assert.equal(result.success, false);
          assert.equal(result.imported, 0);
          assert.equal((await list(pool, 'watchlist')).length, 1);
        },
      );
      await t.test('edited and new rows are checked together with no partial update', async () => {
        await reset();
        const one = { ...row(randomUUID()), assetTag: 'ONE' };
        const two = { ...row(randomUUID(), 'other'), assetTag: 'TWO' };
        await write('watchlist.import', [one, two]);
        const result = await write('watchlist.import', [
          { ...one, ownerGroup: 'changed' },
          { ...two, product: one.product, cpes: one.cpes },
        ]);
        assert.equal(result.success, false);
        assert.equal((await get<WatchListItem>(pool, 'watchlist', one.id))?.ownerGroup, 'SOC');
      });
      await t.test('concurrent single-save and bulk-import attempts cannot create two copies', async () => {
        await reset();
        const results = await Promise.allSettled([
          write('asset.save', row('one')),
          write('asset.import', [row('two')]),
        ]);
        const successes = results.filter((result) => result.status === 'fulfilled' && result.value.success);
        assert.equal(successes.length, 1);
        assert.equal((await list(pool, 'watchlist')).length, 1);
      });
      await t.test('all import paths reject embedded identity wildcards', async () => {
        await reset();
        const unsafe = { ...row(randomUUID()), cpes: [cpe.replace(':widget:', ':widget*:')] };
        await assert.rejects(write('asset.save', unsafe), /specific part/);
        await assert.rejects(write('asset.import', [unsafe]), /specific part/);
        assert.equal((await write('watchlist.import', [unsafe])).success, false);
        assert.equal((await list(pool, 'watchlist')).length, 0);
      });
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
