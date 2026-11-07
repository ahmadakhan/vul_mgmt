import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createPool, migrate, transaction, put, list, get, remove } from '../server/db.ts';
import { reconcileRecommendedFeeds } from '../server/feedBootstrap.ts';
import { RECOMMENDED_FEEDS } from '../server/recommendedFeeds.ts';
import type { ThreatFeed } from '../src/types/index.ts';

test('feed bootstrap is opt-in and URL repair preserves operator intent without stale validators', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const control = createPool(process.env.TEST_DATABASE_URL!);
  const schema = `feed_bootstrap_${randomBytes(8).toString('hex')}`;
  await control.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(process.env.TEST_DATABASE_URL!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);
  try {
    await migrate(pool);
    await transaction(pool, (db) => reconcileRecommendedFeeds(db));
    assert.equal((await list(pool, 'feeds')).length, 0);
    await transaction(pool, (db) => reconcileRecommendedFeeds(db, true));
    assert.equal((await list(pool, 'feeds')).length, RECOMMENDED_FEEDS.length);
    const twitter = await get<ThreatFeed>(pool, 'feeds', 'feed-twitter-security');
    assert.ok(twitter);
    assert.equal(twitter.enabled, false);
    assert.equal(twitter.healthStatus, 'DOWN');
    assert.match(twitter.errorLog!, /rejects automated requests/);
    await put(pool, 'feeds', twitter.id, {
      ...twitter, enabled: true, errorLog: 'Destination hostname is not in EGRESS_ALLOWED_HOSTS',
    });
    await transaction(pool, (db) => reconcileRecommendedFeeds(db, true));
    assert.equal((await list(pool, 'feeds')).length, RECOMMENDED_FEEDS.length);
    const repairedTwitter = await get<ThreatFeed>(pool, 'feeds', twitter.id);
    assert.equal(repairedTwitter?.enabled, false);
    assert.equal(repairedTwitter?.errorLog, twitter.errorLog);
    const catalog = RECOMMENDED_FEEDS[0];
    await put(pool, 'feeds', catalog.id, { ...catalog, enabled: false, authSecretKey: 'preserved-ciphertext',
      url: 'https://legacy.example/source', etag: 'obsolete-validator', healthStatus: 'DOWN',
      consecutiveFailures: 5, circuitOpenUntil: '2030-01-01T00:00:00Z' });
    await transaction(pool, (db) => reconcileRecommendedFeeds(db, false));
    const repaired = await get<ThreatFeed>(pool, 'feeds', catalog.id);
    assert.equal(repaired?.url, catalog.url);
    assert.equal(repaired?.enabled, false);
    assert.equal(repaired?.authSecretKey, 'preserved-ciphertext');
    assert.equal(repaired?.etag, undefined);
    assert.equal(repaired?.ssrfValidated, false);
    assert.equal(repaired?.healthStatus, 'UNTESTED');
    assert.equal(repaired?.circuitOpenUntil, null);

    const darkReading = RECOMMENDED_FEEDS.find((feed) => feed.id === 'feed-darkreading');
    assert.ok(darkReading);
    await put(pool, 'feeds', darkReading.id, { ...darkReading, enabled: false });
    await put(pool, 'feeds', 'feed-darkreading-full', {
      ...darkReading,
      id: 'feed-darkreading-full',
      enabled: true,
    });
    await transaction(pool, (db) => reconcileRecommendedFeeds(db, false));
    assert.equal(await get<ThreatFeed>(pool, 'feeds', 'feed-darkreading-full'), undefined);
    assert.equal((await get<ThreatFeed>(pool, 'feeds', darkReading.id))?.enabled, true);

    await remove(pool, 'feeds', darkReading.id);
    await put(pool, 'feeds', 'operator-darkreading', { ...darkReading, id: 'operator-darkreading', enabled: false });
    await transaction(pool, (db) => reconcileRecommendedFeeds(db, true));
    assert.equal(await get<ThreatFeed>(pool, 'feeds', darkReading.id), undefined);
    assert.equal((await get<ThreatFeed>(pool, 'feeds', 'operator-darkreading'))?.enabled, false);
    assert.equal((await list(pool, 'feeds')).length, RECOMMENDED_FEEDS.length);
  } finally {
    await pool.end();
    await control.query(`DROP SCHEMA ${schema} CASCADE`);
    await control.end();
  }
});