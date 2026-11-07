import type { PoolClient } from './db.ts';
import { get, list, put, remove } from './db.ts';
import type { ThreatFeed } from '../src/types/index.ts';
import { RECOMMENDED_FEEDS, RECOMMENDED_FEED_URLS } from './recommendedFeeds.ts';
import { findDuplicateFeedSource } from './feedIdentity.ts';

const RETIRED_DUPLICATE_FEEDS = [{ duplicateId: 'feed-darkreading-full', canonicalId: 'feed-darkreading' }];

export async function reconcileRecommendedFeeds(db: PoolClient, bootstrap = false): Promise<void> {
  const existing = await list<ThreatFeed>(db, 'feeds');
  const ids = new Set(existing.map((feed) => feed.id));
  if (bootstrap)
    for (const feed of RECOMMENDED_FEEDS) {
      if (ids.has(feed.id) || findDuplicateFeedSource(feed, existing)) continue;
      await put(db, 'feeds', feed.id, {
        ...feed,
        healthStatus: 'healthStatus' in feed ? feed.healthStatus : 'UNTESTED',
        lastSync: null,
        latencyMs: 0,
        itemCountLastRun: 0,
        ssrfValidated: false,
      });
    }
  for (const feed of existing) {
    const url = RECOMMENDED_FEED_URLS.get(feed.id);
    if (!url || !feed.url || feed.url === url) continue;
    await put(db, 'feeds', feed.id, {
      ...feed,
      url,
      ssrfValidated: false,
      etag: undefined,
      lastSync: null,
      healthStatus: 'UNTESTED',
      errorLog: undefined,
      consecutiveFailures: 0,
      circuitOpenUntil: null,
    });
  }
  for (const source of RECOMMENDED_FEEDS) {
    if (source.enabled || !('healthStatus' in source) || source.healthStatus !== 'DOWN') continue;
    const feed = await get<ThreatFeed>(db, 'feeds', source.id);
    if (!feed?.vendorSeed || feed.url !== source.url) continue;
    await put(db, 'feeds', feed.id, {
      ...feed,
      enabled: false,
      healthStatus: source.healthStatus,
      errorLog: source.errorLog,
    });
  }
  for (const { duplicateId, canonicalId } of RETIRED_DUPLICATE_FEEDS) {
    const [duplicate, canonical] = await Promise.all([
      get<ThreatFeed>(db, 'feeds', duplicateId),
      get<ThreatFeed>(db, 'feeds', canonicalId),
    ]);
    if (
      !duplicate?.vendorSeed ||
      !canonical?.vendorSeed ||
      duplicate.url !== 'https://www.darkreading.com/rss.xml' ||
      canonical.url !== duplicate.url
    )
      continue;
    if (duplicate.enabled && !canonical.enabled) {
      await put(db, 'feeds', canonicalId, { ...canonical, enabled: true });
    }
    await remove(db, 'feeds', duplicateId);
  }
}
