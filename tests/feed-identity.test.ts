import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findDuplicateFeedSource, feedSourceKey } from '../server/feedIdentity.ts';
import { RECOMMENDED_FEEDS } from '../server/recommendedFeeds.ts';

test('feed source identity ignores query ordering and fragments', () => {
  assert.equal(
    feedSourceKey('https://example.com/feed?b=2&a=1#latest'),
    feedSourceKey('https://example.com/feed?a=1&b=2'),
  );
});

test('duplicate feed lookup matches canonical endpoints but not the same record', () => {
  const existing = [{ id: 'existing', url: 'https://example.com/feed?b=2&a=1' }];
  assert.equal(
    findDuplicateFeedSource({ id: 'new', url: 'https://example.com/feed?a=1&b=2#latest' }, existing)?.id,
    'existing',
  );
  assert.equal(findDuplicateFeedSource({ id: 'existing', url: existing[0].url }, existing), undefined);
});

test('recommended feeds contain no duplicate endpoints and avoid one-request-per-minute caps', () => {
  const sources = RECOMMENDED_FEEDS.map((feed) => feedSourceKey(feed.url));
  assert.equal(new Set(sources).size, sources.length);
  assert.ok(RECOMMENDED_FEEDS.every((feed) =>
    feed.id === 'feed-github-advisories' ? feed.rateLimitPerMin === 1 : feed.rateLimitPerMin >= 3,
  ));
});

test('recommended public feeds are enabled while credentialed and known-unavailable feeds stay disabled', () => {
  assert.ok(RECOMMENDED_FEEDS.filter((feed) => feed.authType === 'NONE' && feed.vendorSeed && !['feed-twitter-security', 'feed-exploitdb'].includes(feed.id)).every((feed) => feed.enabled));
  assert.ok(RECOMMENDED_FEEDS.filter((feed) => feed.authType !== 'NONE').every((feed) => !feed.enabled));
  assert.ok(RECOMMENDED_FEEDS.filter((feed) => ['feed-twitter-security', 'feed-exploitdb'].includes(feed.id)).every((feed) => !feed.enabled));
});

test('recommended catalog includes the official CISA KEV and FIRST EPSS adapters', () => {
  assert.deepEqual(
    RECOMMENDED_FEEDS.filter((feed) => ['feed-cisa-kev', 'feed-epss'].includes(feed.id)).map((feed) => [
      feed.id,
      feed.type,
      feed.url,
      feed.enabled,
    ]),
    [
      ['feed-cisa-kev', 'CISA_KEV', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', true],
      ['feed-epss', 'EPSS_API', 'https://api.first.org/data/v1/epss', true],
    ],
  );
});
