import type { ThreatFeed } from '../src/types/index.ts';

export function feedSourceKey(url: string): string {
  const endpoint = new URL(url);
  endpoint.hash = '';
  endpoint.searchParams.sort();
  return endpoint.href;
}

export function findDuplicateFeedSource(
  feed: Pick<ThreatFeed, 'id' | 'url'>,
  feeds: readonly Pick<ThreatFeed, 'id' | 'url'>[],
): Pick<ThreatFeed, 'id' | 'url'> | undefined {
  const sourceKey = feedSourceKey(feed.url);
  return feeds.find((candidate) => candidate.id !== feed.id && feedSourceKey(candidate.url) === sourceKey);
}
