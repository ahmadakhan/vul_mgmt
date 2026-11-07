/** Internal state, committed in the same transaction as the imported records. */
import type { NormalizedCVE } from '../src/types/index.ts';
export interface IngestionState {
  cursor?: string;
  hasMore?: boolean;
  revisions?: Record<string, string>;
  indexEtag?: string;
  epssScope?: string[];
  epssExpiresAt?: string;
  /** True when a multi-run catch-up is in progress after extended downtime. */
  catch_up?: boolean;
  /** Next time to start a catch-up run, used by the scheduler to prioritize catch-up. */
  next_catchup_at?: string;
}
export interface FeedCursor extends IngestionState { fingerprint: string }
const HOUR = 3600000;
export const SYNC_OVERLAP_MS = 10 * 60000;
/** Maximum incremental window for sources with per-run record caps (e.g. OpenCVE's 500-CVE limit). */
export const OPENCVE_MAX_WINDOW_HOURS = 3;
/** Bootstrap at most one day; resume older checkpoints in bounded daily slices. */
export function ingestionWindow(scopeHours: number, state: IngestionState = {}, now = Date.now(), maxWindowHours = 24) {
  const cursor = state.cursor ? Date.parse(state.cursor) : NaN;
  const valid = Number.isFinite(cursor) && cursor <= now;
  const start = valid ? cursor - SYNC_OVERLAP_MS : now - Math.min(maxWindowHours, Math.max(0, scopeHours)) * HOUR;
  const end = valid ? Math.min(now, cursor + maxWindowHours * HOUR - SYNC_OVERLAP_MS) : now;
  return { start: new Date(start), end: new Date(end), incremental: valid, hasMore: end < now - 60000 };
}
export function recentRevisions(revisions: Record<string, string>, since: Date) {
  const cutoff = since.getTime() - 24 * HOUR;
  return Object.fromEntries(Object.entries(revisions).filter(([, value]) => {
    const parsed = Date.parse(value);
    // An unparseable timestamp is kept, not dropped: the revision cache is
    // consulted to decide "have we already seen this revision?", so dropping a
    // garbage entry would silently re-ingest the record (and, worse, let a
    // corrupt cache entry be pruned as "old" when its true age is unknown).
    // Keeping it is the conservative direction — at worst we keep one extra
    // cache row until the next successful ingest overwrites it.
    return Number.isNaN(parsed) || parsed >= cutoff;
  }));
}
