import type { QueryConfig } from 'pg';

/**
 * node-postgres honours a per-query `query_timeout` (client.js), but its public
 * `QueryConfig` type omits the field. Without it a probe against a dead socket
 * waits forever instead of detecting the outage, so the timeout is attached
 * here rather than being dropped by the type.
 */
export function timedQuery(
  text: string,
  values: unknown[] = [],
  timeout = 4000,
): QueryConfig & { query_timeout: number } {
  return { text, values, query_timeout: timeout };
}
