import { z } from 'zod';
import type { Db } from './db';
import { EVENT_CATEGORIES, type OperationalEvent } from '../src/types/index.ts';

const sensitive = /password|secret|token|authorization|cookie|api.?key|payload|html|body|credential|privatekey|jwt|authtoken/i;
const MAX_ERROR_TEXT = 4000;
/**
 * Structured description of a thrown value for an operational event.
 *
 * The generic HTTP handler used to record only `errorType`, which left an
 * operator with "Error Type: error" and no way to tell a missing table from a
 * parsing bug. This keeps the message, error/DB code and driver detail/hint in
 * the event context, and enough of the stack to locate the throw site. Values
 * pass through `redactEventContext` when written, so credentials in a context
 * key are still stripped; the message and stack are bounded here so one
 * pathological error cannot consume the 32 kB context budget.
 */
export function describeError(error: unknown, depth = 0): Record<string, unknown> {
  if (error === null || error === undefined) return {};
  if (typeof error !== 'object') return { error: String(error).slice(0, MAX_ERROR_TEXT) };

  const value = error as Record<string, unknown>;
  const message =
    typeof value.message === 'string' && value.message.trim() !== '' ? value.message : String(error);
  const details: Record<string, unknown> = { error: message.slice(0, MAX_ERROR_TEXT) };

  if (typeof value.name === 'string' && value.name) details.errorType = value.name;
  if (typeof value.code === 'string' || typeof value.code === 'number')
    details.errorCode = String(value.code);
  for (const [source, target] of [
    ['detail', 'errorDetail'],
    ['hint', 'errorHint'],
    ['constraint', 'errorConstraint'],
    ['table', 'errorTable'],
    ['column', 'errorColumn'],
    ['schema', 'errorSchema'],
    ['severity', 'errorSeverity'],
  ] as const) {
    if (typeof value[source] === 'string' && value[source]) details[target] = value[source];
  }
  if (typeof value.stack === 'string' && value.stack) details.stack = value.stack.slice(0, MAX_ERROR_TEXT);

  // Node wraps low-level socket/DNS failures in `cause`; surface one or two
  // levels because "fetch failed" alone is not actionable.
  if (depth < 2 && value.cause !== undefined && value.cause !== error)
    details.cause = describeError(value.cause, depth + 1);
  if (depth < 2 && Array.isArray(value.errors))
    details.errors = value.errors.slice(0, 10).map((item) => describeError(item, depth + 1));
  return details;
}

/**
 * Short, human-readable failure label persisted as the event *message*.
 *
 * The message column is full-text indexed and rendered in the UI, so it must
 * stay a stable, low-cardinality summary. The full error text lands in the
 * event *context* instead: embedding it in the message gave every 500 its own
 * message (one per user-supplied id or query), which defeated the tsvector
 * index and made the operations log unscannable.
 */
export function describeFailureSummary(error: unknown): string {
  return error instanceof z.ZodError
    ? 'Validation failed'
    : error instanceof Error && error.name
      ? error.name
      : 'Request failed';
}

/**
 * Context persisted for an unhandled request failure. Kept separate from the
 * Express handler so the shape is unit-testable and every 500 carries the same
 * fields: error detail, reference, route, authenticated actor and caller IP.
 */
export function describeRequestFailure(
  error: unknown,
  request: {
    method?: string;
    path?: string;
    route?: { path?: string };
    query?: unknown;
    ip?: string;
    operator?: { username?: string; role?: string };
  },
  reference: string,
): Record<string, unknown> {
  return {
    ...describeError(error),
    reference,
    httpStatus: 500,
    method: request.method,
    path: request.path,
    ...(request.route?.path ? { route: request.route.path } : {}),
    query: request.query,
    ...(request.operator
      ? { actor: request.operator.username, role: request.operator.role }
      : {}),
    ip: request.ip,
  };
}

export function redactEventContext(value: unknown, depth = 0): unknown {
  if (depth > 5) return '[truncated]';
  if (typeof value === 'string') return value.slice(0, 2000);
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redactEventContext(item, depth + 1));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 50)
        .map(([key, item]) => [
          key,
          sensitive.test(key) ? '[redacted]' : redactEventContext(item, depth + 1),
        ]),
    );
  return undefined;
}
export async function writeEvent(
  db: Db,
  event: Omit<OperationalEvent, 'id' | 'timestamp' | 'context' | 'level'> & {
    level?: OperationalEvent['level'];
    context?: Record<string, unknown>;
  },
) {
  let context = redactEventContext(event.context || {});
  if (JSON.stringify(context).length > 32000) context = { truncated: true };
  await db.query(
    'INSERT INTO operational_events(category,level,code,message,run_id,context) VALUES($1,$2,$3,$4,$5,$6)',
    [
      event.category,
      event.level || 'INFO',
      event.code.slice(0, 100),
      event.message.slice(0, 1000),
      event.runId || null,
      JSON.stringify(context),
    ],
  );
}
const querySchema = z.object({
  // The operations scope excludes categories that have dedicated log views.
  scope: z.enum(['OPERATIONS']).optional(),
  category: z.enum(EVENT_CATEGORIES).optional(),
  level: z.enum(['INFO', 'WARNING', 'ERROR']).optional(),
  runId: z.uuid().optional(),
  q: z.string().trim().max(200).optional(),
  before: z
    .string()
    .regex(/^\d{1,19}$/)
    .refine(
      (value) => /^\d{1,19}$/.test(value) && BigInt(value) <= 9223372036854775807n,
      'Cursor is out of range',
    )
    .optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});
export async function readEvents(
  db: Db,
  input: unknown,
): Promise<{ events: OperationalEvent[]; nextCursor: string | null }> {
  const query = querySchema.parse(input);
  const clauses: string[] = [],
    values: unknown[] = [];
  const where = (sql: string, value: unknown) => {
    values.push(value);
    clauses.push(sql.replace('?', `$${values.length}`));
  };
  if (query.scope === 'OPERATIONS') clauses.push("category NOT IN ('ML', 'SYSTEM')");
  if (query.category) where('category=?', query.category);
  if (query.level) where('level=?', query.level);
  if (query.runId) where('run_id=?', query.runId);
  if (query.before) where('id < ?::bigint', query.before);
  if (query.q)
    where(
      "to_tsvector('simple',code || ' ' || message || ' ' || context::text) @@ plainto_tsquery('simple',?)",
      query.q,
    );
  values.push(query.limit + 1);
  const rows = (
    await db.query(
      // Telemetry columns are surfaced too: they distinguish a correlation
      // worker event from a pipeline event and carry the per-advisory timings
      // an operator needs to place an event on a timeline.
      `SELECT id::text,occurred_at,category,level,code,message,run_id,context,
              sequence,tracking_id::text AS tracking_id,event,
              ingestion_latency_ms,extraction_latency_ms,total_database_time_ms,
              count,attempt
         FROM operational_events ${clauses.length ? 'WHERE ' + clauses.join(' AND ') : ''}
        ORDER BY operational_events.id DESC LIMIT $${values.length}`,
      values,
    )
  ).rows;
  const hasMore = rows.length > query.limit;
  const selected = rows.slice(0, query.limit);
  return {
    events: selected.map((row) => ({
      id: row.id,
      timestamp: row.occurred_at.toISOString(),
      category: row.category,
      level: row.level,
      code: row.code,
      message: row.message,
      runId: row.run_id || undefined,
      context: row.context,
      // Correlation-worker metadata. Omitted rather than null so the client can
      // render a compact row for ordinary pipeline events.
      ...(row.tracking_id ? { trackingId: row.tracking_id } : {}),
      ...(row.event ? { event: row.event } : {}),
      ...(row.sequence !== null && row.sequence !== undefined ? { sequence: Number(row.sequence) } : {}),
      ...(row.ingestion_latency_ms !== null && row.ingestion_latency_ms !== undefined
        ? { ingestionLatencyMs: Number(row.ingestion_latency_ms) }
        : {}),
      ...(row.extraction_latency_ms !== null && row.extraction_latency_ms !== undefined
        ? { extractionLatencyMs: Number(row.extraction_latency_ms) }
        : {}),
      ...(row.total_database_time_ms !== null && row.total_database_time_ms !== undefined
        ? { totalDatabaseTimeMs: Number(row.total_database_time_ms) }
        : {}),
      ...(row.attempt !== null && row.attempt !== undefined ? { attempt: Number(row.attempt) } : {}),
    })),
    nextCursor: hasMore ? selected[selected.length - 1].id : null,
  };
}
