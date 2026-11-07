import type pg from 'pg';
import type { CollectionKind, CollectionPage } from '../shared/state.ts';
import { isCollectionKind } from '../shared/state.ts';

/**
 * Query shape shared by `/api/collections/:kind`. All filtering and ordering is
 * done in PostgreSQL so a large installation never has to ship an entire
 * collection to the browser just to render one page.
 */
export interface CollectionQuery {
  limit: number;
  offset: number;
  search?: string;
  sort?: string;
  order?: 'asc' | 'desc';
  filters?: Record<string, string | string[] | number | boolean | undefined>;
}

// "Latest" recency for findings: the most recent of a CVE's published and
// modified dates. COALESCE to a distant past timestamp so a missing/unparseable
// date on one side cannot drag the whole GREATEST result to NULL (PostgreSQL's
// greatest() returns NULL when any argument is NULL), which would incorrectly
// sink an otherwise recent finding to the bottom of the page.
const FINDINGS_RECENT_ACTIVITY =
  "GREATEST(COALESCE(safe_timestamptz(data->'cve'->>'publishedDate'), '-infinity'::timestamptz), COALESCE(safe_timestamptz(data->'cve'->>'modifiedDate'), '-infinity'::timestamptz))";

const SORTS: Partial<Record<CollectionKind, Record<string, string>>> = {
  cveData: {
    score: "safe_numeric(data->'cvss'->>'score')",
    published: "safe_timestamptz(data->>'publishedDate')",
    modified: "safe_timestamptz(data->>'modifiedDate')",
    updated: 'updated_at',
  },
  findings: {
    latest: FINDINGS_RECENT_ACTIVITY,
    published: "safe_timestamptz(data->'cve'->>'publishedDate')",
    modified: "safe_timestamptz(data->'cve'->>'modifiedDate')",
    updated: 'updated_at',
  },
  advisories: { created: "safe_timestamptz(data->>'createdDate')", updated: 'updated_at' },
  alertedCves: { alerted: "safe_timestamptz(data->>'lastAlertedAt')" },
  emailLogs: { sent: "safe_timestamptz(data->>'sentAt')" },
  webhookLogs: { sent: "safe_timestamptz(data->>'sentAt')" },
  executions: { started: "safe_timestamptz(data->>'startTime')" },
  intelligenceArticles: { published: "safe_timestamptz(data->>'publishedDate')" },
  intelligenceMatches: { updated: 'updated_at' },
  zeroDayDigests: { created: "safe_timestamptz(data->>'createdAt')", updated: 'updated_at' },
};

const DEFAULT_ORDER: Partial<Record<CollectionKind, string>> = {
  cveData: "safe_timestamptz(data->>'modifiedDate') DESC NULLS LAST, id DESC",
  findings: "safe_timestamptz(data->'cve'->>'modifiedDate') DESC NULLS LAST, id DESC",
  advisories: "safe_timestamptz(data->>'createdDate') DESC NULLS LAST, id DESC",
  alertedCves: "safe_timestamptz(data->>'lastAlertedAt') DESC NULLS LAST, id DESC",
  emailLogs: "safe_timestamptz(data->>'sentAt') DESC NULLS LAST, id DESC",
  webhookLogs: "safe_timestamptz(data->>'sentAt') DESC NULLS LAST, id DESC",
  executions: "safe_timestamptz(data->>'startTime') DESC NULLS LAST, id DESC",
  intelligenceArticles: "safe_timestamptz(data->>'publishedDate') DESC NULLS LAST, id DESC",
  zeroDayDigests: "safe_timestamptz(data->>'createdAt') DESC NULLS LAST, id DESC",
};

const orderClause = (kind: CollectionKind, query: CollectionQuery): string => {
  if (kind === 'auditLogs') return 'seq DESC';
  const sorts = SORTS[kind];
  const sort = query.sort && sorts && Object.hasOwn(sorts, query.sort) ? sorts[query.sort] : undefined;
  // DESC defaults to NULLS FIRST; a malformed legacy value should fall to the
  // end of the page instead of outranking every valid timestamp.
  if (sort) return `${sort} ${query.order === 'asc' ? 'ASC' : 'DESC'} NULLS LAST, id DESC`;
  return DEFAULT_ORDER[kind] || 'updated_at DESC, id DESC';
};

const likeValue = (search?: string) =>
  search && search.trim()
    ? `%${search.trim().toLowerCase().replace(/[!%_]/g, (character) => `!${character}`)}%`
    : undefined;

// Match the public snapshot's redaction in both results and search predicates.
// Searching the stored JSON directly would expose hidden values via match counts.
function publicRecordData(kind: CollectionKind): string {
  if (kind === 'feeds') return "(data - 'authSecretKey')";
  if (kind === 'webhooks')
    return "((data - 'url' - 'secretToken') || jsonb_build_object('url', '[configured on server]', 'secretToken', ''))";
  return 'data';
}

function recordConditions(kind: CollectionKind, query: CollectionQuery) {
  const params: unknown[] = [kind];
  const clauses = ['kind=$1'];
  const param = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  const like = likeValue(query.search);
  const filters = query.filters ?? {};
  const isAll = (value: unknown) => value === undefined || value === '' || value === 'ALL';

  switch (kind) {
    case 'cveData': {
      if (like)
        clauses.push(
          `(lower(data->>'cveId') LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'title','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'description','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE((data->'sourceFeeds')::text,'')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE((data->'cpeMatches')::text,'')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE((data->'purls')::text,'')) LIKE ${param(like)} ESCAPE '!')`,
        );
      if (filters.kev === true || filters.kev === 'true' || filters.kev === 'KEV_ONLY')
        clauses.push(`data->'cisaKev'->>'isKev' = 'true'`);
      if (typeof filters.epssMin === 'number' && Number.isFinite(filters.epssMin))
        clauses.push(`safe_numeric(data->'epss'->>'score') >= ${param(filters.epssMin)}`);
      if (filters.dateFilter === 'IN_SCOPE') {
        const hours = typeof filters.scopeHours === 'number' ? filters.scopeHours : 24;
        const hoursParam = param(hours);
        clauses.push(
          `(safe_timestamptz(data->>'publishedDate') >= now() - (${hoursParam} * interval '1 hour')
            OR safe_timestamptz(data->>'modifiedDate') >= now() - (${hoursParam} * interval '1 hour'))`,
        );
      } else if (filters.dateFilter === 'RECENT_MODIFIED') {
        clauses.push(`safe_timestamptz(data->>'modifiedDate') >= now() - interval '7 days'`);
      } else if (filters.dateFilter === 'RECENT_PUBLISHED') {
        clauses.push(`safe_timestamptz(data->>'publishedDate') >= now() - interval '7 days'`);
      }
      break;
    }
    case 'findings': {
      if (like)
        clauses.push(
          `(lower(data->>'cveId') LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'matchedAssetName','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->'cve'->>'title','')) LIKE ${param(like)} ESCAPE '!')`,
        );
      if (!isAll(filters.severity))
        clauses.push(`data->'cve'->'cvss'->>'severity' = ${param(String(filters.severity))}`);
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      if (!isAll(filters.notificationStatus))
        clauses.push(`data->>'notificationStatus' = ${param(String(filters.notificationStatus))}`);
      if (!isAll(filters.executionId))
        // Findings written without an execution (operator-imported, legacy rows)
        // carry no executionId and are correctly excluded from a run-scoped
        // page. ISO-8601 execution ids sort lexicographically, so equality is
        // the exact predicate; no range comparison is involved.
        clauses.push(`data->>'executionId' = ${param(String(filters.executionId))}`);
      break;
    }
    case 'advisories': {
      if (like)
        clauses.push(
          `(lower(data->>'id') LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'title','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'executiveSummary','')) LIKE ${param(like)} ESCAPE '!')`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'deliveryStatus' = ${param(String(filters.status))}`);
      break;
    }
    case 'alertedCves': {
      if (like)
        clauses.push(
          `(lower(data->>'cveId') LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'advisoryId','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE((data->'recipientEmails')::text,'')) LIKE ${param(like)} ESCAPE '!')`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      break;
    }
    case 'emailLogs': {
      if (like)
        clauses.push(
          `(lower(data->>'recipientEmail') LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'subject','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'advisoryId','')) LIKE ${param(like)} ESCAPE '!')`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      if (!isAll(filters.advisoryId))
        clauses.push(`data->>'advisoryId' = ${param(String(filters.advisoryId))}`);
      if (!isAll(filters.provider))
        clauses.push(`data->>'provider' = ${param(String(filters.provider))}`);
      if (!isAll(filters.actionStatus)) {
        if (filters.actionStatus === 'PENDING')
          // Delivered finding emails awaiting operator follow-up. Records
          // written before the field existed have no actionStatus and are
          // PENDING by definition, exactly like the Action Center rendering.
          // Synthetic digest/news deliveries never enter this queue.
          clauses.push(
            `(data->>'status' IN ('ACCEPTED','DELIVERED')
              AND COALESCE(data->>'actionStatus','PENDING') = 'PENDING'
              AND COALESCE(data->>'advisoryId','') NOT IN ('TEST')
              AND COALESCE(data->>'advisoryId','') NOT LIKE 'NEWS:%'
              AND COALESCE(data->>'advisoryId','') NOT LIKE 'ZERODAY:%'
              AND COALESCE(data->>'advisoryId','') NOT LIKE 'UNVERIFIABLE:%'
              AND strpos(COALESCE(data->>'advisoryId',''), 'DAILY_') = 0
              AND strpos(COALESCE(data->>'advisoryId',''), 'DAILY-') = 0)`,
          );
        else if (filters.actionStatus === 'ACTIONED')
          clauses.push(`COALESCE(data->>'actionStatus','') = 'ACTIONED'`);
      }
      if (filters.dateRange && filters.dateRange !== 'custom') {
        // "Today" must cover the whole local calendar day, not the trailing
        // 24 hours; the other ranges are trailing windows.
        if (filters.dateRange === 'today') {
          clauses.push(`safe_timestamptz(data->>'sentAt') >= date_trunc('day', now())`);
        } else {
          const days =
            filters.dateRange === 'week'
              ? 7
              : filters.dateRange === 'month'
              ? 30
              : filters.dateRange === 'quarter'
              ? 90
              : 365;
          const daysParam = param(days);
          clauses.push(
            `safe_timestamptz(data->>'sentAt') >= now() - (${daysParam} * interval '1 day')`,
          );
        }
      }
      break;
    }
    case 'webhookLogs': {
      if (like)
        clauses.push(
          `(lower(COALESCE(data->>'endpointName','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'advisoryId','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'cveId','')) LIKE ${param(like)} ESCAPE '!')`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      break;
    }
    case 'executions': {
      if (like)
        clauses.push(
          `(lower(data->>'id') LIKE ${param(like)} ESCAPE '!' OR lower(COALESCE(data->>'status','')) LIKE ${param(like)} ESCAPE '!')`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      break;
    }
    case 'intelligenceArticles': {
      if (like)
        clauses.push(
          `(lower(COALESCE(data->>'title','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'summary','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE((data->'cveIds')::text,'')) LIKE ${param(like)} ESCAPE '!')`,
        );
      break;
    }
    case 'intelligenceMatches': {
      if (like)
        clauses.push(
          `(lower(COALESCE(data->>'assetName','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'evidence','')) LIKE ${param(like)} ESCAPE '!'
            OR lower(COALESCE(data->>'cveId','')) LIKE ${param(like)} ESCAPE '!')`,
        );
      const articleIds = filters.articleIds;
      if (Array.isArray(articleIds) && articleIds.length)
        clauses.push(`data->'articleIds' ?| ${param(articleIds)}::text[]`);
      break;
    }
    default: {
      // Small configuration collections still get a useful generic search.
      if (like) clauses.push(`lower((${publicRecordData(kind)})::text) LIKE ${param(like)} ESCAPE '!'`);
    }
  }
  return { clauses, params };
}

function auditConditions(query: CollectionQuery) {
  const params: unknown[] = [];
  const clauses: string[] = [];
  const param = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  const like = likeValue(query.search);
  const filters = query.filters ?? {};
  if (like)
    clauses.push(
      `(lower(data->>'event') LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->>'details','')) LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->>'actor','')) LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->>'ipAddress','')) LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->>'id','')) LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->'context'->>'action','')) LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->'context'->>'resourceType','')) LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->'context'->>'resourceId','')) LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->'context'->>'requestId','')) LIKE ${param(like)} ESCAPE '!'
        OR lower(COALESCE(data->'context'->>'outcome','')) LIKE ${param(like)} ESCAPE '!')`,
    );
  if (filters.category && filters.category !== 'ALL')
    clauses.push(`data->>'category' = ${param(String(filters.category))}`);
  if (filters.level && filters.level !== 'ALL')
    clauses.push(`data->>'level' = ${param(String(filters.level))}`);
  return { clauses, params };
}

export async function queryCollection<T = unknown>(
  pool: pg.Pool,
  kind: string,
  query: CollectionQuery,
): Promise<CollectionPage<T>> {
  if (!isCollectionKind(kind))
    throw Object.assign(new Error('Unknown collection'), { status: 404 });
  const limit = Math.max(1, Math.min(1000, Math.floor(query.limit) || 50));
  const offset = Math.max(0, Math.floor(query.offset) || 0);

  if (kind === 'auditLogs') {
    const { clauses, params } = auditConditions(query);
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const count = (
      await pool.query<{ count: number }>(`SELECT count(*)::int AS count FROM audit ${where}`, params)
    ).rows[0].count;
    const items = (
      await pool.query(
        `SELECT data FROM audit ${where} ORDER BY seq DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limit, offset],
      )
    ).rows.map((row) => row.data as T);
    return { items, total: Number(count), limit, offset };
  }

  const { clauses, params } = recordConditions(kind as CollectionKind, query);
  const where = `WHERE ${clauses.join(' AND ')}`;
  const count = (
    await pool.query<{ count: number }>(`SELECT count(*)::int AS count FROM records ${where}`, params)
  ).rows[0].count;
  const items = (
    await pool.query(
      `SELECT ${publicRecordData(kind)} AS data FROM records ${where} ORDER BY ${orderClause(kind as CollectionKind, query)} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset],
    )
  ).rows.map((row) => row.data as T);
  return { items, total: Number(count), limit, offset };
}
