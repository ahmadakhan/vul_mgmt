import type pg from 'pg';
import type {
  ThreatAnalytics,
  TimelineRange,
  TimelineBucket,
  TimelinePoint,
  SeverityDistribution,
  ExploitStatusDistribution,
  VendorAnalytics,
  CveScoreBin,
} from '../src/types/index.ts';

const TIMELINE_BUCKETS: Record<TimelineRange, { bucket: TimelineBucket; days: number }> = {
  '7d': { bucket: 'day', days: 7 },
  '30d': { bucket: 'day', days: 30 },
  '90d': { bucket: 'week', days: 90 },
  '365d': { bucket: 'month', days: 365 },
  all: { bucket: 'month', days: 0 },
};

const PG_DATE_FORMAT: Record<TimelineBucket, string> = {
  day: 'YYYY-MM-DD',
  week: 'IYYY-WIW',
  month: 'YYYY-MM',
};

const SCORE_BINS: CveScoreBin[] = [
  { range: '0.0', count: 0 },
  { range: '0.1-3.9', count: 0 },
  { range: '4.0-6.9', count: 0 },
  { range: '7.0-8.9', count: 0 },
  { range: '9.0-10.0', count: 0 },
];

export function buildDateClause(range: TimelineRange): string {
  const { days } = TIMELINE_BUCKETS[range];
  if (days === 0) return '';
  return `safe_timestamptz(data->>'publishedDate') >= now() - interval '${days} days'`;
}

/** Bucket style for date_trunc/to_char. Exported for analytics tests only. */
export function dateStyle(bucket: TimelineBucket): string {
  return PG_DATE_FORMAT[bucket];
}

/** Number of days a timeline range covers ('all' is 0 = unbounded). */
export function computeBucketDays(range: TimelineRange): number {
  return TIMELINE_BUCKETS[range].days;
}

/** date_trunc granularity for a timeline range. */
export function computeTimelineBucket(range: TimelineRange): TimelineBucket {
  return TIMELINE_BUCKETS[range].bucket;
}

/**
 * Computes aggregated threat analytics from the CVE cache in PostgreSQL.
 * Groups CVEs by publish-date buckets and computes severity, exploit-status,
 * vendor, and CVSS-score distributions for the selected timeline range.
 */
export async function computeThreatAnalytics(
  pool: pg.Pool,
  range: TimelineRange = '30d',
  vendorLimit: number = 10,
): Promise<ThreatAnalytics> {
  const { bucket } = TIMELINE_BUCKETS[range];
  const fmt = PG_DATE_FORMAT[bucket];
  const dateClause = buildDateClause(range);

  const totalResult = await pool.query<{ total: number; kev: number }>(
    `SELECT count(*)::int AS total,
     count(*) FILTER (WHERE data->'cisaKev'->>'isKev' = 'true')::int AS kev
     FROM records WHERE kind = 'cveData' AND ${dateClause || 'true'}`,
  );

  const timelineResult = await pool.query<{
    label: string;
    cveCount: number;
    critical: number;
    high: number;
  }>(
    `SELECT to_char(date_trunc('${bucket}', safe_timestamptz(data->>'publishedDate')), '${fmt}') AS label,
     count(*)::int AS cveCount,
     count(*) FILTER (WHERE data->'cvss'->>'severity' = 'CRITICAL')::int AS critical,
     count(*) FILTER (WHERE data->'cvss'->>'severity' = 'HIGH')::int AS high
     FROM records WHERE kind = 'cveData' AND ${dateClause || 'true'}
     GROUP BY date_trunc('${bucket}', safe_timestamptz(data->>'publishedDate'))
     ORDER BY date_trunc('${bucket}', safe_timestamptz(data->>'publishedDate')) ASC`,
  );

  const severityResult = await pool.query<{ severity: string; count: number }>(
    `SELECT COALESCE(data->'cvss'->>'severity', 'UNKNOWN') AS severity, count(*)::int AS count
     FROM records WHERE kind = 'cveData' AND ${dateClause || 'true'}
     GROUP BY severity`,
  );

  const exploitResult = await pool.query<{ status: string; count: number }>(
    `SELECT data->>'exploitStatus' AS status, count(*)::int AS count
     FROM records WHERE kind = 'cveData' AND ${dateClause || 'true'}
     GROUP BY status`,
  );

  const vendorResult = await pool.query<{
    vendor: string;
    count: number;
    critical: number;
    high: number;
  }>(
    `SELECT vendor,
       count(*)::int AS count,
       count(*) FILTER (WHERE severity = 'CRITICAL')::int AS critical,
       count(*) FILTER (WHERE severity = 'HIGH')::int AS high
     FROM (
       -- CPE 2.3 layout: cpe:2.3:<part>:<vendor>:<product>:...
       -- Use the vendor field (4th component), not the product (5th), and
       -- collapse repeated CPEs so one CVE cannot inflate a vendor's count.
       SELECT DISTINCT r.id AS cve_id,
         -- CPE 2.3 escapes ':' inside a component as '\:' and a literal
         -- backslash as '\\'. Remove the escape characters so a vendor such as
         -- 'a\:b' is not truncated at the escaped colon.
         replace(replace(split_part(cpe, ':', 4), '\\', ''), '\:', ':') AS vendor,
         r.data->'cvss'->>'severity' AS severity
       FROM records r
       CROSS JOIN LATERAL jsonb_array_elements_text(
         CASE WHEN jsonb_typeof(r.data->'cpeMatches') = 'array'
           THEN r.data->'cpeMatches' ELSE '[]'::jsonb END
       ) AS cpe
       WHERE r.kind = 'cveData' AND ${dateClause || 'true'}
         AND cpe LIKE 'cpe:2.3:%'
     ) AS vendors
     -- 'any' is the CPE 2.3 wildcard spelling for an unspecified vendor in a
     -- component (unlike '*', which is an escaped literal in that position).
     WHERE vendor NOT IN ('', '*', '-', 'any')
     GROUP BY vendor
     ORDER BY count DESC, vendor ASC
     LIMIT ${Math.max(1, Math.min(50, vendorLimit))}`,
  );

  const scoreResult = await pool.query<{ score: number | null; count: number }>(
    `SELECT safe_numeric(data->'cvss'->>'score') AS score, count(*)::int AS count
     FROM records WHERE kind = 'cveData' AND ${dateClause || 'true'}
     GROUP BY score`,
  );

  return {
    totalCves: Number(totalResult.rows[0]?.total || 0),
    kevCount: Number(totalResult.rows[0]?.kev || 0),
    timeline: buildTimeline(timelineResult.rows),
    severityDistribution: buildSeverity(severityResult.rows),
    exploitStatusDistribution: buildExploit(exploitResult.rows),
    topVendors: buildVendors(vendorResult.rows),
    cvssScoreHistogram: buildScoreHistogram(scoreResult.rows),
    generatedAt: new Date().toISOString(),
  };
}

function buildTimeline(
  rows: { label: string; cveCount: number; critical: number; high: number }[],
): TimelinePoint[] {
  return rows.map((r) => ({
    label: r.label,
    cveCount: Number(r.cveCount),
    critical: Number(r.critical),
    high: Number(r.high),
  }));
}

function buildSeverity(rows: { severity: string; count: number }[]): SeverityDistribution {
  const dist: SeverityDistribution = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };
  for (const row of rows) {
    const sev = row.severity.toUpperCase();
    if (sev === 'CRITICAL') dist.critical = Number(row.count);
    else if (sev === 'HIGH') dist.high = Number(row.count);
    else if (sev === 'MEDIUM') dist.medium = Number(row.count);
    else if (sev === 'LOW') dist.low = Number(row.count);
    else dist.unknown = Number(row.count);
  }
  return dist;
}

function buildExploit(rows: { status: string; count: number }[]): ExploitStatusDistribution {
  const dist: ExploitStatusDistribution = {
    activeWeaponized: 0,
    reportedInWild: 0,
    pocAvailable: 0,
    none: 0,
  };
  for (const row of rows) {
    if (row.status === 'Active Weaponized') dist.activeWeaponized = Number(row.count);
    else if (row.status === 'Reported In Wild') dist.reportedInWild = Number(row.count);
    else if (row.status === 'POC Available') dist.pocAvailable = Number(row.count);
    else dist.none += Number(row.count);
  }
  return dist;
}

function buildVendors(
  rows: { vendor: string; count: number; critical: number; high: number }[],
): VendorAnalytics[] {
  return rows.map((r) => ({
    vendor: r.vendor,
    cveCount: Number(r.count),
    critical: Number(r.critical),
    high: Number(r.high),
  }));
}

function buildScoreHistogram(rows: { score: number | null; count: number }[]): CveScoreBin[] {
  const bins = [...SCORE_BINS];
  for (const row of rows) {
    const score = row.score !== null ? Number(row.score) : null;
    const count = Number(row.count);
    if (score === null || score < 0.1) {
      bins[0] = { range: '0.0', count: bins[0].count + count };
    } else if (score < 4.0) {
      bins[1] = { range: bins[1].range, count: bins[1].count + count };
    } else if (score < 7.0) {
      bins[2] = { range: bins[2].range, count: bins[2].count + count };
    } else if (score < 9.0) {
      bins[3] = { range: bins[3].range, count: bins[3].count + count };
    } else {
      bins[4] = { range: bins[4].range, count: bins[4].count + count };
    }
  }
  return bins;
}
