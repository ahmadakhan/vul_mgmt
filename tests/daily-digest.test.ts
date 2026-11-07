import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
  digestSeveritySummary,
  digestSeverityKpi,
  formatExecutiveSummary,
  formatExecutiveSummaryText,
  stripGeneratedExecutiveSummaryMarkup,
} from '../src/utils/templateCompiler.ts';
import type { DailyDigestParts, DigestFinding, DigestHealth } from '../src/utils/templateCompiler.ts';

const UI_COLOR_KEYS = ['canvasBg', 'cardBg', 'headerBg', 'accentColor', 'fontFamily', 'headingColor'] as const;

const FINDINGS: DigestFinding[] = [
  { cveId: 'CVE-2026-0001', severity: 'CRITICAL', assetName: 'edge-router-01', vendor: 'VendorX', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001' },
  { cveId: 'CVE-2026-0002', severity: 'CRITICAL', assetName: 'auth-service', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0002' },
  { cveId: 'CVE-2026-0003', severity: 'HIGH', assetName: 'portal-web', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0003' },
  { cveId: 'CVE-2026-0004', severity: 'MEDIUM', assetName: 'internal-api', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0004' },
  { cveId: 'CVE-2026-0005', severity: 'LOW', assetName: 'monitoring-agent', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0005' },
];

const HEALTH: DigestHealth = {
  database: 'connected',
  databaseLatencyMs: 12,
  workerStatus: 'HEALTHY',
  workerHeartbeatAgeSeconds: 4,
  nextScheduledAttempt: '2026-10-30T09:00:00.000Z',
  nextDailyDigestAt: '2026-10-31T05:00:00.000Z',
  backlog: [
    { status: 'QUEUED', count: 0 },
    { status: 'ACCEPTED', count: 12 },
  ],
  checkedAt: '2026-10-29T08:00:00.000Z',
  systemUptime: '187 Days 14 Hours',
  systemUptimePercentage: 99.98,
};

const PARTS: DailyDigestParts = {
  advisory_id: 'DAILY-2026-10-29',
  advisory_title: 'Daily Vulnerability Notification',
  dispatch_date: '2026-10-29T10:00:00.000Z',
  severity: 'HIGH',
  finding_count: FINDINGS.length,
  severity_counts: '2 critical, 1 high, 1 medium, 1 low',
  findings_summary: renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  health_report: renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  recipient_name: 'Team',
  critical_count: 2,
  high_count: 1,
  medium_count: 1,
  low_count: 1,
  asset_count: 5,
  executive_summary: formatExecutiveSummary(5, { CRITICAL: 2, HIGH: 1, MEDIUM: 1, LOW: 1 }),
  report_generated: '29 October 2026 | 22:48 GMT+4',
  critical_summary: digestSeveritySummary('CRITICAL', 2, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  high_summary: digestSeveritySummary('HIGH', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  medium_summary: digestSeveritySummary('MEDIUM', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  low_summary: digestSeveritySummary('LOW', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  critical_kpi: digestSeverityKpi('CRITICAL', 2, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  high_kpi: digestSeverityKpi('HIGH', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  medium_kpi: digestSeverityKpi('MEDIUM', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  low_kpi: digestSeverityKpi('LOW', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
};

test('DEFAULT_DAILY_DIGEST_CUSTOMIZATION defines every color/style the digest UI reads', () => {
  for (const key of UI_COLOR_KEYS) {
    assert.ok(
      DEFAULT_DAILY_DIGEST_CUSTOMIZATION[key],
      `daily digest default is missing the "${key}" value the UI dereferences`,
    );
  }
});

test('renderDailyFindingSummary returns HTML containing each finding CVE', () => {
  const html = renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.equal(typeof html, 'string');
  assert.ok(html.length > 0);
  assert.ok(html.includes('CVE-2026-0001'));
  assert.ok(html.includes('CVE-2026-0003'));
  assert.ok(html.includes('CVE-2026-0004'));
  assert.ok(html.includes('CVE-2026-0005'));
});

test('renderDailyFindingSummary reports "no findings" when the list is empty', () => {
  const html = renderDailyFindingSummary([], DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('No findings'));
});

test('renderDailyFindingSummary groups findings by severity with count headers', () => {
  const html = renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('CRITICAL (2)'));
  assert.ok(html.includes('HIGH (1)'));
  assert.ok(html.includes('MEDIUM (1)'));
  assert.ok(html.includes('LOW (1)'));
  assert.ok(html.includes('edge-router-01 (VendorX)'));
  assert.ok(html.includes('auth-service'));
  assert.ok(html.includes('portal-web'));
  assert.ok(html.includes('internal-api'));
  assert.ok(html.includes('monitoring-agent'));
});

test('renderDailyFindingSummary renders each CVE as a link to its source', () => {
  const html = renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(
    html.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001"'),
    'CVE links to its source URL',
  );
  assert.ok(
    html.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2026-0005"'),
    'CVE links to its source URL',
  );
  assert.ok(!html.includes('Hello'), 'greeting text removed');
});

test('renderDailyHealthReport returns HTML containing the database status', () => {
  const html = renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.equal(typeof html, 'string');
  assert.ok(html.length > 0);
  assert.ok(html.includes('Operational'));
  assert.ok(html.includes('12 ms'));
});

test('renderDailyHealthReport renders Platform Health Status table rows', () => {
  const html = renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('Database Connectivity'));
  assert.ok(html.includes('Operational (12 ms)'));
  assert.ok(html.includes('Healthy'));
  assert.ok(html.includes('Delivery Queue'));
  assert.ok(html.includes('0 Queued | 0 Sending | 0 Awaiting review | 12 Provider accepted | 0 Failed'));
});

test('renderDailyHealthReport returns empty string when health is null', () => {
  const html = renderDailyHealthReport(null, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.equal(html, '');
});

test('renderDailyDigest embeds the findings summary and the health report', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.equal(typeof html, 'string');
  assert.ok(html.includes('CVE-2026-0001'), 'digest embeds the findings summary');
  assert.ok(html.includes('Operational (12 ms)'), 'digest embeds the health report');
  assert.ok(html.includes('Daily Vulnerability Notification'), 'digest embeds the title');
});

test('renderDailyDigest populates KPI counts exactly', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.ok(html.includes('CRITICAL (2)'), 'findings summary shows critical count');
  assert.ok(html.includes('CRITICAL'), 'KPI dashboard shows critical label');
  assert.ok(html.includes('CRITICAL'), 'severity header present');
  assert.ok(html.includes('ASSETS'));
});

test('renderDailyDigest embeds executive summary and report generated date', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.ok(html.includes('Report Generated: 29 October 2026 | 22:48 GMT+4'));
  assert.ok(html.includes('Vulnerability Overview'));
  assert.ok(html.includes('<strong>5 findings</strong>'));
  assert.ok(html.includes('<strong>2 Critical</strong>'));
  assert.ok(html.includes('<strong>1 High</strong>'));
  assert.ok(html.includes('<strong>1 Medium</strong>'));
  assert.ok(html.includes('<strong>1 Low</strong>'));
});

test('renderDailyHealthReport reports process uptime without claiming availability', () => {
  const html = renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('Worker Process Uptime'));
  assert.ok(!html.includes('99.98%'));
  assert.ok(html.includes('187 Days 14 Hours'));
  assert.ok(html.includes('(since restart)'));
  assert.ok(!html.includes('unmeasured'));
});

test('renderDailyDigest contains no leftover template placeholders', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.ok(!html.includes('{{'), 'no unreplaced placeholders remain');
});

test('renderDailyDigest omits zero-count severity sections', () => {
  const zeroParts: DailyDigestParts = {
    ...PARTS,
    medium_count: 0,
    low_count: 0,
    medium_summary: '',
    low_summary: '',
    medium_kpi: '',
    low_kpi: '',
  };
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, zeroParts);
  assert.ok(!html.includes('Medium:</strong>'), 'zero-count medium summary not rendered');
  assert.ok(!html.includes('Low:</strong>'), 'zero-count low summary not rendered');
  assert.ok(!html.includes('MEDIUM (0)'), 'zero-count medium findings not rendered');
  assert.ok(!html.includes('LOW (0)'), 'zero-count low findings not rendered');
  assert.ok(!html.includes('{{'), 'no unreplaced placeholders');
});

test('formatExecutiveSummary explains the zero-finding scope without remediation advice', () => {
  const summary = formatExecutiveSummary(0, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 });
  assert.ok(summary.includes('<strong>0 findings</strong>'));
  assert.ok(summary.includes('matched your subscriptions in the last 24 hours'));
  assert.ok(summary.includes('does not mean there are no open vulnerabilities'));
  assert.ok(summary.includes('held for review are excluded'));
  assert.doesNotMatch(summary, /remediation|critical|medium|low severity/i);
  assert.ok(!summary.includes('undefined'));
});

test('formatExecutiveSummaryText emits plain text for advisory records', () => {
  const summary = formatExecutiveSummaryText(1, { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 });
  assert.ok(!summary.includes('<strong>'));
  assert.ok(summary.includes('1 finding'));
  assert.ok(summary.includes('1 Critical'));
});

test('stripGeneratedExecutiveSummaryMarkup cleans legacy summary tags', () => {
  assert.equal(
    stripGeneratedExecutiveSummaryMarkup('A total of <strong>2 vulnerabilities</strong> were found.'),
    'A total of 2 vulnerabilities were found.',
  );
});

test('formatExecutiveSummary lists each nonzero severity', () => {
  const summary = formatExecutiveSummary(4, { CRITICAL: 2, HIGH: 1, MEDIUM: 1, LOW: 0, UNKNOWN: 0 });
  assert.ok(summary.includes('<strong>2 Critical</strong>'));
  assert.ok(summary.includes('<strong>1 High</strong>'));
  assert.ok(summary.includes('<strong>1 Medium</strong>'));
  assert.ok(!summary.includes('undefined'));
});

test('renderDailyDigest does not escape HTML when all findings are zero', () => {
  const zeroParts: DailyDigestParts = {
    ...PARTS,
    finding_count: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    asset_count: 0,
    severity_counts: '0 critical, 0 high, 0 medium, 0 low',
    executive_summary: formatExecutiveSummary(0, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 }),
  };
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, zeroParts);
  assert.ok(html.includes('<strong>0 findings</strong>'), 'strong tags preserved, not escaped');
  assert.ok(!html.includes('&lt;strong&gt;'), 'no escaped strong tags');
  assert.ok(!html.includes('undefined'), 'no literal "undefined" text');
});

/**
 * The digest header must not carry a severity-coloured rule across the top.
 * A red 4-6px line above "BA Cyber | THREAT INTELLIGENCE" reads as a critical
 * alert on every digest, including quiet days with no findings.
 */
test('digest header has no coloured top rule', () => {
  const parts = {
    advisory_id: 'ADV-1',
    advisory_title: 'Daily',
    dispatch_date: new Date().toISOString(),
    severity: 'CRITICAL',
    finding_count: 1,
    severity_counts: '1 critical',
    findings_summary: renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
    held_for_review: '',
    health_report: '',
    recipient_name: 'Team',
    critical_count: 1,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    asset_count: 1,
    executive_summary: 'Summary',
    report_generated: 'now',
  } as unknown as DailyDigestParts;
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts);
  // Neutral hairline separators in the footer are fine; a thick, accent-coloured
  // rule above the header is not.
  assert.doesNotMatch(
    html,
    /border-top:\s*[2-9]px\s+solid\s+(#dc2626|#ef4444|#b91c1c)/i,
    'header must not render a thick red top rule',
  );
  assert.doesNotMatch(html, /border-top:\s*\d+px\s+solid\s+\$\{/, 'no templated accent-coloured top rule');
});

test('health report separates accepted and failed deliveries and labels times with a UTC offset', () => {
  const health = {
    database: 'connected',
    databaseLatencyMs: 3,
    workerStatus: 'HEALTHY',
    workerHeartbeatAgeSeconds: 12,
    nextScheduledAttempt: null,
    backlog: [
      { status: 'ACCEPTED', count: 14 },
      { status: 'FAILED', count: 1 },
    ],
    checkedAt: new Date().toISOString(),
    systemUptime: '2 Days 3 Hours',
    systemUptimePercentage: null,
  } as unknown as DigestHealth;
  const html = renderDailyHealthReport(health, {
    ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
    timezone: 'Europe/Berlin',
  } as unknown as Parameters<typeof renderDailyHealthReport>[1]);
  assert.match(html, /14 Provider accepted \| 1 Failed/);
  assert.doesNotMatch(html, /Processed/);
  assert.doesNotMatch(html, /\bUTC<|\bUTC\s/, 'timestamps must be labelled with an offset, not bare UTC');
  assert.match(html, /UTC[+-]\d/, 'timestamps must carry a UTC offset');
});

test('remediation guidance refers only to the severities present', () => {
  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']) {
    const summary = formatExecutiveSummary(1, { [severity]: 1 });
    for (const absent of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].filter((s) => s !== severity)) {
      assert.ok(!summary.toLowerCase().includes(absent.toLowerCase()), `${severity} summary mentions absent ${absent}`);
    }
    const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, { ...PARTS, executive_summary: summary });
    assert.ok(html.includes('<strong>1 finding</strong>'));
    assert.ok(!html.includes('&lt;strong&gt;'));
    const injected = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, {
      ...PARTS, executive_summary: summary + '<img src=x onerror=alert(1)>',
    });
    assert.ok(!injected.includes('<img src=x'));
  }
});

test('daily schedule and queued delivery attempts render independently in the workspace timezone', () => {
  const html = renderDailyHealthReport({
    ...HEALTH,
    backlog: [
      { status: 'QUEUED', count: 100 },
      { status: 'SENDING', count: 3 },
      { status: 'REVIEW', count: 55 },
      { status: 'ACCEPTED', count: 750 },
      { status: 'FAILED', count: 7 },
    ],
  }, { ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION, timezone: 'Asia/Dubai' });
  assert.match(html, /Next Delivery Attempt[\s\S]*?30 Oct 2026 13:00 UTC\+4/);
  assert.match(html, /Next Scheduled Digest[\s\S]*?31 Oct 2026 09:00 UTC\+4/);
  assert.ok(html.includes('100 Queued | 3 Sending | 55 Awaiting review | 750 Provider accepted | 7 Failed'));

  const noRetries = renderDailyHealthReport({
    ...HEALTH, nextScheduledAttempt: null,
  }, { ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION, timezone: 'Asia/Dubai' });
  assert.ok(noRetries.includes('31 Oct 2026 09:00 UTC+4'));
  assert.ok(noRetries.includes('No future delivery attempt scheduled'));
  assert.ok(!noRetries.includes('none pending'));
});
