import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderAdvisory, validateAdvisoryFields } from '../server/advisoryRender.ts';
import { compileCustomizedTemplate } from '../src/utils/templateCompiler.ts';
import type { Advisory, Finding } from '../src/types/index.ts';

const baseAdvisory: Advisory = {
  id: 'ADV-2026-001',
  title: 'Test vulnerability advisory',
  severity: 'CRITICAL',
  cveIds: ['CVE-2026-12345'],
  findingIds: ['finding-1'],
  createdDate: new Date().toISOString(),
  deliveryStatus: 'PENDING',
  recipientCount: 1,
  executiveSummary: 'A test vulnerability affects monitored systems.',
  affectedSystems: ['web-server-01'],
  remediationInstructions: 'Apply the vendor patch immediately.',
  vendorLink: 'https://example.com/advisory/12345',
};

test('renderAdvisory does not render audience notice or reviewer comment rows', () => {
  const template = compileCustomizedTemplate({
    fontFamily: 'sans',
    fontColor: '#334155',
    headingColor: '#0f172a',
    accentColor: '#2563eb',
    canvasBg: '#f1f5f9',
    cardBg: '#ffffff',
    headerBg: '#0f172a',
     badgeStampText: 'BA CYBER SECURITY OPERATIONS',
    badgeStampColor: '#2563eb',
    showStamp: true,
    showClassificationBanner: false,
    classificationText: '',
    borderStyle: 'solid',
    borderRadius: '12px',
  });
  const advisory: Advisory = {
    ...baseAdvisory,
    edits: {
      audienceNotice: 'This is a broad-distribution advisory.',
      reviewerComment: 'Reviewed by security team',
      reviewerName: 'sec-op-1',
    },
  };
  const html = renderAdvisory(template, advisory);
  assert.ok(!html.includes('{{'), 'no unrendered tokens');
  assert.ok(!html.includes('Audience Notice'), 'audience notice row should not appear');
  assert.ok(!html.includes('Reviewer Comment'), 'reviewer comment row should not appear');
  assert.ok(!html.includes('This is a broad-distribution advisory.'), 'audience notice text should not appear');
  assert.ok(!html.includes('Reviewed by security team'), 'reviewer comment text should not appear');
});

test('renderAdvisory cve_details renders a linked CVE card with description and KEV', () => {
  const template = compileCustomizedTemplate(testCustomization);
  const html = renderAdvisory(template, baseAdvisory);
  assert.ok(
    html.includes('https://nvd.nist.gov/vuln/detail/CVE-2026-12345'),
    'the CVE ID must link to its authoritative NVD source',
  );
  assert.ok(html.includes('background:#ef4444'), 'severity badge should use CRITICAL color (#ef4444)');
  // The per-CVE detail block is a card, not a bullet list.
  const details = html.slice(html.indexOf('CVE-2026-12345'));
  assert.ok(details.includes('CVSS'), 'each CVE must show its CVSS score');
});

test('renderAdvisory cve_details badge matches advisory severity', () => {
  const template = compileCustomizedTemplate(testCustomization);
  for (const { sev, color } of [
    { sev: 'CRITICAL', color: '#ef4444' },
    { sev: 'HIGH', color: '#f59e0b' },
    { sev: 'MEDIUM', color: '#eab308' },
    { sev: 'LOW', color: '#10b981' },
    { sev: 'UNKNOWN', color: '#6b7280' },
  ]) {
    const html = renderAdvisory(template, { ...baseAdvisory, severity: sev as Advisory['severity'] });
    assert.ok(html.includes(`background:${color}`), `cve_details badge for ${sev} should use ${color}`);
  }
});

const testCustomization = {
  fontFamily: 'sans',
  fontColor: '#334155',
  headingColor: '#0f172a',
  accentColor: '#2563eb',
  canvasBg: '#f1f5f9',
  cardBg: '#ffffff',
  headerBg: '#0f172a',
  badgeStampColor: '#2563eb',
  badgeStampText: 'BA HBS Cyber Operations',
  showStamp: true,
  showClassificationBanner: false,
  classificationText: '',
  borderStyle: 'solid',
  borderRadius: '12px',
} as const;

test('renderAdvisory renders severity badges with correct colors for each severity level', () => {
  const template = compileCustomizedTemplate(testCustomization);
  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']) {
    const html = renderAdvisory(template, { ...baseAdvisory, severity: severity as Advisory['severity'] });
    assert.ok(!html.includes('{{'), `no unrendered tokens for severity ${severity}`);
    assert.ok(
      html.includes(`background:#${severity === 'CRITICAL' ? 'ef4444' : severity === 'HIGH' ? 'f59e0b' : severity === 'MEDIUM' ? 'eab308' : severity === 'LOW' ? '10b981' : '6b7280'}`),
      `severity ${severity} badge should have correct color`,
    );
    assert.ok(html.includes(`${severity} SEVERITY`), `header badge should show "${severity} SEVERITY"`);
    assert.ok(html.includes(`>${severity}<`), `details table badge should show "${severity}"`);
  }
});

test('validateAdvisoryFields returns valid for complete advisory', () => {
  const result = validateAdvisoryFields(baseAdvisory);
  assert.equal(result.valid, true);
  assert.equal(result.missingFields.length, 0);
});

test('validateAdvisoryFields detects empty required fields', () => {
  const cases: { label: string; advisory: Partial<Advisory>; expected: string[] }[] = [
    { label: 'empty id', advisory: { ...baseAdvisory, id: '' }, expected: ['id'] },
    { label: 'empty title', advisory: { ...baseAdvisory, title: '' }, expected: ['title'] },
    { label: 'empty executiveSummary', advisory: { ...baseAdvisory, executiveSummary: '' }, expected: ['executiveSummary'] },
    { label: 'empty remediationInstructions', advisory: { ...baseAdvisory, remediationInstructions: '' }, expected: ['remediationInstructions'] },
    { label: 'empty affectedSystems', advisory: { ...baseAdvisory, affectedSystems: [] }, expected: ['affectedSystems'] },
    {
      label: 'multiple empty fields',
      advisory: { ...baseAdvisory, id: '', title: '', severity: '' as Advisory['severity'] },
      expected: ['id', 'title', 'severity'],
    },
  ];
  for (const { label, advisory, expected } of cases) {
    const result = validateAdvisoryFields(advisory as Advisory);
    assert.equal(result.valid, false, `should be invalid: ${label}`);
    assert.deepEqual(result.missingFields, expected, `missing fields should match: ${label}`);
  }
});

test('renderAdvisory throws when required advisory fields are empty', () => {
  const template = compileCustomizedTemplate(testCustomization);
  assert.throws(
    () => renderAdvisory(template, { ...baseAdvisory, id: '' }),
    /Cannot render advisory email with empty required fields: id/,
  );
  assert.throws(
    () => renderAdvisory(template, { ...baseAdvisory, title: '   ' }),
    /Cannot render advisory email with empty required fields: title/,
  );
  assert.throws(
    () => renderAdvisory(template, { ...baseAdvisory, executiveSummary: '' }),
    /Cannot render advisory email with empty required fields: executiveSummary/,
  );
  assert.throws(
    () => renderAdvisory(template, { ...baseAdvisory, remediationInstructions: '' }),
    /Cannot render advisory email with empty required fields: remediationInstructions/,
  );
  assert.throws(
    () => renderAdvisory(template, { ...baseAdvisory, affectedSystems: [] }),
    /Cannot render advisory email with empty required fields: affectedSystems/,
  );
});

test('renderAdvisory produces template matching the studio HTML structure', () => {
  const template = compileCustomizedTemplate(testCustomization);
  const html = renderAdvisory(template, baseAdvisory);
  assert.ok(template.includes('ul { margin:0; padding-left:20px; }'), 'template lists should use consistent left spacing');
   assert.ok(html.includes('THREAT INTELLIGENCE &amp; BA CYBER SECURITY OPERATIONS'), 'studio label should appear');
  assert.ok(html.includes('Security Advisory'), 'static heading should appear');
  assert.ok(html.includes('ADV-2026-001'), 'advisory id should be rendered');
  assert.ok(html.includes('Test vulnerability advisory'), 'advisory title should be rendered');
  assert.ok(html.includes('BA Threat Intelligence'), 'footer label should appear');
  assert.ok(html.includes('EXECUTIVE SUMMARY'), 'executive summary section should appear');
  assert.ok(html.includes('ADVISORY DETAILS'), 'advisory details section should appear');
  assert.ok(!html.includes('Vulnerability Name'), 'vulnerability name row should not appear');
  assert.ok(html.includes('Test vulnerability advisory'), 'advisory title should be rendered');
  assert.ok(html.includes('Affected Products &amp; Versions'), 'affected products row should appear');
  assert.ok(html.includes('Workaround / Mitigation'), 'mitigation row should appear');
  assert.ok(html.includes('Honeywell Recommended Actions'), 'recommended action row should appear');
});

const findingsWithVendorLinks: Finding[] = [
  {
    id: 'finding-1',
    cveId: 'CVE-2026-12345',
    cve: {
      cveId: 'CVE-2026-12345',
      title: 'Test vulnerability',
      description: 'A test vulnerability',
      publishedDate: '2026-10-30T00:00:00Z',
      modifiedDate: '2026-10-30T00:00:00Z',
      cvss: { version: '3.1', score: 9.8, vector: 'AV:N/AC:L', severity: 'CRITICAL' },
      cwe: [],
      cpeMatches: ['cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*'],
      cpeMatchDetails: [
        {
          criteria: 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
          range: { versionStartIncluding: '1.2.0', versionEndExcluding: '2.0.0' },
        },
      ],
      versionRange: { versionStartIncluding: '1.2.0', versionEndExcluding: '2.0.0' },
      sourceFeeds: [],
      epss: { score: 0.5, percentile: 0.8 },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      remediation: {
        patchUrl: 'https://vendor.com/patch/CVE-2026-12345',
        vendorAdvisoryRef: 'https://vendor.com/advisory/CVE-2026-12345',
        immediateActions: [],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    } as any,
    matchedAssetId: 'asset-1',
    matchedAssetName: 'web-server-01',
    matchedAssetVendor: 'Northstar Networks',
    matchedAssetProduct: 'Edge Gateway',
    matchedCpe: 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
    matchingMethod: 'CPE',
    matchingEvidence: 'matched',
    exploitRisk: 'STANDARD',
    notificationStatus: 'AUTO_DISPATCHED',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    timeline: [],
  } as unknown as Finding,
];

test('renderAdvisory shows View Vendor Guidance and Advisory link from finding remediation data', () => {
  const template = compileCustomizedTemplate(testCustomization);
  const html = renderAdvisory(template, baseAdvisory, findingsWithVendorLinks);
  assert.ok(html.includes('View Vendor Guidance'), 'view vendor guidance should appear with a link');
  assert.ok(html.includes('Advisory link'), 'vendor security advisory should appear with a link');
  assert.ok(html.includes('href="https://vendor.com/patch/CVE-2026-12345"'), 'view vendor guidance should point to the patch URL');
  assert.ok(html.includes('href="https://vendor.com/advisory/CVE-2026-12345"'), 'vendor security advisory should point to the advisory URL');
  assert.ok(!html.includes('href=""'), 'no empty href should remain');
});

test('renderAdvisory uses styled CVE links, affected version bounds, and per-CVE remediation', () => {
  const first = findingsWithVendorLinks[0];
  const secondCve = 'CVE-2026-12346';
  const second: Finding = {
    ...first,
    id: 'finding-2',
    cveId: secondCve,
    cve: {
      ...first.cve,
      cveId: secondCve,
      title: 'Second test vulnerability',
      remediation: {
        ...first.cve.remediation,
        patchUrl: 'https://vendor.com/patch/CVE-2026-12346',
        immediateActions: ['Disable the vulnerable feature until patched.'],
        stepByStep: ['Install the vendor update and verify service health.'],
      },
    },
  };
  const advisory = { ...baseAdvisory, cveIds: [first.cveId, secondCve] };
  const html = renderAdvisory(
    compileCustomizedTemplate(testCustomization),
    advisory,
    [first, second],
  );

  assert.match(html, /color:#1d4ed8;text-decoration:underline/);
  assert.ok(html.includes('Northstar Networks - Edge Gateway'));
  assert.ok(html.includes('Affected versions: &gt;= 1.2.0 and &lt; 2.0.0'));
  assert.ok(html.includes('Product:</strong> Northstar Networks - Edge Gateway'));
  assert.ok(html.includes('Affected version(s):</strong> &gt;= 1.2.0 and &lt; 2.0.0'));
  assert.ok(html.includes('Published:</strong> 30 Oct 2026'));
  assert.ok(html.includes('Last modified:</strong> 30 Oct 2026'));
  assert.ok(html.includes('Operator-provided note (unverified):</strong> Apply the vendor patch immediately.'));
  assert.ok(html.includes('This note is not evidence that a patch or fix is available.'));
  assert.ok(html.includes('Disable the vulnerable feature until patched.'));
  assert.ok(html.includes(`href="https://vendor.com/patch/${secondCve}"`));
});

test('renderAdvisory uses cautious remediation fallback and explicit unavailable finding metadata', () => {
  const finding: Finding = {
    ...findingsWithVendorLinks[0],
    cve: {
      ...findingsWithVendorLinks[0].cve,
      publishedDate: undefined,
      modifiedDate: undefined,
      remediation: { immediateActions: [], stepByStep: [], workarounds: [] },
    },
    matchedAssetVendor: '',
    matchedAssetProduct: '',
    matchedAssetName: '',
  } as unknown as Finding;
  const html = renderAdvisory(
    compileCustomizedTemplate(testCustomization),
    baseAdvisory,
    [finding],
  );

  assert.ok(html.includes('No vendor patch or fix guidance is supplied for this finding, so availability must not be assumed.'));
  assert.ok(html.includes('Published:</strong> Unavailable'));
  assert.ok(html.includes('Last modified:</strong> Unavailable'));
  assert.ok(html.includes('Product:</strong> vendor - product'));
  assert.ok(html.includes('Affected version(s):</strong> &gt;= 1.2.0 and &lt; 2.0.0'));
  assert.ok(html.includes('Operator-provided note (unverified)'));
  assert.ok(!html.includes('Apply a vendor-supported fix'));
  assert.ok(!html.includes('Apply vendor patches immediately'));
});

test('renderAdvisory keeps per-product remediation guidance scoped to its finding', () => {
  const first: Finding = {
    ...findingsWithVendorLinks[0],
    cve: {
      ...findingsWithVendorLinks[0].cve,
      remediation: {
        ...findingsWithVendorLinks[0].cve.remediation,
        immediateActions: ['Isolate the Northstar gateway pending vendor guidance.'],
      },
    },
  };
  const second: Finding = {
    ...first,
    id: 'finding-other-product',
    matchedAssetVendor: 'Contoso',
    matchedAssetProduct: 'Gateway',
    matchedAssetName: 'Contoso Gateway',
    cve: {
      ...first.cve,
      remediation: {
        ...first.cve.remediation,
        patchUrl: 'https://contoso.example/patch',
        vendorAdvisoryRef: 'https://contoso.example/advisory',
        immediateActions: ['Isolate the Contoso gateway pending vendor guidance.'],
        stepByStep: [],
        workarounds: [],
        rollbackPlan: '',
      },
    },
  };
  const html = renderAdvisory(
    compileCustomizedTemplate(testCustomization),
    baseAdvisory,
    [first, second],
  );
  const northstar = html.indexOf('Northstar Networks - Edge Gateway');
  const northstarAction = html.indexOf('Isolate the Northstar gateway pending vendor guidance.');
  const contoso = html.indexOf('Contoso - Gateway', northstarAction);
  const contosoAction = html.indexOf('Isolate the Contoso gateway pending vendor guidance.');

  assert.ok(northstar >= 0 && northstarAction > northstar);
  assert.ok(contoso > northstarAction && contosoAction > contoso);
  assert.ok(html.includes('https://vendor.com/patch/CVE-2026-12345'));
  assert.ok(html.includes('https://contoso.example/patch'));
});

test('renderAdvisory hides View Vendor Guidance and Vendor Security Advisory when no vendor link is present in findings', () => {
  const template = compileCustomizedTemplate(testCustomization);
  const html = renderAdvisory(template, baseAdvisory);
  assert.ok(!html.includes('View Vendor Guidance'), 'view vendor guidance should be hidden without a vendor link in findings');
  assert.ok(!html.includes('Vendor Security Advisory'), 'vendor security advisory should be hidden without a vendor link in findings');
  assert.ok(html.includes('Apply the vendor patch immediately.'), 'manual operator remediation remains unchanged when no findings are supplied');
  assert.ok(!html.includes('#if'), 'no unrendered conditional tokens should remain');
});
