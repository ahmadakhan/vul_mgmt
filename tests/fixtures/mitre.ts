export const mitreRecord = (id = 'CVE-2026-98001', date = new Date().toISOString()) => ({
  dataType: 'CVE_RECORD', dataVersion: '5.2',
  cveMetadata: { cveId: id, state: 'PUBLISHED', datePublished: date, dateUpdated: date },
  containers: { cna: {
    title: 'Example widget vulnerability',
    descriptions: [{ lang: 'en', value: 'Example widget has a security vulnerability.' }],
    affected: [{ vendor: 'example', product: 'widget', cpes: ['cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*'],
      versions: [{ version: '1.0', lessThan: '2.0', status: 'affected', versionType: 'semver' }] }],
    metrics: [{ cvssV3_1: { version: '3.1', baseScore: 8.1, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' } }],
    references: [{ url: 'https://example.com/advisory' }],
    problemTypes: [{ descriptions: [{ cweId: 'CWE-79' }] }],
  } },
});
export const mitreDelta = (id = 'CVE-2026-98001', date = new Date().toISOString()) => [{
  fetchTime: date, new: [{ cveId: id, dateUpdated: date }],
  updated: [{ cveId: id, dateUpdated: date }], error: [],
}];
