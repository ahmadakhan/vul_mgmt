import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { searchThreatIntelligence, generateCpePrefixes } from '../server/threatSearch';
import type { Requester } from '../server/network';
import { loadConfig } from '../server/config';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
});

const mockCve = {
  id: 'CVE-2024-1234',
  published: '2024-01-01T00:00:00.000',
  lastModified: '2024-01-02T00:00:00.000',
  vulnStatus: 'Analyzed',
  descriptions: [{ lang: 'en', value: 'A buffer overflow in Microsoft Windows 10.' }],
  configurations: [
    {
      nodes: [
        {
          cpeMatch: [
            {
              criteria: 'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
              vulnerable: true,
            },
          ],
        },
      ],
    },
  ],
  metrics: {
    cvssMetricV31: [
      {
        cvssData: {
          version: '3.1',
          baseScore: 7.5,
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
          baseSeverity: 'HIGH',
        },
      },
    ],
  },
  weaknesses: [{ description: [{ lang: 'en', value: 'CWE-120' }] }],
  references: [{ url: 'https://msrc.microsoft.com/update', tags: ['Vendor Advisory'] }],
};

const mockCve2 = {
  id: 'CVE-2024-5678',
  published: '2024-03-01T00:00:00.000',
  lastModified: '2024-03-02T00:00:00.000',
  vulnStatus: 'Analyzed',
  descriptions: [{ lang: 'en', value: 'A vulnerability in Apache HTTP Server.' }],
  configurations: [
    {
      nodes: [
        {
          cpeMatch: [
            {
              criteria: 'cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*',
              vulnerable: true,
            },
          ],
        },
      ],
    },
  ],
  metrics: {
    cvssMetricV31: [
      {
        cvssData: {
          version: '3.1',
          baseScore: 9.8,
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseSeverity: 'CRITICAL',
        },
      },
    ],
  },
  weaknesses: [],
  references: [],
};

function createMockDb(hasAliases = false): Parameters<typeof searchThreatIntelligence>[1] {
  const rows: any[] = [];
  if (hasAliases) {
    rows.push({
      data: { scope: 'VENDOR', canonical: 'apache', aliases: ['apache_software_foundation', 'httpd'] },
    });
  }
  return {
    query: async () => ({ rows }),
  } as unknown as Parameters<typeof searchThreatIntelligence>[1];
}

function createRequester(response: {
  status: number;
  body: string;
  headers?: Record<string, string>;
}): Requester {
  return async () => ({
    status: response.status,
    body: response.body,
    headers: response.headers || {},
  });
}

test('searchThreatIntelligence searches NVD by CPE virtual match and returns matching CVEs', async () => {
  const requester = createRequester({
    status: 200,
    body: JSON.stringify({
      totalResults: 1,
      vulnerabilities: [{ cve: mockCve }],
    }),
  });

  const db = createMockDb(false);

  const result = await searchThreatIntelligence(requester, db, config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
  });

  assert.equal(result.hits.length, 1);
  assert.equal(result.hits[0].cve.cveId, 'CVE-2024-1234');
  assert.equal(result.hits[0].source, 'NVD_API');
  assert.ok(result.hits[0].matchingCpes.includes('cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*'));
  assert.equal(result.rateLimited, false);
  assert.equal(result.vendor, 'microsoft');
  assert.equal(result.product, 'windows_10');
});

test('searchThreatIntelligence uses keyword search fallback when no CPE match', async () => {
  let cpeCallCount = 0;
  const keywordRequester: Requester = async () => {
    if (cpeCallCount < 3) {
      cpeCallCount++;
      return {
        status: 200,
        body: JSON.stringify({ totalResults: 0, vulnerabilities: [] }),
        headers: {},
      };
    }
    return {
      status: 200,
      body: JSON.stringify({
        totalResults: 1,
        vulnerabilities: [{ cve: mockCve2 }],
      }),
      headers: {},
    };
  };

  const db = createMockDb(false);

  const result = await searchThreatIntelligence(keywordRequester, db, config, {
    vendor: 'apache',
    product: 'http_server',
    limit: 50,
  });

  assert.ok(result.hits.length >= 1);
  const hit = result.hits.find((h) => h.cve.cveId === 'CVE-2024-5678');
  assert.ok(hit, 'should have found CVE-2024-5678 via keyword fallback');
});

test('searchThreatIntelligence handles NVD rate limiting gracefully', async () => {
  const requester: Requester = async () => ({
    status: 429,
    body: '',
    headers: { 'retry-after': '30' },
  });

  const db = createMockDb(false);

  const result = await searchThreatIntelligence(requester, db, config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
  });

  assert.equal(result.rateLimited, true);
  assert.equal(result.retryAfter, 30);
  assert.equal(result.hits.length, 0);
});

test('searchThreatIntelligence returns empty results when no matches found', async () => {
  const requester = createRequester({
    status: 200,
    body: JSON.stringify({ totalResults: 0, vulnerabilities: [] }),
  });

  const db = createMockDb(false);

  const result = await searchThreatIntelligence(requester, db, config, {
    vendor: 'unknown_vendor',
    product: 'unknown_product',
    limit: 50,
  });

  assert.equal(result.hits.length, 0);
  assert.equal(result.totalResults, 0);
  assert.equal(result.rateLimited, false);
});

test('searchThreatIntelligence filters out rejected CVEs', async () => {
  const requester = createRequester({
    status: 200,
    body: JSON.stringify({
      totalResults: 2,
      vulnerabilities: [
        { cve: mockCve },
        {
          cve: {
            id: 'CVE-2024-9999',
            vulnStatus: 'Rejected',
            descriptions: [{ lang: 'en', value: 'Rejected CVE' }],
          },
        },
      ],
    }),
  });

  const db = createMockDb(false);

  const result = await searchThreatIntelligence(requester, db, config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
  });

  assert.equal(result.hits.length, 1);
  assert.equal(result.hits[0].cve.cveId, 'CVE-2024-1234');
});

test('searchThreatIntelligence resolves vendor aliases from custom thesaurus', async () => {
  const requester = createRequester({
    status: 200,
    body: JSON.stringify({
      totalResults: 1,
      vulnerabilities: [{ cve: mockCve2 }],
    }),
  });

  const db = createMockDb(true);

  const result = await searchThreatIntelligence(requester, db, config, {
    vendor: 'apache',
    product: 'http_server',
    limit: 50,
  });

  assert.ok(result.hits.length >= 1);
});

test('searchThreatIntelligence generates CPE virtual-match prefixes for parts a, o, h', async () => {
  let calledUrls: string[] = [];
  const requester: Requester = async (url) => {
    calledUrls.push(url);
    return {
      status: 200,
      body: JSON.stringify({ totalResults: 0, vulnerabilities: [] }),
      headers: {},
    };
  };

  const db = createMockDb(false);

  await searchThreatIntelligence(requester, db, config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
  });

  const matchUrls = calledUrls.filter((u) => u.includes('virtualMatchString='));
  assert.ok(matchUrls.length >= 1, 'should make at least one CPE virtual-match request');
  const matchString = new URL(matchUrls[0]).searchParams.get('virtualMatchString');
  assert.ok(matchString, 'virtualMatchString parameter should be present');
  assert.ok(matchString.startsWith('cpe:2.3:'), 'should use CPE 2.3 format');
  assert.ok(
    matchString.startsWith('cpe:2.3:a:microsoft:windows_10:'),
    'should target the vendor/product prefix with CPE 2.3 format',
  );
  assert.equal(
    matchString.split(':').length,
    13,
    'should have 13 fields (cpe:2.3:part:vendor:product + 8 wildcard components)',
  );
});

test('keyword fallback normalizes CPE-style underscores for NVD text search', async () => {
  const calledUrls: string[] = [];
  const requester: Requester = async (url) => {
    calledUrls.push(url);
    return {
      status: 200,
      body: JSON.stringify({ totalResults: 0, vulnerabilities: [] }),
      headers: {},
    };
  };

  await searchThreatIntelligence(requester, createMockDb(false), config, {
    vendor: 'apache',
    product: 'http_server',
    limit: 50,
  });

  const keywordUrl = calledUrls.find((url) => url.includes('keywordSearch='));
  assert.ok(keywordUrl, 'should fall back to keyword search');
  assert.equal(
    new URL(keywordUrl).searchParams.get('keywordSearch'),
    'apache http server',
    'should send plain words, not CPE identifiers',
  );
});

test('searchThreatIntelligence passes pubStartDate to the NVD API when startDate is provided', async () => {
  const calledUrls: string[] = [];
  const requester: Requester = async (url) => {
    calledUrls.push(url);
    return {
      status: 200,
      body: JSON.stringify({
        totalResults: 1,
        vulnerabilities: [{ cve: mockCve }],
      }),
      headers: {},
    };
  };

  const db = createMockDb(false);

  await searchThreatIntelligence(requester, db, config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
    startDate: '2024-01-01',
  });

  const cpeUrls = calledUrls.filter((u) => u.includes('virtualMatchString='));
  assert.ok(cpeUrls.length >= 1, 'should make CPE virtual-match requests');
  const startDate = new URL(cpeUrls[0]).searchParams.get('pubStartDate');
  assert.equal(
    startDate,
    '2024-01-01T00:00:00.000',
    'should send pubStartDate in ISO 8601 with milliseconds',
  );
});

test('searchThreatIntelligence omits pubStartDate when no startDate is given', async () => {
  const calledUrls: string[] = [];
  const requester: Requester = async (url) => {
    calledUrls.push(url);
    return {
      status: 200,
      body: JSON.stringify({
        totalResults: 1,
        vulnerabilities: [{ cve: mockCve }],
      }),
      headers: {},
    };
  };

  const db = createMockDb(false);

  await searchThreatIntelligence(requester, db, config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
  });

  const cpeUrls = calledUrls.filter((u) => u.includes('virtualMatchString='));
  assert.ok(cpeUrls.length >= 1);
  const startDate = new URL(cpeUrls[0]).searchParams.get('pubStartDate');
  assert.equal(startDate, null, 'should not send pubStartDate when no startDate given');
});

test('searchThreatIntelligence passes pubStartDate to keyword fallback requests', async () => {
  const calledUrls: string[] = [];
  const requester: Requester = async (url) => {
    calledUrls.push(url);
    return {
      status: 200,
      body: JSON.stringify({
        totalResults: 0,
        vulnerabilities: [],
      }),
      headers: {},
    };
  };

  await searchThreatIntelligence(requester, createMockDb(false), config, {
    vendor: 'apache',
    product: 'http_server',
    limit: 50,
    startDate: '2024-06-01',
  });

  const keywordUrls = calledUrls.filter((u) => u.includes('keywordSearch='));
  assert.ok(keywordUrls.length >= 1, 'should fall back to keyword search');
  const startDate = new URL(keywordUrls[0]).searchParams.get('pubStartDate');
  assert.equal(startDate, '2024-06-01T00:00:00.000', 'keyword fallback should also receive the start date');
});

test('searchThreatIntelligence returns startDate in the response', async () => {
  const requester = createRequester({
    status: 200,
    body: JSON.stringify({
      totalResults: 1,
      vulnerabilities: [{ cve: mockCve }],
    }),
  });

  const db = createMockDb(false);

  const result = await searchThreatIntelligence(requester, db, config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
    startDate: '2024-01-01',
  });

  assert.equal(result.startDate, '2024-01-01');
});

test('searchThreatIntelligence skips CVEs with invalid CPEs instead of aborting the batch', async () => {
  const cveWithBadCpe = {
    id: 'CVE-2024-9999',
    published: '2024-01-01T00:00:00.000',
    lastModified: '2024-01-02T00:00:00.000',
    vulnStatus: 'Analyzed',
    descriptions: [{ lang: 'en', value: 'A vulnerability with invalid CPE data.' }],
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              { criteria: 'INVALID_CPE_STRING', vulnerable: true },
              {
                criteria: 'cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*',
                vulnerable: true,
              },
            ],
          },
        ],
      },
    ],
    metrics: {
      cvssMetricV31: [
        {
          cvssData: {
            version: '3.1',
            baseScore: 7.5,
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            baseSeverity: 'HIGH',
          },
        },
      ],
    },
    weaknesses: [],
    references: [],
  };

  const requester = createRequester({
    status: 200,
    body: JSON.stringify({
      totalResults: 1,
      vulnerabilities: [{ cve: cveWithBadCpe }],
    }),
  });

  const db = createMockDb(false);

  const result = await searchThreatIntelligence(requester, db, config, {
    vendor: 'apache',
    product: 'http_server',
    limit: 50,
  });

  assert.equal(result.hits.length, 1, 'should return the valid CVE despite the invalid CPE');
  assert.equal(result.hits[0].cve.cveId, 'CVE-2024-9999');
  assert.equal(
    result.hits[0].matchingCpes.includes('cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*'),
    true,
    'should match the valid CPE, not the invalid one',
  );
});

test('searchThreatIntelligence returns empty results when all CVEs have only invalid CPEs', async () => {
  const cveAllBadCpes = {
    id: 'CVE-2024-ALLBADCPE',
    published: '2024-01-01T00:00:00.000',
    lastModified: '2024-01-02T00:00:00.000',
    vulnStatus: 'Analyzed',
    descriptions: [{ lang: 'en', value: 'A vulnerability with only invalid CPE data.' }],
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [{ criteria: 'INVALID_CPE_STRING', vulnerable: true }],
          },
        ],
      },
    ],
    metrics: {
      cvssMetricV31: [
        {
          cvssData: {
            version: '3.1',
            baseScore: 7.5,
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            baseSeverity: 'HIGH',
          },
        },
      ],
    },
    weaknesses: [],
    references: [],
  };

  const requester = createRequester({
    status: 200,
    body: JSON.stringify({
      totalResults: 1,
      vulnerabilities: [{ cve: cveAllBadCpes }],
    }),
  });

  const db = createMockDb(false);

  const result = await searchThreatIntelligence(requester, db, config, {
    vendor: 'apache',
    product: 'http_server',
    limit: 50,
  });

  assert.equal(result.hits.length, 0, 'should return no hits when CPEs are invalid');
  assert.equal(result.totalResults, 0);
});

test('generateCpePrefixes produces valid CPE 2.3 match strings for all three parts', () => {
  const prefixes = generateCpePrefixes('microsoft', 'windows_10');
  assert.equal(prefixes.length, 3);
  assert.deepEqual(prefixes, [
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'cpe:2.3:h:microsoft:windows_10:*:*:*:*:*:*:*:*',
  ]);
});

test('generateCpePrefixes produces a string with exactly 13 fields (12 colons)', () => {
  const prefixes = generateCpePrefixes('apache', 'http_server');
  for (const prefix of prefixes) {
    const fields = prefix.split(':');
    assert.equal(fields.length, 13, `CPE should have 13 fields: ${prefix}`);
    assert.equal(fields[0], 'cpe');
    assert.equal(fields[1], '2.3');
  }
});

test('generateCpePrefixes escapes empty vendor/product as literal values', () => {
  const prefixes = generateCpePrefixes('vendor', 'product');
  for (const prefix of prefixes) {
    const fields = prefix.split(':');
    assert.equal(fields.length, 13);
    assert.equal(fields[0], 'cpe');
    assert.equal(fields[1], '2.3');
    assert.equal(fields[3], 'vendor');
    assert.equal(fields[4], 'product');
    for (let i = 5; i < 13; i++) {
      assert.equal(fields[i], '*', `field at index ${i} should be a wildcard`);
    }
  }
});

test('generateCpePrefixes escapes CPE components and keeps all prefixes bounded', () => {
  const prefixes = generateCpePrefixes('vendor:name', 'product*\u003cplus\u003e');
  assert.ok(prefixes.length >= 3 && prefixes.length <= 12);
  assert.ok(prefixes.every((prefix) => prefix.startsWith('cpe:2.3:')));
  assert.ok(prefixes.some((prefix) => prefix.includes('vendor\\:name')));
  assert.ok(prefixes.some((prefix) => prefix.includes('product\\*')));
});

test('keyword fallback excludes unrelated CVEs without alias or text corroboration', async () => {
  const unrelated = {
    ...mockCve,
    id: 'CVE-2024-9999',
    descriptions: [{ lang: 'en', value: 'An unrelated database vulnerability.' }],
    configurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:other:database:1:*:*:*:*:*:*:*', vulnerable: true }] }] }],
  };
  const requester = createRequester({ status: 200, body: JSON.stringify({ totalResults: 1, vulnerabilities: [{ cve: unrelated }] }) });
  const result = await searchThreatIntelligence(requester, createMockDb(), config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
  });
  assert.equal(result.hits.length, 0);
});

test('an empty upstream result set is reported as empty, not as an error', async () => {
  const requester = createRequester({
    status: 200,
    body: JSON.stringify({ totalResults: 0, vulnerabilities: [] }),
  });
  const result = await searchThreatIntelligence(requester, createMockDb(), config, {
    vendor: 'acme',
    product: 'nothing_here',
    limit: 50,
  });
  assert.equal(result.hits.length, 0);
  assert.equal(result.rateLimited, false);
});

test('all CPE lookups and the keyword fallback failing surfaces an upstream error', async () => {
  const requester = createRequester({ status: 404, body: '{"message":"not found"}' });
  await assert.rejects(
    () =>
      searchThreatIntelligence(requester, createMockDb(), config, {
        vendor: 'apache',
        product: 'log4j',
        limit: 50,
      }),
    (error: Error) => {
      assert.equal(error.name, 'ThreatSearchUpstreamError');
      assert.match(error.message, /NVD threat search failed/);
      return true;
    },
    'a total upstream failure must not masquerade as an empty result set',
  );
});

test('a failing CPE lookup recovers through the keyword fallback instead of returning nothing', async () => {
  const requester: Requester = async (url) =>
    url.includes('virtualMatchString')
      ? { status: 404, body: '{"message":"no such cpe"}', headers: {} }
      : {
          status: 200,
          body: JSON.stringify({ totalResults: 1, vulnerabilities: [{ cve: mockCve }] }),
          headers: {},
        };
  const result = await searchThreatIntelligence(requester, createMockDb(), config, {
    vendor: 'microsoft',
    product: 'windows_10',
    limit: 50,
  });
  assert.equal(result.hits.length, 1, 'the keyword fallback must still answer the query');
  assert.equal(result.hits[0].source, 'KEYWORD_FALLBACK');
});

test('an upstream 5xx on every path is an upstream error, never an empty result', async () => {
  const requester = createRequester({ status: 503, body: 'upstream unavailable' });
  await assert.rejects(
    () =>
      searchThreatIntelligence(requester, createMockDb(), config, {
        vendor: 'apache',
        product: 'tomcat',
        limit: 10,
      }),
    (error: Error) => error.name === 'ThreatSearchUpstreamError',
  );
});

test('rate limiting still wins over the upstream-failure classification', async () => {
  const requester = createRequester({ status: 429, body: '{}', headers: { 'retry-after': '30' } });
  const result = await searchThreatIntelligence(requester, createMockDb(), config, {
    vendor: 'apache',
    product: 'tomcat',
    limit: 10,
  });
  assert.equal(result.rateLimited, true, 'a 429 stays a rate-limit result, not an error');
  assert.equal(result.retryAfter, 30);
});
