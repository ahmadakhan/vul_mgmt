import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { Advisory, EmailConfiguration, Finding } from '../src/types/index.ts';
import type { Job } from '../server/delivery.ts';
import { sendProviderEmail } from '../server/emailProviders.ts';
import {
  HTML_ATTACHMENT_MAX_BYTES,
  deliveryHtmlIsAttachable,
  htmlAttachmentIsAttachable,
  renderFindingsDocument,
  resolveAdvisoryTemplate,
} from '../server/deliveryDocument.ts';
import { DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION, compileCustomizedTemplate } from '../src/utils/templateCompiler.ts';
import type { Requester } from '../server/network.ts';

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                    */
/* -------------------------------------------------------------------------- */

const finding = (overrides: Partial<Finding> & { id: string; cveId: string }): Finding =>
  ({
    matchedAssetId: `asset-${overrides.id}`,
    matchedAssetName: 'server-1 (acme widget)',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'widget',
    matchedCpe: 'cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*',
    matchingMethod: 'STRICT_CPE_INTERVAL',
    matchingEvidence: 'Matched strict CPE 2.3 component tokens (70% confidence)',
    confidence: 70,
    notificationStatus: 'REVIEW_REQUIRED',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    reviewNotifiedAt: null,
    exploitRisk: 'NONE',
    timeline: [],
    cve: {
      cveId: overrides.cveId,
      title: 'Acme widget flaw',
      description: 'A flaw in the Acme widget allows remote code execution.',
      publishedDate: '2026-01-01T00:00:00Z',
      modifiedDate: '2026-01-02T00:00:00Z',
      cvss: { version: '3.1', score: 9.1, vector: 'AV:N/AC:L', severity: 'CRITICAL' },
      cwe: [],
      cpeMatches: ['cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*'],
      epss: { score: 0.4, percentile: 90 },
      cisaKev: { inKev: false, dueDate: null, cveNotes: '', isKev: false },
      exploitStatus: 'None',
      remediation: { play: [], nextSteps: [], vendorAdvisoryRef: 'https://vendor.example/advisory' },
      sourceFeeds: ['NVD'],
    },
    ...overrides,
  }) as unknown as Finding;

const advisory: Advisory = {
  id: 'ADV-TEST',
  title: 'Security finding notification',
  severity: 'CRITICAL',
  cveIds: [],
  findingIds: [],
  createdDate: '2026-01-01T00:00:00Z',
  deliveryStatus: 'PENDING',
  recipientCount: 0,
  executiveSummary: 'summary',
  remediationInstructions: 'patch',
  vendorLink: '',
  affectedSystems: ['server-1 (acme widget)'],
  isDigestBatch: true,
};

// The consolidated path lists every finding's CVE on the advisory; the per-CVE card (and its
// low-confidence note) renders from that list, so the fixture must do the same.
const withCves = (findings: Finding[]): Advisory => ({
  ...advisory,
  cveIds: [...new Set(findings.map((item) => item.cveId))],
});

const operatorTemplate = compileCustomizedTemplate({
  ...DEFAULT_TEMPLATE_CUSTOMIZATION,
  headerBg: '#123456',
  badgeStampText: 'ACME SOC',
});

/* -------------------------------------------------------------------------- */
/* Provider attachments                                                        */
/* -------------------------------------------------------------------------- */

const providerJob = (html: string): Job =>
  ({
    id: randomUUID(),
    payload: { subject: 'Subject', text: 'Text', html, recipientEmail: 'soc@example.com', cveIds: [] },
  }) as unknown as Job;

const capture = (reply: { status: number; headers?: Record<string, string>; body: string }) => {
  const sent: { url: string; body: any }[] = [];
  const request: Requester = async (url, options) => {
    sent.push({ url, body: JSON.parse(String(options?.body)) });
    return { status: reply.status, headers: reply.headers ?? {}, body: reply.body };
  };
  return { sent, request };
};

const SAMPLE_HTML = '<!doctype html><html><body style="background:#123456"><h1>Findings</h1></body></html>';
const attachment = {
  filename: 'FINDINGS-ABC.html',
  content: Buffer.from(SAMPLE_HTML, 'utf8'),
  contentType: 'text/html; charset=utf-8',
};

test('Mailjet receives the HTML attachment under its documented field names', async () => {
  const { sent, request } = capture({
    status: 200,
    body: JSON.stringify({ Messages: [{ Status: 'success', To: [{ Email: 'soc@example.com', MessageID: '99' }] }] }),
  });
  const config: EmailConfiguration = {
    ...DEFAULT_EMAIL_CONFIG,
    provider: 'MAILJET_API',
    fromEmail: 'alerts@example.com',
    apiKey: 'public',
    mailjetApiSecret: 'private',
  };
  await sendProviderEmail(config, 'public', providerJob(SAMPLE_HTML), request, false, [attachment]);
  const [file] = sent[0].body.Messages[0].Attachments;
  // Mailjet's v3.1 schema is `Filename`; `FileName` is not recognised.
  assert.deepEqual(Object.keys(file).sort(), ['Base64Content', 'ContentType', 'Filename']);
  assert.equal(file.Filename, 'FINDINGS-ABC.html');
  assert.equal(file.ContentType, 'text/html; charset=utf-8');
  assert.equal(Buffer.from(file.Base64Content, 'base64').toString('utf8'), SAMPLE_HTML);
  assert.equal(sent[0].body.Messages[0].HTMLPart, SAMPLE_HTML, 'the attachment is the body, byte for byte');
});

test('SendGrid and Postmark attachments carry the exact HTML under their own schemas', async () => {
  const sendgrid = capture({ status: 202, headers: { 'x-message-id': 'sg-1' }, body: '' });
  await sendProviderEmail(
    { ...DEFAULT_EMAIL_CONFIG, provider: 'SENDGRID', fromEmail: 'alerts@example.com', apiKey: 'k' },
    'k',
    providerJob(SAMPLE_HTML),
    sendgrid.request,
    false,
    [attachment],
  );
  const sg = sendgrid.sent[0].body.attachments[0];
  assert.equal(sg.filename, 'FINDINGS-ABC.html');
  assert.equal(sg.type, 'text/html; charset=utf-8');
  assert.equal(sg.disposition, 'attachment');
  assert.equal(Buffer.from(sg.content, 'base64').toString('utf8'), SAMPLE_HTML);

  const postmark = capture({ status: 200, body: JSON.stringify({ ErrorCode: 0, MessageID: 'pm-1' }) });
  await sendProviderEmail(
    { ...DEFAULT_EMAIL_CONFIG, provider: 'POSTMARK', fromEmail: 'alerts@example.com', apiKey: 'k' },
    'k',
    providerJob(SAMPLE_HTML),
    postmark.request,
    false,
    [attachment],
  );
  const pm = postmark.sent[0].body.Attachments[0];
  assert.equal(pm.Name, 'FINDINGS-ABC.html');
  assert.equal(pm.ContentType, 'text/html; charset=utf-8');
  assert.equal(Buffer.from(pm.Content, 'base64').toString('utf8'), SAMPLE_HTML);
});

/* -------------------------------------------------------------------------- */
/* Document fidelity                                                           */
/* -------------------------------------------------------------------------- */

test('the operator template wins: custom template, then customization, then default', () => {
  const custom = '<html><body>custom {{marker}}</body></html>';
  assert.equal(resolveAdvisoryTemplate({ customAdvisoryTemplate: custom }), custom);
  assert.equal(
    resolveAdvisoryTemplate({ customAdvisoryTemplate: '   ', templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION }),
    compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION),
    'a blank custom template falls through',
  );
  assert.equal(
    resolveAdvisoryTemplate({ templateCustomization: { ...DEFAULT_TEMPLATE_CUSTOMIZATION, headerBg: '#123456' } }),
    compileCustomizedTemplate({ ...DEFAULT_TEMPLATE_CUSTOMIZATION, headerBg: '#123456' }),
  );
  assert.equal(resolveAdvisoryTemplate(undefined), compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION));
});

test('a findings document renders from the operator template, not the built-in default', () => {
  const findings = [finding({ id: 'f1', cveId: 'CVE-2026-10001' })];
  const generatedAt = new Date('2026-01-01T12:00:00Z');
  const branded = renderFindingsDocument({ advisory: withCves(findings), findings, generatedAt, template: operatorTemplate });
  const plain = renderFindingsDocument({ advisory: withCves(findings), findings, generatedAt });
  assert.ok(branded.html.includes('#123456'));
  assert.ok(branded.html.includes('ACME SOC'));
  assert.ok(!plain.html.includes('ACME SOC'));
});

test('the plain-text part states each low-confidence finding and its reason', () => {
  const low = finding({
    id: 'f1',
    cveId: 'CVE-2026-10001',
    confidence: 70,
    matchingEvidence: 'Version range could not be verified (70% confidence)',
  });
  const sure = finding({ id: 'f2', cveId: 'CVE-2026-10002', confidence: 100, matchingEvidence: 'Exact CPE match' });
  const generatedAt = new Date('2026-01-01T12:00:00Z');
  const mixed = renderFindingsDocument({ advisory: withCves([low, sure]), findings: [low, sure], generatedAt });
  assert.match(mixed.text, /Limited confidence/);
  assert.match(mixed.text, /CVE-2026-10001 \| server-1 \(acme widget\) \| match confidence 70% \| Version range could not be verified/);
  assert.ok(!/CVE-2026-10002 \|[^\n]*match confidence/.test(mixed.text), 'confident findings are not flagged');
  // The HTML says the same thing the text says.
  assert.match(mixed.html, /Low confidence/);
  assert.match(mixed.html, /Version range could not be verified/);
  const confidentOnly = renderFindingsDocument({ advisory: withCves([sure]), findings: [sure], generatedAt });
  assert.ok(!confidentOnly.text.includes('Limited confidence'));
});

test('the HTML attachment has its own ceiling, independent of the PDF layout limit', () => {
  const html = `<html>${'x'.repeat(3_000_000)}</html>`;
  assert.equal(deliveryHtmlIsAttachable(html), false, 'too large for the PDF renderer');
  assert.equal(htmlAttachmentIsAttachable(html), true, 'still attachable as a file');
  assert.equal(htmlAttachmentIsAttachable('x'.repeat(HTML_ATTACHMENT_MAX_BYTES + 1)), false);
  assert.equal(htmlAttachmentIsAttachable(''), false);
  assert.equal(htmlAttachmentIsAttachable(undefined), false);
});