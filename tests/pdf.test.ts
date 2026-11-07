import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { advisoryHtmlToText, renderAdvisoryPdf, closePdfRenderer } from '../server/pdf.ts';
import { renderAdvisory } from '../server/advisoryRender.ts';
import { advisoryFilename, timestampedAdvisoryFilename } from '../server/pdf.ts';
import { compileCustomizedTemplate, DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
import { DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { sendProviderEmail } from '../server/emailProviders.ts';
import type { Advisory, EmailConfiguration, Finding } from '../src/types/index.ts';
import { applyJobEdits, type Job } from '../server/delivery.ts';

test('advisory HTML conversion preserves readable content and skips executable/resource markup', () => {
  const text = advisoryHtmlToText(`<html><head><title>Ignored title</title><style>.secret{display:none}</style></head>
    <body><h1>CVE-2026-12345 advisory</h1><p>Patch the affected application.</p>
    <a href="https://vendor.example/advisory">Vendor guidance</a>
    <script>EXECUTABLE_SENTINEL</script><img src="https://tracker.example/pixel" alt="tracking pixel">
    <svg><text>SVG_SENTINEL</text></svg></body></html>`);
  assert.match(text, /CVE-2026-12345 advisory/i);
  assert.match(text, /Patch the affected application/);
  assert.match(text, /Vendor guidance/);
  assert.doesNotMatch(text, /Ignored title|secret|EXECUTABLE_SENTINEL|tracker\.example|SVG_SENTINEL/);
});

test('advisoryFilename uses the real advisory ID', () => {
  assert.equal(advisoryFilename('ADV-05Oct2026-A1B2C3D4'), 'ADV-05Oct2026-A1B2C3D4.pdf');
});

test('a document without an advisory ID is named with its timestamp', () => {
  assert.equal(
    timestampedAdvisoryFilename(new Date('2026-03-09T08:05:00Z'), 'UTC'),
    '09Mar20260805.pdf',
  );
});

const advisory = {
  id: 'ADV-05Oct2026-A1B2C3D4',
  title: 'Test vulnerability advisory',
  severity: 'CRITICAL',
  cveIds: ['CVE-2026-12345', 'CVE-2026-67890'],
  affectedSystems: ['web-01', 'db-02'],
  executiveSummary: 'A critical test vulnerability affects monitored systems.',
  remediationInstructions: 'Apply the vendor patch and verify inventory coverage.',
  vendorLink: 'https://example.com/advisory/2026-0001',
} as unknown as Advisory;

test('renderAdvisoryPdf renders matching clean cards, badges, metadata and links', async () => {
  const template = compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
  const findings = [
    {
      cveId: 'CVE-2026-12345',
      cve: {
        cvss: { severity: 'HIGH', score: 7.1 },
        description: 'High-severity finding description.',
        cisaKev: { isKev: false },
        remediation: { vendorAdvisoryRef: 'https://vendor.example/security/advisory' },
        cpeMatches: [],
      },
      matchedAssetVendor: 'Dell',
      matchedAssetProduct: 'OpenManage Enterprise',
      matchedAssetName: 'Dell OpenManage Enterprise',
    },
    {
      cveId: 'CVE-2026-67890',
      cve: {
        cvss: { severity: 'MEDIUM', score: 6.8 },
        description: 'Medium-severity finding description.',
        cisaKev: { isKev: false },
        remediation: {},
        cpeMatches: [],
      },
      matchedAssetVendor: 'Dell',
      matchedAssetProduct: 'OpenManage Enterprise',
      matchedAssetName: 'Dell OpenManage Enterprise',
    },
  ] as unknown as Finding[];
  const html = renderAdvisory(template, advisory, findings);
  assert.ok(html.includes('CVE-2026-12345'));
  assert.ok(!html.includes('{{advisory_id}}'));
  assert.match(template, />Advisory link<\/a>/);
  assert.match(html, /href="https:\/\/vendor\.example\/security\/advisory"[^>]*>Advisory link<\/a>/);
  assert.match(html, /<div style="margin:0 0 8px;padding:0;font-size:12px;line-height:19px;color:#334155;">/);
  const emailCards = [...html.matchAll(/<table class="vulnstream-pdf-card" data-pdf-cve="([^"]+)"/g)];
  assert.equal(emailCards.length, advisory.cveIds.length);
  assert.deepEqual(emailCards.map((card) => card[1]), advisory.cveIds);
  assert.ok(html.includes('margin:0 0 16px;border-collapse:separate'));
  assert.ok(html.includes('border:1px solid #e2e8f0;border-radius:4px'));
  assert.doesNotMatch(html, /data-pdf-accent|border-left:\s*0|<td width="4"/);
  assert.match(html, /Affected version\(s\):<\/strong> Unavailable; confirm with vendor/);
  assert.match(html, /Published:<\/strong> Unavailable/);
  assert.match(html, /Last modified:<\/strong> Unavailable/);
  const pdf = await renderAdvisoryPdf(html);
  try {
    assert.equal(Buffer.from(pdf).slice(0, 5).toString(), '%PDF-');
    assert.ok(pdf.length > 2000, 'PDF should contain rendered content');
    assert.ok(Buffer.from(pdf).toString('latin1').includes('https://vendor.example/security/advisory'), 'PDF keeps a clickable email vendor link');
  } finally {
    await closePdfRenderer();
  }
});

test('the PDF attachment contains the same low-confidence notice as the email', async () => {
  // The attachment is rendered from the exact HTML the recipient receives, so a
  // finding whose confidence is limited is annotated in both, not just one.
  const template = compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
  const limited = {
    id: 'f-limited',
    cveId: 'CVE-2026-55555',
    confidence: 70,
    matchingEvidence: 'Matched strict CPE 2.3 component tokens (70% confidence)',
    matchedAssetVendor: 'Acme',
    matchedAssetProduct: 'Widget',
    matchedAssetName: 'srv-1 (Acme Widget)',
    cve: {
      cveId: 'CVE-2026-55555',
      title: 'Acme widget flaw',
      description: 'Remote code execution in Acme widget.',
      publishedDate: '2026-01-01T00:00:00Z',
      modifiedDate: '2026-01-01T00:00:00Z',
      cvss: { severity: 'CRITICAL', score: 9.8 },
      cisaKev: { isKev: false },
      remediation: {},
      cpeMatches: [],
    },
  } as unknown as Finding;
  const view = { ...advisory, cveIds: ['CVE-2026-55555'], findingIds: ['f-limited'] };
  const html = renderAdvisory(template, view, [limited]);
  const text = advisoryHtmlToText(html);
  assert.match(text, /Low confidence/);
  assert.match(text, /70% match confidence/);
  assert.match(text, /Matched strict CPE 2\.3 component tokens/);
  const pdf = await renderAdvisoryPdf(html);
  await closePdfRenderer();
  assert.equal(Buffer.from(pdf).slice(0, 5).toString(), '%PDF-');
});

test('Chromium PDF renders final HTML without executing scripts or fetching remote resources', async () => {
  let requests = 0;
  const server = createServer((_request, response) => {
    requests++;
    response.writeHead(200, { 'content-type': 'text/plain' }).end('unexpected remote response');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const remoteOrigin = `http://127.0.0.1:${address.port}`;
  const html = `<html><head>
      <link rel="stylesheet" href="${remoteOrigin}/style.css">
      <script>fetch('${remoteOrigin}/script-fetch'); document.body.dataset.scriptExecuted='true';</script>
      <style>.remote{background-image:url('${remoteOrigin}/css-image')}</style>
    </head><body>
      <h1>Browser-rendered security advisory</h1>
      <div class="remote">No remote styling should load.</div>
      <img src="${remoteOrigin}/image.png">
      <a href="https://vendor.example/advisory">Vendor source</a>
      <a href="javascript:window.__badLinkExecuted=true">Unsafe script link</a>
      <script src="${remoteOrigin}/external-script.js"></script>
    </body></html>`;
  try {
    const pdf = await renderAdvisoryPdf(html);
    const pdfText = Buffer.from(pdf).toString('latin1');
    assert.equal(pdfText.slice(0, 5), '%PDF-');
    assert.ok(pdfText.includes('/Producer (Skia/PDF'), 'PDF is produced by Chromium print rendering');
    assert.ok(pdfText.includes('https://vendor.example/advisory'), 'safe source links remain clickable in PDF');
    assert.equal(requests, 0, 'scripts and remote resource requests are blocked');
  } finally {
    await closePdfRenderer();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test('rendered advisory PDF is attached to provider messages', async () => {
  const template = compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
  const html = renderAdvisory(template, advisory);
  const pdf = await renderAdvisoryPdf(html);
  const attachment = {
    filename: advisoryFilename('ADV-05Oct2026-A1B2C3D4'),
    content: Buffer.from(pdf),
    contentType: 'application/pdf' as const,
  };
  const base64 = attachment.content.toString('base64');
  const config: EmailConfiguration = { ...DEFAULT_EMAIL_CONFIG, provider: 'SENDGRID', fromEmail: 'security@example.invalid' };
  const job = {
    id: 'test-job',
    dedupe_key: 'test',
    channel: 'email',
    target_id: 'recipient',
    advisory_id: 'ADV-05Oct2026-A1B2C3D4',
    attempts: 1,
    lock_token: 'test',
    payload: { subject: 'Security notice', text: 'see html', html, recipientEmail: 'recipient@example.invalid', cveIds: ['CVE-2026-12345'] },
  };
  let capturedBody: string | undefined;
  await sendProviderEmail(
    config,
    'token',
    job as any,
    async (_url, options) => {
      capturedBody = options?.body;
      return { status: 202, headers: { 'x-message-id': 'id' }, body: '' };
    },
false,
      [attachment],
    );
  await closePdfRenderer();

  assert.ok(capturedBody);
  const payload = JSON.parse(capturedBody!);
  assert.equal(payload.attachments[0].type, 'application/pdf');
  assert.equal(payload.attachments[0].filename, 'ADV-05Oct2026-A1B2C3D4.pdf');
  assert.equal(payload.attachments[0].disposition, 'attachment');
  assert.equal(payload.attachments[0].content, base64);
  assert.ok(base64.length > 1000);
});

/**
 * The PDF attachment must be built from the *edited* body.
 *
 * `buildPdfAttachment` used to render `job.payload.html` directly. An operator
 * editing an email in the Action Center (notice, reviewer comment, or a full
 * body override) therefore shipped a corrected email whose attachment still
 * showed the original text. The sender normalises through `applyJobEdits`, so
 * this asserts the helper the attachment renderer relies on stays lossless and
 * idempotent — the same contract the transport path depends on.
 */
test('PDF input is derived from the edited email body, not the queued template', () => {
  const original = '<html><body><p>Original advisory body</p></body></html>';
  const edits = {
    audienceNotice: 'Patched on the DMZ cluster already.',
    reviewerComment: 'Validated by the on-call engineer.',
    reviewerName: 'Ops',
    customBodyOverride: '<html><body><p>Corrected advisory body</p></body></html>',
  };

  const edited = applyJobEdits({
    id: 'job-1',
    dedupe_key: 'dedupe-1',
    channel: 'email',
    target_id: 'recipient-1',
    advisory_id: 'ADV-TEST',
    payload: { recipientEmail: 'sec@example.com', subject: 'Subject', text: 'text', cveIds: [], html: original },
    attempts: 0,
    lock_token: 'token',
    edits,
  } as Job);

  assert.match(edited.payload.html ?? '', /Corrected advisory body/);
  // The attachment renderer receives `applyJobEdits(job).payload.html`; the
  // unedited template must not be what reaches it.
  assert.notEqual(edited.payload.html, original);

  // Idempotent: re-applying the same edits must not duplicate the notice/comment
  // blocks, which would otherwise appear twice in the rendered PDF.
  const again = applyJobEdits(edited);
  assert.equal(again.payload.html, edited.payload.html);
});
