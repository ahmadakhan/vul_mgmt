import type { Advisory, Finding, TemplateCustomization } from '../src/types/index.ts';
import {
  DEFAULT_TEMPLATE_CUSTOMIZATION,
  compileCustomizedTemplate,
} from '../src/utils/templateCompiler.ts';
import { confidenceIsLimited, renderAdvisory } from './advisoryRender.ts';
import { advisoryEmail } from './advisoryEmail.ts';
import { mlComposeAdvisoryEmail } from './ml/integration.ts';
import { PDF_MAX_HTML_BYTES } from './pdf.ts';

/**
 * Canonical delivery document builder.
 *
 * Every finding email is rendered by *this* function and by nothing else, and
 * the PDF attachment is generated from its `html` output. That single-build
 * contract is what makes "the attachment is the email" a structural guarantee
 * rather than a convention: header colours, severity badges, CVE cards,
 * remediation blocks and the operator-provided note are produced once and used
 * by both transports.
 *
 * Two invariants make the attachment byte-identical to the body:
 *  - `generatedAt` is supplied by the caller. The template embeds a
 *    "Report Generated" timestamp; rendering the body and the attachment at two
 *    different instants would make them differ by a second, so the timestamp is
 *    pinned once per delivery and reused for the attachment render.
 *  - `renderFindingsDocument` returns the exact `html` that was attached to the
 *    payload, so a caller can never attach a document rendered from different
 *    findings than the ones described in the body.
 */

/**
 * Max rendered HTML size accepted by the PDF renderer.
 *
 * Imported from the renderer rather than duplicated so the delivery gate and the
 * renderer can never disagree about what is attachable.
 */
export const DELIVERY_HTML_MAX_BYTES = PDF_MAX_HTML_BYTES;

export interface DeliveryDocument {
  subject: string;
  text: string;
  html: string;
  /** The instant embedded in the document, pinned for attachment rendering. */
  generatedAt: Date;
}

const uniqueSorted = (values: string[]) => [...new Set(values.filter(Boolean))].sort();

const SEVERITY_RANK: Record<string, number> = {
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const highestSeverity = (findings: Finding[]): Advisory['severity'] =>
  findings.reduce(
    (severity, finding) =>
      (SEVERITY_RANK[finding.cve?.cvss?.severity] ?? 0) > (SEVERITY_RANK[severity] ?? 0)
        ? finding.cve.cvss.severity
        : severity,
    'UNKNOWN' as Advisory['severity'],
  );

const isLowConfidence = (finding: Finding): boolean => confidenceIsLimited(finding);

/**
 * Single-finding detail line used by the plain-text body. Held findings carry
 * their reason so the text alternative also states why confidence is limited.
 */
export const deliveryFindingDetail = (finding: Finding) =>
  `${finding.cveId} | ${finding.cve?.cvss?.severity ?? 'UNKNOWN'}${finding.cve?.cisaKev?.isKev ? ' | CISA KEV' : ''} | ${finding.matchedAssetName}`;

/**
 * Builds the recipient-specific advisory view for one delivery.
 *
 * The view is derived from the findings the recipient is actually receiving and
 * never from the union advisory, so a digest can never disclose a finding the
 * recipient is not subscribed to.
 */
export function deliveryAdvisoryView(original: Advisory, findings: Finding[]): Advisory {
  const links = uniqueSorted(
    findings.flatMap((finding) => [
      finding.cve?.remediation?.vendorAdvisoryRef || '',
      finding.cve?.remediation?.patchUrl || '',
    ]),
  );
  let composed: {
    subject?: string;
    executiveSummary: string;
    remediationInstructions: string;
  } = {
    executiveSummary: original.executiveSummary,
    remediationInstructions: original.remediationInstructions,
  };
  try {
    composed = mlComposeAdvisoryEmail(findings, original);
  } catch {
    // Rendering must never fail because the composition layer is unavailable.
  }
  return {
    ...original,
    severity: highestSeverity(findings),
    title: composed.subject || original.title,
    cveIds: uniqueSorted(findings.map((finding) => finding.cveId)),
    findingIds: findings.map((finding) => finding.id),
    affectedSystems: uniqueSorted(findings.map((finding) => finding.matchedAssetName)),
    executiveSummary: composed.executiveSummary || original.executiveSummary,
    remediationInstructions: composed.remediationInstructions || original.remediationInstructions,
    vendorLink: links[0] || '',
    isDigestBatch: findings.length > 1 ? true : original.isDigestBatch,
  };
}

/** The operator's saved template record (`records` kind `template`, id `main`). */
export interface SavedTemplateRecord {
  templateCustomization?: TemplateCustomization;
  /** A hand-authored advisory template that replaces the generated layout. */
  customAdvisoryTemplate?: string | null;
}

/**
 * Resolves the compiled advisory template the operator designed.
 *
 * This is the same precedence the application state uses (`customAdvisoryTemplate`
 * first, otherwise the compiled customization, otherwise the product default),
 * so a delivered email is rendered from the template the editor previews. The
 * consolidated finding path previously rendered from the built-in default, which
 * made real emails differ from the preview in layout, colours and branding.
 */
export function resolveAdvisoryTemplate(record?: SavedTemplateRecord | null): string {
  const custom = record?.customAdvisoryTemplate;
  if (typeof custom === 'string' && custom.trim()) return custom;
  return compileCustomizedTemplate(record?.templateCustomization ?? DEFAULT_TEMPLATE_CUSTOMIZATION);
}

export interface DeliveryDocumentInput {
  /** Advisory metadata for this recipient's view. */
  advisory: Advisory;
  /** Findings carried by this delivery, in the order they should render. */
  findings: Finding[];
  /**
   * Already-compiled advisory template (see `resolveAdvisoryTemplate`). Takes
   * precedence over `templateCustomization` so callers that have the operator's
   * saved template render from it.
   */
  template?: string;
  /** Operator-managed template customization used for the HTML body. */
  templateCustomization?: TemplateCustomization;
  /** Pinned render instant; one value per delivery. */
  generatedAt?: Date;
}

/**
 * Builds the one document used for an email body and its attachments.
 *
 * The text alternative carries the same limited-confidence notices as the HTML,
 * each with its reason, so a plain-text client is told exactly what the HTML
 * reader is told.
 */
export function renderFindingsDocument(input: DeliveryDocumentInput): DeliveryDocument {
  const { advisory, findings } = input;
  const generatedAt = input.generatedAt ?? new Date();
  const template =
    input.template ?? compileCustomizedTemplate(input.templateCustomization ?? DEFAULT_TEMPLATE_CUSTOMIZATION);
  const html = renderAdvisory(template, advisory, findings, { generatedAt });
  const email = advisoryEmail(advisory, html, findings.map(deliveryFindingDetail), { findings });
  const limited = limitedConfidenceLines(findings);
  const text = limited.length ? `${email.text}\n\n${limited.join('\n')}` : email.text;
  return { ...email, text, html: email.html ?? html, generatedAt };
}

export interface PlainTextSection {
  heading: string;
  lines: string[];
}

/**
 * Plain-text companion for the consolidated digest.
 *
 * The HTML body is the authoritative document; this is its text alternative for
 * clients that do not render HTML. It is generated from the same findings and the
 * same view so the two can never describe different sets.
 */
export function renderFindingsText(
  advisory: Advisory,
  findings: Finding[],
  sections: PlainTextSection[] = [],
): string {
  const lines: string[] = [
    `Advisory ID: ${advisory.id}`,
    `Advisory Title: ${advisory.title}`,
    `Severity: ${advisory.severity}`,
    `Created: ${advisory.createdDate}`,
  ];
  for (const section of sections) if (section.lines.length) lines.push('', `${section.heading}:`, ...section.lines);
  const limited = limitedConfidenceLines(findings);
  if (limited.length) lines.push('', ...limited);
  lines.push(
    '',
    'CVE IDs:',
    ...advisory.cveIds,
    '',
    'Executive Summary:',
    advisory.executiveSummary,
    '',
    'Affected Systems:',
    ...advisory.affectedSystems,
    '',
    'Remediation Instructions:',
    advisory.remediationInstructions,
  );
  if (advisory.vendorLink) lines.push('', `Vendor Advisory: ${advisory.vendorLink}`);
  return lines.join('\n');
}

const stripLine = (value: string | undefined) =>
  (value || '').replace(/[\r\n\t]+/g, ' ').replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '').trim();

/**
 * Plain-text notice for findings whose match confidence is limited: the heading
 * followed by one line per finding with its confidence and the reason. Empty when
 * every finding is fully confident. Shared by every text alternative so the
 * single-document and digest paths cannot word it differently.
 */
function limitedConfidenceLines(findings: readonly Finding[]): string[] {
  const limited = findings.filter(isLowConfidence);
  if (!limited.length) return [];
  return [
    'Limited confidence (confirm applicability before remediation):',
    ...limited.map(
      (finding) =>
        `- ${finding.cveId} | ${finding.matchedAssetName} | ${confidenceLabel(finding)} | ${
          stripLine(finding.matchingEvidence) || 'Applicability could not be fully verified'
        }`,
    ),
  ];
}

const confidenceLabel = (finding: Finding) =>
  typeof finding.confidence === 'number' && Number.isFinite(finding.confidence)
    ? `match confidence ${Math.round(finding.confidence)}%`
    : 'match confidence not available';

export { isLowConfidence as findingHasLimitedConfidence };

/**
 * True when a rendered document is small enough to attach.
 *
 * The PDF renderer rejects oversized HTML, and an oversized body would fail the
 * whole delivery. Callers use this to skip the attachment (degrading to
 * HTML-only) instead of failing the email.
 */
export const deliveryHtmlIsAttachable = (html: string | undefined): html is string =>
  typeof html === 'string' &&
  html.length > 0 &&
  Buffer.byteLength(html, 'utf8') <= DELIVERY_HTML_MAX_BYTES;

/**
 * Size ceiling for attaching the HTML document itself.
 *
 * The PDF renderer's 2 MB limit exists because Chromium has to lay the page out;
 * an HTML attachment is just the bytes of the body, so tying it to that limit
 * silently dropped the attachment for large digests (roughly 700+ findings). The
 * ceiling is still bounded because the message carries the body, the attachment
 * (base64, +33%) and optionally a PDF, and common providers reject a message
 * above about 15 MB in total.
 */
export const HTML_ATTACHMENT_MAX_BYTES = 4_000_000;

/** True when the exact email HTML can be attached as a file. */
export const htmlAttachmentIsAttachable = (html: string | undefined): html is string =>
  typeof html === 'string' &&
  html.length > 0 &&
  Buffer.byteLength(html, 'utf8') <= HTML_ATTACHMENT_MAX_BYTES;
