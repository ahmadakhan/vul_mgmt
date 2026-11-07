import type { Advisory, Finding } from '../src/types/index.ts';
import { stripGeneratedExecutiveSummaryMarkup } from '../src/utils/templateCompiler.ts';

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, ch =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);

const stripCrlf = (value: string) => value.replace(/[\r\n]/g, ' ');

export interface AdvisoryEmailOptions {
  findings?: Finding[];
}

/** Advisory IDs carry the configured prefix and remain stable on retries/resends. */
export function advisoryEmail(
  advisory: Advisory,
  html?: string,
  detailLines?: string[],
  options?: AdvisoryEmailOptions,
) {
  const safeId = stripCrlf(advisory.id);
  const safeSeverity = stripCrlf(advisory.severity);
  const safeTitle = stripCrlf(advisory.title);
  const escapedId = escapeHtml(advisory.id);
  if (html !== undefined && !html.includes(escapedId)) {
    const identity = `<p style="font-family:Arial,sans-serif;font-size:12px;color:#52525b;padding:12px 16px;">Advisory ID: <strong>${escapedId}</strong></p>`;
    html = /<body\b[^>]*>/i.test(html)
      ? html.replace(/<body\b[^>]*>/i, match => match + identity)
      : identity + html;
  }
  const details =
    detailLines && detailLines.length
      ? `\n\nFindings:\n${detailLines.map(stripCrlf).join('\n')}`
      : '';
  const findingsSection =
    options?.findings && options.findings.length
      ? `\n\nAffected Assets:\n${[
          ...new Set(
            options.findings.map(f => `${f.matchedAssetName}${f.matchedAssetVendor ? ` (${f.matchedAssetVendor})` : ''}`),
          ),
        ].join('\n')}`
      : '';
  return {
    subject: `[${safeId}] [${safeSeverity}] ${safeTitle}`,
    text: `Advisory ID: ${advisory.id}
Advisory Title: ${advisory.title}
Severity: ${advisory.severity}
Created: ${advisory.createdDate}

CVE IDs:
${advisory.cveIds.join('\n')}

Executive Summary:
${stripGeneratedExecutiveSummaryMarkup(advisory.executiveSummary)}

Affected Systems:${findingsSection}
${advisory.affectedSystems.join('\n')}

${details}
Remediation Instructions:
${advisory.remediationInstructions}${
      advisory.vendorLink ? `\n\nVendor Advisory: ${advisory.vendorLink}` : ''
    }`,
    html,
  };
}
