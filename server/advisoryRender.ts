import type { Advisory, Finding, ReviewEdits } from '../src/types/index.ts';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import { formatDate } from '../src/utils/dateTime.ts';
import { stripGeneratedExecutiveSummaryMarkup } from '../src/utils/templateCompiler.ts';
import { mlComposeAdvisoryEmail } from './ml/integration';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#10b981',
  UNKNOWN: '#6b7280',
};
const SEVERITY_BADGE = (severity: string, suffix = '') => {
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
  const label = severity || 'UNKNOWN';
  const escapedLabel = label.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
  return `<span style="display:inline-block;padding:4px 10px;border-radius:4px;background:${color};color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">${escapedLabel}${suffix}</span>`;
};

/**
 * Validates that all required advisory fields needed by the email template
 * are populated. Called by renderAdvisory to prevent emails with empty
 * content from being queued for delivery.
 */
export function validateAdvisoryFields(advisory: Advisory): AdvisoryFieldValidation {
  const missingFields: string[] = [];
  if (!advisory.id || !advisory.id.trim()) missingFields.push('id');
  if (!advisory.title || !advisory.title.trim()) missingFields.push('title');
  if (!advisory.severity) missingFields.push('severity');
  if (!advisory.executiveSummary || !advisory.executiveSummary.trim())
    missingFields.push('executiveSummary');
  if (!advisory.remediationInstructions || !advisory.remediationInstructions.trim())
    missingFields.push('remediationInstructions');
  if (!advisory.affectedSystems || advisory.affectedSystems.length === 0)
    missingFields.push('affectedSystems');
  return { valid: missingFields.length === 0, missingFields };
}

export interface AdvisoryFieldValidation {
  valid: boolean;
  missingFields: string[];
}

/**
 * Renders the operator-managed advisory template for one advisory view.
 *
 * A digest is rendered from a recipient-specific advisory view (a subset of the
 * findings in the combined advisory), so the rendered HTML can never disclose a
 * finding that the recipient is not subscribed to.
 *
  * Throws if any required advisory field is empty, preventing emails with
  * missing content from being queued for delivery.
  *
  * `findings`, when provided, supplies each CVE's own severity and CVSS score
  * for the {{cve_details}} block. Without it, every CVE badge falls back to
  * the advisory's single aggregate severity (its highest-ranked finding),
  * which is correct for the overall advisory badge but misrepresents any
  * lower-severity CVE bundled alongside a higher one.
  */

/**
 * Feed-controlled URL guard for rendered advisory links. Vendor links come from
 * CVE feeds (not from operators), so a hostile record must not become a
 * `javascript:`/`data:` target inside the delivered email or PDF. Only http(s)
 * URLs without embedded credentials are renderable; anything else renders as
 * plain text.
 */
function safeHttpHref(value: string): string {
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return '';
    return url.href;
  } catch {
    return '';
  }
}

const SEVERITY_RANK: Record<string, number> = {
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};
function cveSeverity(cve: string, advisory: Advisory, findings?: Finding[]): string {
  const cveFindings = findings?.filter((f) => f.cveId === cve) || [];
  if (cveFindings.length) {
    return cveFindings.reduce(
      (current, f) =>
        (SEVERITY_RANK[f.cve.cvss.severity] || 0) > (SEVERITY_RANK[current] || 0) ? f.cve.cvss.severity : current,
      'UNKNOWN' as string,
    );
  }
  return advisory.severity || 'UNKNOWN';
}
function severityRank(cve: string, advisory: Advisory, findings?: Finding[]): number {
  return SEVERITY_RANK[cveSeverity(cve, advisory, findings)] || 0;
}

function versionRangeLabel(range?: Finding['cve']['versionRange']): string | undefined {
  if (!range) return undefined;
  const bounds = [
    range.versionStartIncluding ? `>= ${range.versionStartIncluding}` : '',
    range.versionStartExcluding ? `> ${range.versionStartExcluding}` : '',
    range.versionEndIncluding ? `<= ${range.versionEndIncluding}` : '',
    range.versionEndExcluding ? `< ${range.versionEndExcluding}` : '',
  ].filter(Boolean);
  return bounds.length ? bounds.join(' and ') : undefined;
}

function affectedVersionLabel(finding: Finding): string | undefined {
  const matchingCriteria = finding.cve.cpeMatchDetails?.filter(
    (detail) => detail.criteria === finding.matchedCpe,
  );
  const criteria = matchingCriteria?.length
    ? matchingCriteria
    : finding.cve.cpeMatchDetails?.length
      ? finding.cve.cpeMatchDetails
      : (finding.cve.cpeMatches || []).map((criteria) => ({ criteria, range: finding.cve.versionRange }));
  const versions = new Set<string>();
  for (const detail of criteria || []) {
    const parsed = parseCPE23(detail.criteria);
    if (parsed.isValid && parsed.version !== '*' && parsed.version !== '-') {
      versions.add(parsed.version);
      continue;
    }
    const range = versionRangeLabel(detail.range || finding.cve.versionRange);
    if (range) versions.add(range);
  }
  return versions.size ? [...versions].join('; ') : undefined;
}

function findingProductLabel(finding?: Finding): string {
  if (!finding) return 'Unavailable';
  const parsed = parseCPE23(finding.matchedCpe || '');
  const cpeVendor = parsed.isValid && !['*', '-'].includes(parsed.vendor) ? parsed.vendor : '';
  const cpeProduct = parsed.isValid && !['*', '-'].includes(parsed.product) ? parsed.product : '';
  const vendor = finding.matchedAssetVendor || cpeVendor;
  const product = finding.matchedAssetProduct || cpeProduct;
  if (vendor && product) return `${vendor} - ${product}`;
  return product || finding.matchedAssetName || 'Unavailable';
}

function formattedDate(value?: string | null): string {
  const date = formatDate(value);
  return date === '—' ? 'Unavailable' : date;
}

/**
 * True when the finding's measured match confidence is below certainty.
 *
 * Findings are never withheld for confidence: every correlation is dispatched.
 * The flag drives the in-finding notice that names the limitation and its
 * reason, so reduced confidence is communicated instead of being dropped.
 */
export function confidenceIsLimited(finding: Finding): boolean {
  const confidence = finding.confidence;
  return typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 100;
}

function confidencePercent(finding: Finding): string {
  const confidence = finding.confidence;
  return typeof confidence === 'number' && Number.isFinite(confidence)
    ? `${Math.round(confidence)}% match confidence`
    : '';
}

/**
 * Removes the machine-readable confidence suffix the pipeline appends to every
 * evidence string ("... (70% confidence)") so the notice does not repeat the
 * figure twice. Matching evidence is plain feed-derived text, never markup.
 */
function stripConfidenceEvidence(evidence?: string): string {
  return (evidence || '')
    .replace(/\s*\(\s*\d{1,3}% confidence\s*\)\s*$/i, '')
    .replace(/[\r\n\t]+/g, ' ')
    .trim();
}

export interface AdvisoryRenderOptions {
  /**
   * Pinned render instant.
   *
   * The template embeds a "Report Generated" timestamp. The same rendered HTML
   * drives both the email body and the PDF attachment, so the instant must be
   * supplied by the caller: rendering the body and the attachment separately
   * would stamp them a moment apart and make the attachment differ from the
   * email. Callers that render once may omit it.
   */
  generatedAt?: Date;
}

export function renderAdvisory(
  template: string,
  advisory: Advisory,
  findings?: Finding[],
  options: AdvisoryRenderOptions = {},
): string {
  const validation = validateAdvisoryFields(advisory);
  if (!validation.valid) {
    throw new Error(
      `Cannot render advisory email with empty required fields: ${validation.missingFields.join(', ')}`,
    );
  }
  const escape = (v: string) =>
    v.replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  const edits: ReviewEdits = advisory.edits || {};
  // ML-guided summary uses the actual finding mix. Remediation stays tied to
  // supplied vendor guidance and playbooks rather than model-selected claims.
  let composedSummary = advisory.executiveSummary;
  const composedRemediation =
    'Confirm affected-system and version applicability against current vendor guidance. Follow only documented remediation or playbook steps; patch availability is not assumed.';
  const operatorRemediationNote = advisory.remediationInstructions.trim()
    ? `<div style="margin:10px 0 0;padding:9px 11px;border:1px solid #e2e8f0;background:#f8fafc;font-size:12px;line-height:19px;color:#334155;"><strong>Operator-provided note (unverified):</strong> ${escape(advisory.remediationInstructions)}<br/>This note is not evidence that a patch or fix is available. Confirm its instructions against current vendor guidance before acting.</div>`
    : '';
  if (findings?.length) {
    try {
      const composed = mlComposeAdvisoryEmail(findings, advisory);
      if (!edits.customBodyOverride && composed.executiveSummary)
        composedSummary = composed.executiveSummary;
    } catch {
      // Rendering must never fail because the ML layer is unavailable.
    }
  }
  const productEntries = findings
    ? [...new Map(findings.map((finding) => {
        const name = findingProductLabel(finding);
        const versions = affectedVersionLabel(finding);
        const line = `${name}${versions ? ` | Affected versions: ${versions}` : ' | Version applicability: confirm with vendor'}`;
        return [line, line];
      })).values()]
    : advisory.affectedSystems;
  const remediationBlocks = (advisory.cveIds.length ? advisory.cveIds : ['Advisory']).map((cveId) => {
    const cveFindings = findings?.filter((finding) => finding.cveId === cveId) || [];
    const heading = cveId === 'Advisory'
      ? 'General remediation guidance'
      : `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">${escape(cveId)}</a>`;
    const targets = cveFindings.length ? cveFindings : [undefined];
    const targetGuidance = targets.map((finding) => {
      const remediation = finding?.cve.remediation;
      const actions = [...new Set([
        ...(remediation?.immediateActions || []),
        ...(remediation?.stepByStep || []),
      ].filter((action) => action.trim()))];
      const patchHref = safeHttpHref(remediation?.patchUrl || '');
      const vendorHref = safeHttpHref(remediation?.vendorAdvisoryRef || '');
      const targetLabel = finding ? findingProductLabel(finding) : 'the affected products listed above';
      const actionList = actions.length
        ? actions
        : [
            `Confirm the affected versions of ${targetLabel} against current vendor guidance for ${cveId}. ${patchHref || vendorHref ? 'Follow only remediation steps documented by the vendor after confirming applicability.' : 'No vendor patch or fix guidance is supplied for this finding, so availability must not be assumed.'}`,
            'Use documented compensating controls only where appropriate, and monitor for further vendor guidance.',
          ];
      const actionHtml = actionList
        .map((action) => `<li style="margin:0 0 5px;padding:0;">${escape(action)}</li>`)
        .join('');
      const workarounds = [...new Set(remediation?.workarounds || [])];
      const workaroundHtml = workarounds.length
        ? `<div style="margin:10px 0 0;"><strong>Workarounds</strong><ul style="margin:5px 0 0;padding-left:20px;">${workarounds.map((item) => `<li style="margin:0 0 5px;">${escape(item)}</li>`).join('')}</ul></div>`
        : '';
      const rollbackHtml = remediation?.rollbackPlan?.trim()
        ? `<p style="margin:10px 0 0;"><strong>Rollback:</strong> ${escape(remediation.rollbackPlan)}</p>`
        : '';
      const guidanceLinks = [
        patchHref
          ? `<a href="${escape(patchHref)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">Vendor patch</a>`
          : '',
        vendorHref
          ? `<a href="${escape(vendorHref)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">Security advisory</a>`
          : '',
      ].filter(Boolean);
      const versionLabel = finding ? affectedVersionLabel(finding) : undefined;
      const targetHeading = finding
        ? `<div style="margin:8px 0 5px;font-size:12px;line-height:18px;font-weight:700;color:#334155;">${escape(targetLabel)}${versionLabel ? ` · ${escape(versionLabel)}` : ''}</div>`
        : '';
      return `${targetHeading}<ul style="margin:0;padding-left:20px;font-size:12px;line-height:19px;color:#334155;">${actionHtml}</ul>${workaroundHtml}${rollbackHtml}${guidanceLinks.length ? `<div style="margin:9px 0 0;font-size:12px;line-height:19px;">${guidanceLinks.join(' <span style="color:#94a3b8;padding:0 5px;">|</span> ')}</div>` : ''}`;
    }).join('');
    return `<div style="margin:0 0 12px;padding:12px 14px;border:1px solid #e2e8f0;border-radius:4px;background:#ffffff;">
  <div style="margin:0 0 7px;font-size:13px;line-height:19px;font-weight:700;color:#0f172a;">${heading}</div>
  ${targetGuidance}
</div>`;
  }).join('');
  const values: Record<string, string> = {
    severity: advisory.severity,
    advisory_id: advisory.id,
    advisory_title: advisory.title,
    dispatch_date: (options.generatedAt ?? new Date()).toLocaleString('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }),
    executive_summary: escape(stripGeneratedExecutiveSummaryMarkup(composedSummary)),
    cve_ids: advisory.cveIds.join(', '),
    affected_systems: advisory.affectedSystems.join('\n'),
    affected_systems_html: advisory.affectedSystems
      .map((sys: string) => `<div style="margin:0 0 4px;padding-left:0;font-size:12px;line-height:18px;color:#334155;">${escape(sys)}</div>`)
      .join('\n'),
    vendor_products: productEntries.join('\n'),
    vendor_products_html: productEntries
      .map((entry) => `<div style="margin:0 0 8px;padding:0;font-size:12px;line-height:19px;color:#334155;">${escape(entry)}</div>`)
      .join('\n'),
    remediation_steps: `<p style="margin:0 0 10px;font-size:12px;line-height:19px;color:#334155;">${escape(composedRemediation)}</p>${remediationBlocks}${operatorRemediationNote}`,
    vendor_link: safeHttpHref(advisory.vendorLink || ''),
    remediation_link:
      safeHttpHref(
        findings?.find((f) => f.cve?.remediation?.patchUrl)?.cve?.remediation?.patchUrl || '',
      ),
    references_link:
      safeHttpHref(
        findings?.find((f) => f.cve?.remediation?.vendorAdvisoryRef)?.cve?.remediation?.vendorAdvisoryRef || '',
      ),
    cve_id_links: [...advisory.cveIds]
      .sort((a: string, b: string) => severityRank(b, advisory, findings) - severityRank(a, advisory, findings) || a.localeCompare(b))
      .map(
        (cve: string) =>
          `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank" rel="noopener noreferrer" style="display:inline-block;margin:0 8px 4px 0;color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">${escape(cve)}</a>`,
      )
      .join(', '),
    cve_details: [...advisory.cveIds]
      // CRITICAL -> HIGH -> MEDIUM -> LOW -> UNKNOWN; ties broken by CVE id so a
      // re-send of the same findings renders in a stable order.
      .sort((a: string, b: string) => severityRank(b, advisory, findings) - severityRank(a, advisory, findings) || a.localeCompare(b))
      .map((cve: string) => {
        // Multiple findings can share a CVE (one per matched asset); use the
        // highest-ranked severity among them so the badge never understates
        // risk for this specific CVE.
        const cveFindings = findings?.filter((f) => f.cveId === cve) || [];
        const ranks: Advisory['severity'][] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const severity = cveFindings.reduce(
          (current, f) =>
            ranks.indexOf(f.cve.cvss.severity) > ranks.indexOf(current) ? f.cve.cvss.severity : current,
          (cveFindings.length ? 'UNKNOWN' : advisory.severity) as Advisory['severity'],
        );
        const primary = cveFindings.find((f) => f.cve.cvss.severity === severity) || cveFindings[0];
        const score = primary?.cve.cvss.score;
        const kev = cveFindings.some((f) => f.cve.cisaKev?.isKev);
        // Only a real, parseable http(s) vendor reference is published. The old
        // fallback chain ended at `advisory.vendorLink`, which is a synthesized
        // value rather than a vendor advisory URL, so "View Source" could point
        // at nothing useful.
        const vendorHref = safeHttpHref(
          cveFindings.find((f) => f.cve.remediation?.vendorAdvisoryRef)?.cve.remediation?.vendorAdvisoryRef || '',
        );
        // The description is rendered as prose (clamped) rather than a bullet:
        // it is the substance of the entry, not an attribute of it.
        const rawDescription =
          cveFindings.find((f) => f.cve.description)?.cve.description || 'No vendor description published.';
        const description =
          rawDescription.length > 600 ? `${rawDescription.slice(0, 597).trimEnd()}…` : rawDescription;
        const colour = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
        const scoreLabel = typeof score === 'number' ? score.toFixed(1) : 'N/A';
        // Every finding is dispatched, including those the matching policy could
        // not confirm with full confidence. Rather than withholding them (which
        // silently lost real exposure), the advisory states the limitation on the
        // finding itself so the reader knows what still has to be verified.
        const lowConfidenceNote = (finding?: Finding) => {
          if (!finding || !confidenceIsLimited(finding)) return '';
          const confidenceLabel = confidencePercent(finding);
          const evidence = stripConfidenceEvidence(finding.matchingEvidence);
          return `<div style="margin:5px 0 0;padding:7px 9px;border-left:3px solid #b7791f;background:#fffbeb;font-size:11px;line-height:17px;color:#7c2d12;"><strong>Low confidence${confidenceLabel ? ` (${escape(confidenceLabel)})` : ''}:</strong> ${escape(evidence || 'Applicability could not be fully verified; confirm the affected version with the vendor before remediation.')}</div>`;
        };
        const productMetadata = (cveFindings.length ? cveFindings : [undefined])
          .map((finding) => {
            const productName = findingProductLabel(finding);
            const version = finding ? affectedVersionLabel(finding) || 'Unavailable; confirm with vendor' : 'Unavailable';
            return `<div style="margin:5px 0 0;font-size:11px;line-height:17px;color:#475569;"><strong>Product:</strong> ${escape(productName)} &nbsp; <strong>Affected version(s):</strong> ${escape(version)}<br/><strong>Published:</strong> ${escape(formattedDate(finding?.cve.publishedDate))} &nbsp; <strong>Last modified:</strong> ${escape(formattedDate(finding?.cve.modifiedDate))}</div>${lowConfidenceNote(finding)}`;
          })
          .join('');
        // NVD is the authoritative, always-available source for a CVE id; it is
        // the link the reader needs from the CVE ID itself.
        const nvdHref = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
        const sources = [`<a data-pdf-source="NVD" href="${nvdHref}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">NVD</a>`];
        if (vendorHref)
          sources.push(
            `<a data-pdf-source="Vendor advisory" href="${escape(vendorHref)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">Vendor advisory</a>`,
          );
        sources.push(
          `<a data-pdf-source="CISA KEV" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">CISA KEV</a>`,
        );
        return `<table class="vulnstream-pdf-card" data-pdf-cve="${escape(cve)}" data-pdf-severity="${escape(severity)}" data-pdf-score="${scoreLabel}" data-pdf-kev="${kev}" role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 16px;border-collapse:separate;border-spacing:0;background:#ffffff;">
  <tbody><tr>
    <td style="padding:14px;border:1px solid #e2e8f0;border-radius:4px;background:#ffffff;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
    <tr class="vulnstream-pdf-header">
      <td style="padding:0;vertical-align:top;">
        <div style="font-size:14px;font-weight:bold;color:#0f172a;line-height:20px;">
          <a href="${nvdHref}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">${escape(cve)}</a>
        </div>
      </td>
      <td width="1%" align="right" style="padding:0 0 0 12px;white-space:nowrap;vertical-align:top;">
        <span style="display:inline-block;background:${colour};color:#ffffff;padding:3px 9px;border-radius:4px;font-size:11px;font-weight:bold;letter-spacing:0.3px;">${escape(severity)} \u00b7 CVSS ${scoreLabel}</span>
        ${kev ? '<span style="display:inline-block;margin-left:6px;background:#7f1d1d;color:#ffffff;padding:3px 9px;border-radius:4px;font-size:11px;font-weight:bold;letter-spacing:0.3px;">KEV</span>' : ''}
      </td>
    </tr>
    <tr>
      <td colspan="2" style="padding:8px 0 0;font-size:12px;line-height:19px;color:#334155;text-align:left;">${escape(description)}</td>
    </tr>
    <tr>
      <td colspan="2" style="padding:6px 0 0;text-align:left;">${productMetadata}</td>
    </tr>
    <tr class="vulnstream-pdf-sources">
      <td colspan="2" style="padding:8px 0 0;font-size:11px;line-height:16px;color:#64748b;text-align:left;">Sources: ${sources.join(' <span style="color:#cbd5e1;">&middot;</span> ')}</td>
    </tr>
  </table></td>
  </tr></tbody>
</table>`;
      })
      .join('\n'),
    // Prose blocks instead of bullets: a numbered step list reads as an ordered
    // procedure and survives plain-text clients without a bullet glyph.
    mitigation_steps: `<div style="font-size:12px;line-height:20px;color:#334155;">
  <div style="margin:0 0 6px;"><strong>1.</strong>&nbsp; Confirm affected products and versions with current vendor guidance.</div>
  <div style="margin:0 0 6px;"><strong>2.</strong>&nbsp; Use vendor-documented workarounds or compensating controls only when appropriate.</div>
  <div style="margin:0;"><strong>3.</strong>&nbsp; Monitor affected services for relevant vendor updates and validate any remediation through change management.</div>
</div>`,
    recommended_actions: `<div style="font-size:12px;line-height:20px;color:#334155;">
  <div style="margin:0 0 6px;"><strong>1.</strong>&nbsp; Inventory all affected systems identified in this advisory.</div>
  <div style="margin:0 0 6px;"><strong>2.</strong>&nbsp; Confirm applicability and available remediation with the current vendor guidance.</div>
  <div style="margin:0;"><strong>3.</strong>&nbsp; Validate backup, restore, and operational functionality after any documented remediation.</div>
</div>`,
    audience_notice: edits.audienceNotice
      ? escape(edits.audienceNotice).replace(/\n/g, '<br/>')
      : 'This advisory is being distributed to all recipients per the EVERYONE delivery policy.',
     reviewer_comment: edits.reviewerComment
       ? `<strong>Reviewer note${edits.reviewerName ? ` by ${escape(edits.reviewerName)}` : ''}</strong> ${escape(edits.reviewerComment).replace(/\n/g, '<br/>')}`
       : '',
     severity_badge: SEVERITY_BADGE(advisory.severity),
     severity_header_badge: SEVERITY_BADGE(advisory.severity, ' SEVERITY'),
   };
  const rawHtmlTokens = new Set([
    'cve_id_links',
    'cve_details',
    'affected_systems_html',
    'vendor_products_html',
    'remediation_steps',
    'mitigation_steps',
    'recommended_actions',
    'severity_badge',
    'severity_header_badge',
  ]);
  let processed = template.replace(/\{\{#if\s+([a-z_]+)\}\}([\s\S]*?)\{\{\/if\}\}/g, (_, key, content) => {
    return values[key] && values[key].trim() ? content : '';
  });
  return processed.replace(/{{([a-z_]+)}}/g, (_, key) => {
    if (rawHtmlTokens.has(key)) return values[key] || '';
    return escape(values[key] || '');
  });
}
