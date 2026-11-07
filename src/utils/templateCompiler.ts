import { TemplateCustomization } from '../types/index.ts';
import { resolveTimezone, utcOffsetLabel } from './dateTime.ts';

export const DEFAULT_TEMPLATE_CUSTOMIZATION: TemplateCustomization = {
  fontFamily: 'sans',
  fontColor: '#334155',
  headingColor: '#0f172a',
  accentColor: '#dc2626',
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
};

export function getFontFamilyCss(family: TemplateCustomization['fontFamily']): string {
  switch (family) {
    case 'mono':
      return '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';
    case 'serif':
      return 'Georgia, Cambria, "Times New Roman", Times, serif';
    case 'system':
      return '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';
    case 'sans':
    default:
      return '"Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
  }
}

export function compileCustomizedTemplate(config: TemplateCustomization): string {
  // Customization fields are text/CSS values, never arbitrary HTML or CSS.
  config = { ...DEFAULT_TEMPLATE_CUSTOMIZATION, ...config };
  for (const key of [
    'fontColor',
    'headingColor',
    'accentColor',
    'canvasBg',
    'cardBg',
    'headerBg',
    'badgeStampColor',
  ] as const) {
    if (!/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(config[key]))
      config[key] = DEFAULT_TEMPLATE_CUSTOMIZATION[key];
  }
  if (!['solid', 'dashed', 'none'].includes(config.borderStyle)) config.borderStyle = 'solid';
  if (!/^\d{1,3}(?:px|rem|%)$/.test(config.borderRadius)) config.borderRadius = '12px';
  const escapeHtml = (value: string) =>
    String(value).replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  config.badgeStampText = escapeHtml(config.badgeStampText);
  config.classificationText = escapeHtml(config.classificationText);
  const fontCss = getFontFamilyCss(config.fontFamily);

  const headerHex = config.headerBg.slice(1);
  const expanded = headerHex.length === 3 ? [...headerHex].map((ch) => ch + ch).join('') : headerHex;
  const luminance = [0, 2, 4]
    .map((offset) => parseInt(expanded.slice(offset, offset + 2), 16) / 255)
    .map((channel) => (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
    .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
  const headerText = luminance > 0.179 ? '#0f172a' : '#ffffff';
  const headerMuted = luminance > 0.179 ? '#334155' : '#cbd5e1';
  const stampHtml = config.showStamp
    ? `<p style="margin:0 0 12px;font-size:11px;line-height:18px;letter-spacing:1.5px;font-weight:700;color:${config.badgeStampColor};">${config.badgeStampText}</p>`
    : '';
  const classificationBanner = config.showClassificationBanner
    ? `<tr><td style="padding:12px 28px;background:${config.canvasBg};color:${config.fontColor};font-size:10px;line-height:16px;letter-spacing:1px;text-align:center;">${config.classificationText}</td></tr>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<title>Security Advisory</title>

<style>
  body,table,td,a { -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; }
  table,td { mso-table-lspace:0pt; mso-table-rspace:0pt; }
  table { border-collapse:collapse; }
  a { overflow-wrap:anywhere; word-break:break-word; }
  ul { margin:0; padding-left:20px; }
  body{
    margin:0;
    padding:0;
    background:${config.canvasBg};
    font-family:${escapeHtml(fontCss)};
  }
  table{
    border-collapse:collapse;
  }
  a{
    color:${config.accentColor};
    text-decoration:underline;
    word-break:break-word;
  }
  @media only screen and (max-width:600px){
    .container{
      width:100% !important;
    }
    .mobile-padding{
      padding:20px !important;
    }
    .title{
      font-size:22px !important;
      line-height:28px !important;
    }
  }
</style>
</head>

<body>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${config.canvasBg}">
<tr>
<td align="center" style="padding:24px 12px;">

<table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" class="container" style="width:680px;max-width:680px;background:${config.cardBg};border:1px ${config.borderStyle} #e2e8f0;">

    ${classificationBanner}

    <!-- HEADER -->
    <tr>
        <td bgcolor="${config.headerBg}" style="padding:20px 32px;box-shadow:0 1px 3px rgba(0,0,0,0.2);">

            ${stampHtml}

            <div style="font-size:10px;font-weight:bold;letter-spacing:1.5px;color:${headerMuted};margin-bottom:8px;">
                THREAT INTELLIGENCE &amp; BA CYBER SECURITY OPERATIONS
            </div>

            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:8px;">
                <tr>
                    <td>
                        {{severity_header_badge}}
                    </td>
                </tr>
            </table>

            <div class="title" style="font-size:24px;line-height:30px;font-weight:bold;color:${headerText};margin-bottom:6px;">
                Security Advisory
            </div>

            <div style="font-size:16px;line-height:22px;font-weight:600;color:${headerText};margin-bottom:8px;">
                {{advisory_title}}
            </div>

            <div style="font-size:12px;line-height:18px;color:${headerMuted};">
                Advisory ID: {{advisory_id}}<br>
                Report Generated: {{dispatch_date}}
            </div>

        </td>
    </tr>

    <!-- EXECUTIVE SUMMARY -->
    <tr>
        <td style="padding:24px 32px;border-bottom:1px solid #e2e8f0;">

            <div style="font-size:11px;font-weight:bold;letter-spacing:1.5px;color:${config.accentColor};margin-bottom:8px;">
                EXECUTIVE SUMMARY
            </div>

            <p style="margin:0;font-size:14px;line-height:24px;color:${config.fontColor};">
                {{executive_summary}}
            </p>

        </td>
    </tr>

    <!-- ADVISORY DETAILS -->
    <tr>
        <td class="mobile-padding" style="padding:32px;">

            <div style="font-size:11px;font-weight:bold;letter-spacing:1.5px;color:${config.accentColor};margin-bottom:12px;">
                ADVISORY DETAILS
            </div>

             <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-size:13px;line-height:22px;">

                 <tr>
                     <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                         CVE ID
                     </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{cve_id_links}}
                    </td>
                </tr>

                <tr>
                    <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        Severity
                    </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{severity_badge}}
                    </td>
                </tr>

                <tr>
                    <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        Date of Release
                    </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{dispatch_date}}
                    </td>
                </tr>

                <tr>
                    <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        Date of Update
                    </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{dispatch_date}}
                    </td>
                </tr>

                <tr>
                    <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        Vulnerability Details
                    </td>

                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{cve_details}}
                    </td>
                </tr>

                <tr>
                    <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        Affected Products &amp; Versions
                    </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{vendor_products_html}}
                    </td>
                </tr>

                <tr>
                    <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        Remediation
                    </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">

                        <div style="background:#f8fafc;border-left:4px solid ${config.accentColor};padding:12px;">
                            {{remediation_steps}}
                        </div>

                        {{#if remediation_link}}<p style="margin:12px 0 0;">
                            <a href="{{remediation_link}}" target="_blank">
                                View Vendor Guidance
                            </a>
                        </p>{{/if}}

                    </td>
                </tr>

                <tr>
                    <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        Workaround / Mitigation
                    </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{mitigation_steps}}
                    </td>
                </tr>

                <tr>
                    <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        References
                    </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{#if references_link}}<div style="font-size:12px;line-height:18px;text-align:left;">
                            <a href="{{references_link}}" target="_blank" rel="noopener noreferrer" style="color:#2563eb;text-decoration:underline;">Advisory link</a>
                        </div>{{/if}}
                    </td>
                </tr>

                <tr>
                       <td bgcolor="#f8fafc" style="padding:12px;font-weight:bold;border:1px solid #e2e8f0;color:#0f172a;">
                        Honeywell Recommended Actions
                    </td>
                    <td style="padding:12px;border:1px solid #e2e8f0;text-align:left;vertical-align:top;">
                        {{recommended_actions}}
                    </td>
                </tr>

            </table>

        </td>
    </tr>

    <!-- FOOTER -->
    <tr>
        <td style="padding:24px 32px;border-top:1px solid #e2e8f0;background:#fafafa;">

            <div style="font-size:13px;font-weight:bold;color:#0f172a;margin-bottom:8px;">
                BA Threat Intelligence
            </div>

             <div style="font-size:12px;line-height:20px;color:#64748b;">
                This advisory was generated from monitored inventory, vendor security notifications,
                and threat intelligence sources. Evaluate applicability to your environment before
                implementing remediation actions. All remediation activities should follow approved
                operational and change management procedures.
            </div>

            <div style="margin-top:12px;font-size:12px;line-height:20px;color:#64748b;">
                For questions or additional information, contact:
                <a href="mailto:DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com" style="color:${config.accentColor};text-decoration:underline;">DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com</a>
            </div>

        </td>
    </tr>

</table>

</td>
</tr>
</table>

</body>
</html>`;
}

export const DEFAULT_DAILY_DIGEST_CUSTOMIZATION: TemplateCustomization = {
  ...DEFAULT_TEMPLATE_CUSTOMIZATION,
  badgeStampText: 'DAILY DIGEST',
};

export interface DigestFinding {
  cveId: string;
  severity: string;
  assetName: string;
  vendor?: string;
  sourceUrl?: string;
  cvssScore?: number;
  exploitStatus?: 'Active Weaponized' | 'POC Available' | 'Reported In Wild' | 'None';
  epssScore?: number;
  cisaKev?: boolean;
}

export interface DigestHealth {
  database: 'connected' | 'degraded';
  databaseLatencyMs: number;
  workerStatus: string;
  workerHeartbeatAgeSeconds: number | null;
  nextScheduledAttempt: string | null;
  nextDailyDigestAt?: string | null;
  backlog: { status: string; count: number }[];
  checkedAt: string;
  systemUptime: string;
  /** Legacy availability field; not displayed because process uptime is not availability. */
  systemUptimePercentage: number | null;
}

export interface DailyDigestParts {
   advisory_id: string;
  advisory_title: string;
  dispatch_date: string;
  severity: string;
  finding_count: number;
  severity_counts: string;
  findings_summary: string;
  health_report: string;
  recipient_name: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  asset_count: number;
  executive_summary: string;
  report_generated: string;
  critical_summary: string;
  high_summary: string;
  medium_summary: string;
  low_summary: string;
  critical_kpi: string;
  high_kpi: string;
  medium_kpi: string;
  low_kpi: string;
  held_for_review?: string;
}

const digestEscapeHtml = (value: string) =>
  String(value).replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
  );

function normalizeDigestConfig(config: TemplateCustomization): TemplateCustomization {
  config = { ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION, ...config };
  for (const key of [
    'fontColor',
    'headingColor',
    'accentColor',
    'canvasBg',
    'cardBg',
    'headerBg',
    'badgeStampColor',
  ] as const) {
    if (!/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(config[key]))
      config[key] = DEFAULT_DAILY_DIGEST_CUSTOMIZATION[key];
  }
  if (!['solid', 'dashed', 'none'].includes(config.borderStyle)) config.borderStyle = 'solid';
  if (!/^\d{1,3}(?:px|rem|%)$/.test(config.borderRadius)) config.borderRadius = '12px';
  config.badgeStampText = digestEscapeHtml(config.badgeStampText);
  config.classificationText = digestEscapeHtml(config.classificationText);
  return config;
}

export function compileDailyDigestTemplate(config: TemplateCustomization): string {
  config = normalizeDigestConfig(config);
  const headerHex = config.headerBg.slice(1);
  const expanded = headerHex.length === 3 ? [...headerHex].map((ch) => ch + ch).join('') : headerHex;
  const luminance = [0, 2, 4]
    .map((offset) => parseInt(expanded.slice(offset, offset + 2), 16) / 255)
    .map((channel) => (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
    .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
  const headerText = luminance > 0.179 ? '#0f172a' : '#ffffff';
  const headerMuted = luminance > 0.179 ? '#334155' : '#cbd5e1';
  const stampHtml = config.showStamp
    ? `<p style="margin:0 0 8px;font-size:11px;line-height:18px;letter-spacing:1.5px;font-weight:700;color:${config.badgeStampColor};">${config.badgeStampText}</p>`
    : '';
  const classificationBanner = config.showClassificationBanner
    ? `<tr><td style="padding:12px 28px;background:${config.canvasBg};color:${config.fontColor};font-size:10px;line-height:16px;letter-spacing:1px;text-align:center;">${config.classificationText}</td></tr>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<title>Daily Vulnerability Notification</title>

<style>
body{
    margin:0;
    padding:0;
    background:${config.canvasBg};
    font-family:${digestEscapeHtml(getFontFamilyCss(config.fontFamily))};
}
table{
    border-collapse:collapse;
}
img{
    border:0;
    display:block;
}
@media only screen and (max-width:600px){
    .container{
        width:100% !important;
    }
    .stack{
        display:block !important;
        width:100% !important;
    }
    .mobile-padding{
        padding:20px !important;
    }
    .title{
        font-size:22px !important;
        line-height:28px !important;
    }
}
</style>
</head>

<body>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${config.canvasBg}">
<tr>
<td align="center" style="padding:24px 12px;">

<table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" class="container" style="width:680px;max-width:680px;background:${config.cardBg};border:1px solid #e2e8f0;">

${classificationBanner}

    <!-- HEADER -->
    <tr>
        <td bgcolor="${config.headerBg}" style="padding:20px 32px;">

            ${stampHtml}
            <div style="font-size:10px;font-weight:bold;letter-spacing:1.5px;color:${headerMuted};margin-bottom:8px;">
                BA Cyber | THREAT INTELLIGENCE
            </div>

             <div class="title" style="font-size:24px;line-height:30px;font-weight:bold;color:${headerText};margin-bottom:6px;">
                 {{advisory_title}}
             </div>

             <div style="font-size:12px;line-height:18px;color:${headerMuted};">
                 Advisory ID: {{advisory_id}} &middot; Report Generated: {{report_generated}}
             </div>
             <meta name="dispatch-date" content="{{dispatch_date}}">
             <meta name="digest-severity" content="{{severity}}">

        </td>
    </tr>

    <!-- EXECUTIVE SUMMARY -->
     <tr>
         <td class="mobile-padding" style="padding:28px 32px;">

             <div style="font-size:11px;font-weight:bold;letter-spacing:1.5px;color:${config.accentColor};margin-bottom:8px;">
                 EXECUTIVE SUMMARY
             </div>

            <h2 style="margin:0 0 12px 0;font-size:20px;color:${config.headingColor};">
                Vulnerability Overview
            </h2>

            <p style="margin:0;font-size:14px;line-height:24px;color:#475569;">
                {{executive_summary}}
            </p>

        </td>
    </tr>

    <!-- KPI DASHBOARD -->
    <tr>
        <td style="padding:0 32px 28px 32px;">

            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">

                <tr>

                    <td align="center" bgcolor="#f8fafc" style="padding:16px;border:1px solid #e2e8f0;">
                        <div style="font-size:24px;font-weight:bold;color:#0f172a;">{{finding_count}}</div>
                        <div style="font-size:11px;color:#64748b;">TOTAL FINDINGS</div>
                    </td>

                    {{critical_kpi}}
                    {{high_kpi}}
                    {{medium_kpi}}
                    {{low_kpi}}

    <td align="center" bgcolor="#eff6ff" style="padding:16px;border:1px solid #e2e8f0;">
                        <div style="font-size:24px;font-weight:bold;color:#2563eb;">{{asset_count}}</div>
                        <div style="font-size:11px;color:#64748b;">ASSETS</div>
                    </td>

                </tr>

            </table>

        </td>
    </tr>

    <!-- FINDINGS -->
    <tr>
        <td class="mobile-padding" style="padding:0 32px 28px 32px;">

            <h2 style="margin:0 0 16px;font-size:18px;color:#0f172a;">
                Vulnerability Findings
            </h2>

     {{findings_summary}}

     </td>
 </tr>

     <!-- LIMITED-CONFIDENCE FINDINGS -->
     <tr>
         <td class="mobile-padding" style="padding:0 32px 24px 32px;">

             <h2 style="margin:0 0 16px;font-size:18px;color:#0f172a;">
                 Confidence Follow-up
             </h2>

             {{held_for_review}}

         </td>
     </tr>

     <!-- PLATFORM HEALTH -->
    <tr>
        <td class="mobile-padding" style="padding:0 32px 32px 32px;">

            <h2 style="margin:0 0 16px;font-size:18px;color:#0f172a;">
                Platform Health Status
            </h2>

            {{health_report}}

        </td>
    </tr>

    <!-- FOOTER -->
    <tr>
        <td style="padding:24px 32px;background:#fafafa;border-top:1px solid #e2e8f0;">

            <div style="font-size:13px;font-weight:bold;color:#0f172a;margin-bottom:8px;">
                BA Threat Intelligence
            </div>

             <div style="font-size:12px;line-height:20px;color:#64748b;">
                 This digest provides a consolidated view of newly identified vulnerabilities and platform
                 health status. Prioritize remediation activities according to asset criticality,
                 business impact, and established vulnerability management SLAs. All implementation
                 and remediation activities should follow approved change management procedures.
             </div>

             <div style="margin-top:12px;font-size:11px;line-height:18px;color:#94a3b8;">
                 Severity breakdown: {{critical_count}} Critical, {{high_count}} High, {{medium_count}} Medium, {{low_count}} Low
             </div>

            <div style="margin-top:12px;font-size:12px;line-height:20px;color:#64748b;">
                For questions or additional information, contact:
                <a href="mailto:DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com" style="color:${config.accentColor};text-decoration:underline;">DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com</a>
            </div>

        </td>
    </tr>

</table>

</td>
</tr>
</table>

</body>
</html>`;
}
export function renderDailyFindingSummary(findings: DigestFinding[], config: TemplateCustomization): string {
  const safe = normalizeDigestConfig(config);
  if (!findings.length) {
    return `<p style="margin:0;font-size:12px;line-height:20px;color:${safe.fontColor};">No findings in the last 24 hours.</p>`;
  }
  const bySeverity: Record<string, DigestFinding[]> = {};
  for (const finding of findings) (bySeverity[finding.severity] ||= []).push(finding);
  const ordered = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const).filter(
    (s) => bySeverity[s]?.length,
  );
  const severityStyle: Record<string, { bg: string; border: string; text: string }> = {
    CRITICAL: { bg: '#fef2f2', border: '#dc2626', text: '#b91c1c' },
    HIGH: { bg: '#fff7ed', border: '#ea580c', text: '#c2410c' },
    MEDIUM: { bg: '#fefce8', border: '#ca8a04', text: '#a16207' },
    LOW: { bg: '#ecfdf5', border: '#16a34a', text: '#15803d' },
    UNKNOWN: { bg: '#f8fafc', border: '#94a3b8', text: '#475569' },
  };
  return ordered
    .map((severity, index) => {
      const items = bySeverity[severity].slice().sort((left, right) => left.cveId.localeCompare(right.cveId));
      const style = severityStyle[severity] || severityStyle.UNKNOWN;
      const marginBottom = index < ordered.length - 1 ? ' style="margin-bottom:18px;"' : '';
      const cards = items
        .slice(0, 25)
        .map((f) => {
          const cveIdHtml = f.sourceUrl
            ? `<a href="${digestEscapeHtml(f.sourceUrl)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">${digestEscapeHtml(f.cveId)}</a>`
            : `<strong style="color:#1d4ed8;">${digestEscapeHtml(f.cveId)}</strong>`;
          const tags: string[] = [];
          if (typeof f.cvssScore === 'number') {
            tags.push(`CVSS ${f.cvssScore.toFixed(1)}`);
          }
          if (f.cisaKev) {
            tags.push('CISA KEV');
          }
          if (f.exploitStatus && f.exploitStatus !== 'None') {
            tags.push(f.exploitStatus);
          }
          if (typeof f.epssScore === 'number' && f.epssScore > 0.2) {
            tags.push(`EPSS ${(f.epssScore * 100).toFixed(0)}%`);
          }
          const tagHtml = tags.map((tag) =>
            `<span style="display:inline-block;margin:3px 5px 0 0;padding:2px 6px;border:1px solid #dbe2ea;border-radius:3px;background:#f8fafc;color:#475569;font-size:10px;line-height:15px;">${digestEscapeHtml(tag)}</span>`,
          ).join('');
          return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0 0 10px;border-collapse:collapse;table-layout:fixed;">
    <tr class="vulnstream-pdf-card" data-pdf-accent="${style.border}">
        <td style="padding:12px 14px;border:1px solid #e2e8f0;border-left:4px solid ${style.border};background:#ffffff;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;table-layout:fixed;">
                <tr>
                    <td style="padding:0 8px 0 0;font-size:14px;line-height:20px;font-weight:700;word-break:break-word;">${cveIdHtml}</td>
                    <td align="right" style="width:1%;padding:0;white-space:nowrap;vertical-align:top;">
                        <span style="display:inline-block;padding:3px 7px;border-radius:3px;background:${style.bg};color:${style.text};font-size:10px;line-height:15px;font-weight:700;">${severity}${typeof f.cvssScore === 'number' ? ` · CVSS ${f.cvssScore.toFixed(1)}` : ''}</span>
                    </td>
                </tr>
            </table>
            <p style="margin:8px 0 0;font-size:12px;line-height:18px;color:#334155;"><strong>Asset:</strong> ${digestEscapeHtml(f.assetName)}${f.vendor ? ` (${digestEscapeHtml(f.vendor)})` : ''}</p>
            ${tagHtml ? `<div style="margin-top:5px;line-height:20px;">${tagHtml}</div>` : ''}
        </td>
    </tr>
</table>`;
        })
        .join('');
      const extra = items.length > 25
        ? `<p style="margin:0;font-size:11px;line-height:17px;color:#71717a;">${items.length - 25} more ${severity.toLowerCase()} finding${items.length - 25 === 1 ? '' : 's'} omitted</p>`
        : '';
      return `<div${marginBottom}>
    <p style="margin:0 0 9px;font-size:12px;line-height:18px;font-weight:700;color:${style.text};">${severity} (${items.length})</p>
    ${cards}${extra}
</div>`;
    })
    .join('\n');
}

export function renderDailyHealthReport(health: DigestHealth | null, config: TemplateCustomization & { timezone?: string }): string {
  if (!health) return '';
  const safe = normalizeDigestConfig(config);
  // Workspace timezone for every timestamp in this table. The digest body is
  // rendered on the server, so it cannot rely on the viewer's browser zone.
  const outputTimezone = resolveTimezone(config.timezone);
  const workerStatusLabel: Record<string, string> = {
    HEALTHY: 'Healthy',
    DISABLED: 'Disabled',
    STALE: 'Stale',
    NOT_OBSERVED: 'Not observed',
  };
  const workerStatusColor: Record<string, string> = {
    HEALTHY: '#16a34a',
    DISABLED: '#64748b',
    STALE: '#ea580c',
    NOT_OBSERVED: '#64748b',
  };
  const workerLabel = workerStatusLabel[health.workerStatus] || health.workerStatus;
  const workerColor = workerStatusColor[health.workerStatus] || '#64748b';
  const dbLabel = health.database === 'connected' ? `Operational (${health.databaseLatencyMs} ms)` : 'Degraded';
  const dbColor = health.database === 'connected' ? '#16a34a' : '#dc2626';
  const heartbeatLabel =
    health.workerHeartbeatAgeSeconds !== null
      ? `${health.workerHeartbeatAgeSeconds} seconds ago`
      : 'N/A';
  const deliveryQueueLabel = [
    ['QUEUED', 'Queued'],
    ['SENDING', 'Sending'],
    ['REVIEW', 'Awaiting review'],
    ['ACCEPTED', 'Provider accepted'],
    ['FAILED', 'Failed'],
  ].map(([status, label]) => {
    const count = health.backlog.filter((b) => b.status === status).reduce((sum, b) => sum + b.count, 0);
    return `${count} ${label}`;
  }).join(' | ');
  const formatHealthDate = (iso: string): string => {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '—';
    // Rendered in the workspace timezone, not UTC: an operator reading the
    // digest at 09:00 local must not have to convert a UTC timestamp by hand.
    // The UTC offset is appended so the instant is never ambiguous.
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: outputTimezone,
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).formatToParts(date);
    const day = parts.find((p) => p.type === 'day')?.value || '';
    const month = parts.find((p) => p.type === 'month')?.value || '';
    const year = parts.find((p) => p.type === 'year')?.value || '';
    const hour = parts.find((p) => p.type === 'hour')?.value || '';
    const minute = parts.find((p) => p.type === 'minute')?.value || '';
    return `${day} ${month} ${year} ${hour}:${minute} ${utcOffsetLabel(date, outputTimezone)}`;
  };
  const nextDigest = health.nextDailyDigestAt
    ? formatHealthDate(health.nextDailyDigestAt)
    : 'Not scheduled';
  const nextDelivery = health.nextScheduledAttempt
    ? formatHealthDate(health.nextScheduledAttempt)
    : 'No future delivery attempt scheduled';
  const lastCheck = formatHealthDate(health.checkedAt);
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0">

                <tr bgcolor="#f8fafc">
                    <td style="padding:10px;border:1px solid #e2e8f0;font-weight:bold;font-size:12px;">
                        Component
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-weight:bold;font-size:12px;">
                        Status
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Database Connectivity
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;color:${dbColor};font-size:12px;">
                        ${dbLabel}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Worker Process Uptime
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;color:#16a34a;font-size:12px;">
                        ${digestEscapeHtml(health.systemUptime)} (since restart)
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Notification Service
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;color:${workerColor};font-size:12px;">
                        ${workerLabel}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Last Heartbeat
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(heartbeatLabel)}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Delivery Queue (retained jobs)
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(deliveryQueueLabel)}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Next Delivery Attempt
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(nextDelivery)}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Next Scheduled Digest
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(nextDigest)}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Last Health Check
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(lastCheck)}
                    </td>
                </tr>

            </table>`;
}

export function renderHeldForReview(count: number, config: TemplateCustomization): string {
  const safe = normalizeDigestConfig(config);
  if (count === 0) {
    return `<p style="margin:0;font-size:12px;line-height:20px;color:#64748b;">No outstanding confidence follow-ups.</p>`;
  }
  // Every finding is dispatched; a finding counted here was delivered with a
  // stated confidence limitation, not withheld for review.
  return `<p style="margin:0;font-size:14px;line-height:24px;color:#475569;">${count} finding(s) were dispatched with a stated confidence limitation. Each one requires manual verification of asset applicability against current vendor guidance; the delivered email names the reason on the finding itself.</p>`;
}

const SEVERITY_KPI: Record<string, { label: string; color: string; bg: string }> = {
  CRITICAL: { label: 'CRITICAL', color: '#dc2626', bg: '#fef2f2' },
  HIGH: { label: 'HIGH', color: '#ea580c', bg: '#fff7ed' },
  MEDIUM: { label: 'MEDIUM', color: '#ca8a04', bg: '#fefce8' },
  LOW: { label: 'LOW', color: '#16a34a', bg: '#ecfdf5' },
};

const SEVERITY_TITLE: Record<string, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
};

export const digestSeveritySummary = (
  severity: string,
  count: number,
  config: TemplateCustomization,
): string => {
  if (count === 0) return '';
  const safe = normalizeDigestConfig(config);
  const sev = SEVERITY_KPI[severity] ?? { label: severity, color: safe.fontColor, bg: '#f8fafc' };
  const color = severity === 'CRITICAL' ? '#dc2626' : severity === 'HIGH' ? '#ea580c' : severity === 'MEDIUM' ? '#ca8a04' : '#16a34a';
  return `<td style="font-size:12px;color:${color};" align="center">
    <strong>${SEVERITY_TITLE[severity] ?? severity}:</strong> ${count}
</td>`;
};

export const digestSeverityKpi = (
  severity: string,
  count: number,
  config: TemplateCustomization,
): string => {
  if (count === 0) return '';
  const safe = normalizeDigestConfig(config);
  const sev = SEVERITY_KPI[severity] ?? { label: severity, color: safe.fontColor, bg: '#f8fafc' };
  return `<td align="center" bgcolor="${sev.bg}" style="padding:16px;border:1px solid #e2e8f0;">
    <div style="font-size:24px;font-weight:bold;color:${sev.color};">${count}</div>
    <div style="font-size:11px;color:#64748b;">${sev.label}</div>
</td>`;
};

export const formatExecutiveSummary = (total: number, counts: Record<string, number>): string => {
  const overview = `A total of <strong>${total} ${total === 1 ? 'finding' : 'findings'}</strong> matched your subscriptions in the last 24 hours`;
  if (total === 0) {
    return `${overview}. This does not mean there are no open vulnerabilities. Findings held for review are excluded from this total.`;
  }
  const parts: string[] = [];
  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const) {
    if (counts[severity] > 0) {
      parts.push(
        `<strong>${counts[severity]} ${severity.charAt(0) + severity.slice(1).toLowerCase()}</strong>`,
      );
    }
  }
  const summary =
    parts.length > 1
      ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`
      : parts.length === 1
        ? parts[0]
        : 'no';
  const guidance: string[] = [];
  if (counts.CRITICAL > 0) guidance.push('Prioritize immediate remediation of critical findings.');
  if (counts.HIGH > 0) guidance.push('Address high-severity findings promptly through your change management process.');
  const routineSeverities = ['MEDIUM', 'LOW'].filter((severity) => counts[severity] > 0);
  if (routineSeverities.length) guidance.push(`Address ${routineSeverities.map((severity) => severity.toLowerCase()).join(' and ')} severity findings according to established risk treatment procedures.`);
  if (counts.UNKNOWN > 0) guidance.push('Assess findings with unknown severity before assigning remediation priority.');
  return `${overview}, including ${summary} severity findings across monitored assets. ${guidance.join(' ')}`;
}

export const formatExecutiveSummaryText = (total: number, counts: Record<string, number>): string =>
  formatExecutiveSummary(total, counts).replace(/<\/?strong>/g, '');

export const stripGeneratedExecutiveSummaryMarkup = (value: string): string =>
  value.replace(/<\/?strong>/gi, '');

/**
 * The daily digest's executive summary is trusted HTML only when it is exactly
 * the sentence this module generates or a legacy generated sentence.
 * Anything else is data and is escaped.
 *
 * The comparison is made against the generated sentence itself rather than a
 * hand-written pattern: a pattern has to be kept in step with the wording by
 * hand, and one that drifts silently starts escaping legitimate markup (or, if
 * loosened, starts trusting injected markup).
 */
function digestSafeExecutiveSummary(value: string): string {
  const total = /^A total of <strong>(\d+) findings?<\/strong>/.exec(value);
  if (total) {
    const counts: Record<string, number> = {};
    for (const match of value.matchAll(/<strong>(\d+) (Critical|High|Medium|Low|Unknown)<\/strong>/g)) {
      counts[match[2].toUpperCase()] = Number(match[1]);
    }
    if (value === formatExecutiveSummary(Number(total[1]), counts)) return value;
  }
  // A generated sentence contains `<strong>` around a total and around each
  // severity count, and no other markup at all. Both halves are required: the
  // tag inventory alone would still allow arbitrary text inside the tags, and
  // the wording alone would still allow an extra tag to be appended.
  const noForeignMarkup = !value.replace(/<\/?strong>/g, '').includes('<');
   // The list separator accepts an Oxford comma as well as the generated form, so
  // a hand-authored summary that only differs in punctuation still renders.
  const element = '<strong>\\d+ [A-Z][a-z]+<\\/strong>';
  // Older generated summaries used "no" in place of an empty severity list.
  const generatedShape = new RegExp(
    `^A total of <strong>\\d+ vulnerabilit(?:y|ies)<\\/strong> were identified during the latest monitoring cycle, including (?:no|(?:${element})(?:,(?: and)? | and )?(?:${element}(?:,(?: and)? | and )?)*) severity findings across monitored assets\\. Immediate remediation of critical findings is recommended while medium and low severity items should be addressed according to established risk treatment and vulnerability management procedures\\.$`,
  );
  return noForeignMarkup && generatedShape.test(value) ? value : digestEscapeHtml(value);
}

export function renderDailyDigest(config: TemplateCustomization, parts: DailyDigestParts, template?: string): string {
  const compiled = template || compileDailyDigestTemplate(config);
  return compiled
    .replace(/{{report_generated}}/g, digestEscapeHtml(parts.report_generated))
    .replace(/{{finding_count}}/g, String(parts.finding_count))
    .replace(/{{critical_count}}/g, String(parts.critical_count))
    .replace(/{{high_count}}/g, String(parts.high_count))
    .replace(/{{medium_count}}/g, String(parts.medium_count))
    .replace(/{{low_count}}/g, String(parts.low_count))
    .replace(/{{asset_count}}/g, String(parts.asset_count))
    .replace(/{{advisory_title}}/g, digestEscapeHtml(parts.advisory_title))
    .replace(/{{advisory_id}}/g, digestEscapeHtml(parts.advisory_id))
    .replace(/{{recipient_name}}/g, digestEscapeHtml(parts.recipient_name))
    .replace(/{{severity_counts}}/g, digestEscapeHtml(parts.severity_counts))
    .replace(/{{dispatch_date}}/g, digestEscapeHtml(parts.dispatch_date))
    .replace(/{{severity}}/g, digestEscapeHtml(parts.severity))
    // The executive summary is composed server-side from fixed templates and
    // anchors, not from inventory text, so it stays raw HTML. It is escaped here
    // when it is not one of those compositions, so operator-editable input such
    // as an asset name can never become live markup in a delivered email.
    .replace(
      /{{executive_summary}}/g,
      // The replacement is a value, not a pattern: a `$` in operator text would
      // otherwise be interpreted as a capture reference by String.replace.
      () => digestSafeExecutiveSummary(parts.executive_summary),
    )
    .replace(/{{findings_summary}}/g, parts.findings_summary)
    .replace(/{{health_report}}/g, parts.health_report)
    .replace(/{{critical_summary}}/g, parts.critical_summary || '')
    .replace(/{{high_summary}}/g, parts.high_summary || '')
    .replace(/{{medium_summary}}/g, parts.medium_summary || '')
    .replace(/{{low_summary}}/g, parts.low_summary || '')
    .replace(/{{critical_kpi}}/g, parts.critical_kpi || '')
    .replace(/{{high_kpi}}/g, parts.high_kpi || '')
    .replace(/{{medium_kpi}}/g, parts.medium_kpi || '')
    .replace(/{{low_kpi}}/g, parts.low_kpi || '')
    .replace(/{{held_for_review}}/g, parts.held_for_review || '');
}
