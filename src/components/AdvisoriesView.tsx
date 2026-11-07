import { PageHeading } from './PageHeading';
import React, { useState } from 'react';
import { Advisory } from '../types';
import { Download, Printer, Copy, Check, Send, X } from 'lucide-react';
import { Pagination } from './Pagination';
import { useCollection } from '../hooks/useCollection';
import { copyText } from '../utils/clipboard';
import { CveLink } from './CveLink';
import { formatDate as fmtDate } from '../utils/dateTime';
import { stripGeneratedExecutiveSummaryMarkup } from '../utils/templateCompiler';
import { useApp } from '../context/AppContext';

export const AdvisoriesView: React.FC = () => {
  const { settings } = useApp();
  const [copied, setCopied] = useState<string | null>(null);
  const [activeModalAdvisory, setActiveModalAdvisory] = useState<Advisory | null>(null);

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(5);
  // Advisories are paginated server-side: the state snapshot only carries the
  // most recent page-sized slice and must not be treated as the full history.
  const { items: advisories, total } = useCollection<Advisory>('advisories', {
    page: currentPage,
    pageSize,
  });

  const handleCopyMarkdown = async (adv: Advisory) => {
    const md = `# PRODUCT SECURITY ADVISORY: ${adv.id}
**Title:** ${adv.title}
**Severity:** ${adv.severity}
**Created:** ${new Date(adv.createdDate).toUTCString()}
**Status:** ${adv.deliveryStatus} (${adv.recipientCount} Recipients)

## Summary
${stripGeneratedExecutiveSummaryMarkup(adv.executiveSummary)}

## Affected Vulnerabilities
${adv.cveIds.map((c) => `- [${c}](https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)})`).join('\n')}

## Monitored Systems
${adv.affectedSystems.map((s) => `- ${s}`).join('\n')}

## Remediation Instructions
${adv.remediationInstructions}

---
*Autonomous Product Vulnerability Notification — BA Threat Intel Platform.*`;

    if (await copyText(md)) {
      setCopied(adv.id);
      setTimeout(() => setCopied(null), 2000);
    }
  };

  const handleDownloadHtmlPdf = (original: Advisory) => {
    const escape = (value: string) =>
      value.replace(
        /[&<>"']/g,
        (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
      );
    const adv = {
      ...original,
      id: escape(original.id),
      title: escape(original.title),
      executiveSummary: escape(stripGeneratedExecutiveSummaryMarkup(original.executiveSummary)),
      remediationInstructions: escape(original.remediationInstructions),
      cveIds: original.cveIds.map(escape),
      affectedSystems: original.affectedSystems.map(escape),
    };
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${adv.id} - Security Advisory</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 40px; color: #18181b; background: #ffffff; }
    .header { border-bottom: 2px solid #27272a; padding-bottom: 20px; margin-bottom: 30px; }
    .title { font-size: 22px; font-weight: bold; margin: 0 0 8px 0; color: #09090b; }
    .badge { display: inline-block; background: #27272a; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
    .section { margin-bottom: 25px; }
    .section-title { font-size: 15px; font-weight: bold; border-bottom: 1px solid #e4e4e7; padding-bottom: 6px; margin-bottom: 10px; color: #27272a; }
    .mono { font-family: ui-monospace, monospace; background: #f4f4f5; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
    .footer { margin-top: 50px; font-size: 11px; color: #71717a; border-top: 1px solid #e4e4e7; padding-top: 15px; }
    @media print { body { padding: 0; } }
  </style>
</head>
<body>
  <div class="header">
    <span class="badge">${adv.severity}</span>
    <h1 class="title">${adv.id}: ${adv.title}</h1>
    <p style="color: #71717a; font-size: 12px; margin: 0;">Generated on ${new Date(adv.createdDate).toUTCString()} to ${adv.recipientCount} authorized stakeholders</p>
  </div>

  <div class="section">
    <div class="section-title">1. Executive Summary</div>
    <p style="line-height: 1.6; font-size: 13px;">${adv.executiveSummary}</p>
  </div>

  <div class="section">
    <div class="section-title">2. Correlated Products &amp; CVEs</div>
    <p style="font-size: 13px;"><strong>CVE Identifiers:</strong> ${adv.cveIds.map((cveId) => `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}" target="_blank" rel="noopener noreferrer" style="font-family: monospace; font-weight: 600; color: #2563eb; margin-right: 8px;">${cveId}</a>`).join('')}</p>
    <p style="font-size: 13px;"><strong>Impacted Systems:</strong></p>
    <ul style="font-size: 13px;">
      ${adv.affectedSystems.map((s) => `<li>${s}</li>`).join('')}
    </ul>
  </div>

  <div class="section">
    <div class="section-title">3. Remediation Guidance</div>
    <p style="line-height: 1.6; font-size: 13px;">${adv.remediationInstructions}</p>
  </div>

  <div class="footer">
    BA Threat Intel Autonomous Intelligence • Zero-Touch Alerting Service
  </div>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', url);
    downloadAnchor.setAttribute('download', `${adv.id.split('-').slice(0, 3).join('-')}.html`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const handlePrintInPage = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="ui-page-header">
        <PageHeading page="advisories">
          Generated bulletins and their actual transport status. Provider acceptance is not confirmation of
          inbox delivery.
        </PageHeading>

        <div className="text-xs font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-3 py-1.5 rounded-xl shadow-sm">
          Total Generated:{' '}
          <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900">{total}</strong>
        </div>
      </div>

      {/* Advisory Cards List */}
      <div className="space-y-4">
        {advisories.map((adv) => (
          <div
            key={adv.id}
            className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm space-y-4 transition-colors"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 pb-3">
              <div className="flex items-center space-x-2.5">
                <span className="font-mono text-xs font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-900 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 px-2 py-0.5 rounded-lg border border-zinc-800 dark:border-zinc-800 light:border-zinc-300">
                  {adv.id}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800/80 dark:bg-zinc-800/80 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700/60 dark:border-zinc-700/60 light:border-zinc-300">
                  {adv.severity}
                </span>
                <h3 className="text-sm font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                  {adv.title}
                </h3>
              </div>

              <div className="flex items-center space-x-2 text-xs font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                <span className="text-emerald-400 flex items-center gap-1 font-sans">
                  <Send className="w-3 h-3" />
                  {adv.deliveryStatus}
                </span>
                <span>•</span>
                <span>{adv.recipientCount} Recipients</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="md:col-span-2 space-y-2">
                <div className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 leading-relaxed">
                  {stripGeneratedExecutiveSummaryMarkup(adv.executiveSummary)}
                </div>
                <div className="text-[11px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-500">
                  <span>Impacted Systems: </span>
                  <span className="text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
                    {adv.affectedSystems.join(', ')}
                  </span>
                </div>
              </div>

              <div className="space-y-1.5 bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800/70 dark:border-zinc-800/70 light:border-zinc-200">
                <div className="text-[11px] font-mono uppercase text-zinc-500 dark:text-zinc-500 light:text-zinc-600">
                  Correlated CVEs
                </div>
                <div className="flex flex-wrap gap-1">
                  {adv.cveIds.map((cve) => (
                    <span key={cve} className="px-1.5 py-0.5">
                      <CveLink cveId={cve} className="text-[10px]" />
                    </span>
                  ))}
                </div>
                <div className="text-[10px] text-zinc-500 font-mono pt-1">
                  Generated: {fmtDate(adv.createdDate, settings.timezone)}
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-xs">
              <div className="text-[11px] text-zinc-500 font-mono">Advisory Ref: {adv.id}</div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleCopyMarkdown(adv)}
                  className="px-2.5 py-1 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition flex items-center space-x-1"
                  title="Copy Markdown"
                >
                  {copied === adv.id ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  <span>{copied === adv.id ? 'Copied' : 'Markdown'}</span>
                </button>
                <button
                  onClick={() => handleDownloadHtmlPdf(adv)}
                  className="px-2.5 py-1 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-medium border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 flex items-center space-x-1 transition"
                  title="Download HTML Bulletin / Print to PDF"
                >
                  <Download className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Download Report</span>
                </button>
                <button
                  onClick={() => setActiveModalAdvisory(adv)}
                  className="px-3 py-1 rounded-xl bg-zinc-100 dark:bg-zinc-100 light:bg-zinc-900 hover:bg-zinc-200 dark:hover:bg-zinc-200 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition"
                >
                  View Bulletin
                </button>
              </div>
            </div>
          </div>
        ))}

        {/* Pagination */}
        <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm">
          <Pagination
            currentPage={currentPage}
            totalItems={total}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setCurrentPage(1);
            }}
            pageSizeOptions={[5, 10, 20]}
          />
        </div>
      </div>

      {/* Advisory Modal */}
      {activeModalAdvisory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setActiveModalAdvisory(null)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-200 pb-3 mb-4">
              <span className="text-[10px] font-medium font-mono px-2 py-0.5 rounded-full bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300">
                {activeModalAdvisory.severity} ADVISORY
              </span>
              <h2 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mt-2">
                {activeModalAdvisory.id}: {activeModalAdvisory.title}
              </h2>
              <p className="text-xs text-zinc-500 font-mono mt-0.5">
                Generated on {new Date(activeModalAdvisory.createdDate).toUTCString()}
              </p>
            </div>

            <div className="space-y-3.5 text-xs">
              <div>
                <h4 className="font-semibold text-zinc-300 dark:text-zinc-300 light:text-zinc-700 uppercase tracking-wider mb-1 text-[11px]">
                  1. Summary
                </h4>
                <p className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
                  {stripGeneratedExecutiveSummaryMarkup(activeModalAdvisory.executiveSummary)}
                </p>
              </div>

              <div>
                <h4 className="font-semibold text-zinc-300 dark:text-zinc-300 light:text-zinc-700 uppercase tracking-wider mb-1 text-[11px]">
                  2. Impacted Products &amp; Assets
                </h4>
                <div className="bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 space-y-1 text-zinc-300 dark:text-zinc-300 light:text-zinc-800">
                  <div>
                    <strong>CVEs:</strong>{' '}
                    {activeModalAdvisory.cveIds.map((cve, index) => (
                      <React.Fragment key={cve}>
                        {index > 0 && ', '}
                        <CveLink cveId={cve} />
                      </React.Fragment>
                    ))}
                  </div>
                  <div>
                    <strong>Monitored Products:</strong> {activeModalAdvisory.affectedSystems.join(', ')}
                  </div>
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-zinc-300 dark:text-zinc-300 light:text-zinc-700 uppercase tracking-wider mb-1 text-[11px]">
                  3. Technical Remediation Instructions
                </h4>
                <div className="bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-mono leading-relaxed whitespace-pre-wrap">
                  {activeModalAdvisory.remediationInstructions}
                </div>
              </div>
            </div>

            <div className="flex justify-end space-x-2 mt-5 pt-4 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
              <button
                onClick={() => handleDownloadHtmlPdf(activeModalAdvisory)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 text-xs flex items-center space-x-1 transition"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Report</span>
              </button>
              <button
                onClick={handlePrintInPage}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 text-xs flex items-center space-x-1 transition"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print</span>
              </button>
              <button
                onClick={() => setActiveModalAdvisory(null)}
                className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
