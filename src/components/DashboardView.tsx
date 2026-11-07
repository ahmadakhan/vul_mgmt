import { PageHeading } from './PageHeading';
import React from 'react';
import { useApp } from '../context/AppContext';
import { Shield, Flame, Radio, FileText, Server, ArrowUpRight, Cpu, MailCheck, Send, ChevronRight, Code, Package, CheckCircle2 } from 'lucide-react';
import { Finding } from '../types';
import { CveLink } from './CveLink';
import { compareFindingsByRecency } from '../utils/findingSort';
import { formatDate } from '../utils/dateTime';

export const DashboardView: React.FC = () => {
  const {
    findings,
    watchlist,
    feeds,
    setActiveTab,
    setSelectedFinding,
    webhooks,
    settings,
    summary,
    counts,
  } = useApp();

  // The snapshot carries only recent slices of findings/email logs. Exact KPI
  // totals come from the server-computed summary so a large installation does
  // not under-report once those slices are capped.
  const activeVulnerabilities = findings
    .filter(
      (f) =>
        !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status) &&
        f.notificationStatus !== 'NOT_APPLICABLE',
    )
    .sort(compareFindingsByRecency);

  const totalCpesCount = watchlist.reduce((acc, curr) => acc + curr.cpes.length, 0);
  const totalPurlsCount = watchlist.reduce((acc, curr) => acc + (curr.purls ? curr.purls.length : 0), 0);

  const handleSelectFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    setActiveTab('findings');
  };

  return (
    <div className="space-y-6">
      <div className="ui-page-header">
        <PageHeading page="dashboard">
          Monitor your product exposure, prioritize correlated vulnerabilities, and track intelligence
          ingestion and notification delivery across your workspace.
        </PageHeading>
        <button onClick={() => setActiveTab('watchlist')} className="ui-secondary">
          Monitored products ({watchlist.length})
        </button>
      </div>

      {/* ALL KPI Cards CLICKABLE with direct navigation */}
      <div className="ui-metrics grid grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6 gap-3">
        {/* 1. Monitored Products -> Watchlist */}
        <button
          type="button"
          onClick={() => setActiveTab('watchlist')}
          className="group w-full cursor-pointer rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-4 text-left shadow-sm transition hover:border-zinc-600 hover:bg-zinc-900/70 dark:border-zinc-800/80 dark:bg-zinc-900/40 dark:hover:border-zinc-600 light:border-zinc-200 light:bg-white light:hover:border-zinc-400"
          title="Click to view and manage Monitored Products"
          aria-label={`View ${watchlist.length} monitored products`}
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-zinc-200 transition">Products</span>
            <Server className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-200 transition" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span>{watchlist.length}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">{totalCpesCount} Strict CPEs</div>
        </button>

        {/* 2. Active Vulnerabilities -> Findings */}
        <button
          type="button"
          onClick={() => setActiveTab('findings')}
          className="group w-full cursor-pointer rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-4 text-left shadow-sm transition hover:border-zinc-600 hover:bg-zinc-900/70 dark:border-zinc-800/80 dark:bg-zinc-900/40 dark:hover:border-zinc-600 light:border-zinc-200 light:bg-white light:hover:border-zinc-400"
          title="Click to review correlated product vulnerabilities"
          aria-label={`Review ${summary.activeFindings} active vulnerabilities`}
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-zinc-200 transition">Vulnerabilities</span>
            <Shield className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-200 transition" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span>{summary.activeFindings}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">
            {summary.criticalFindings} Critical Impact
          </div>
        </button>

        {/* 3. CISA KEV In Wild -> Findings */}
        <button
          type="button"
          onClick={() => setActiveTab('findings')}
          className="group w-full cursor-pointer rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-4 text-left shadow-sm transition hover:border-amber-600/60 hover:bg-zinc-900/70 dark:border-zinc-800/80 dark:bg-zinc-900/40 dark:hover:border-amber-600/60 light:border-zinc-200 light:bg-white light:hover:border-amber-400"
          title="Click to view CISA KEV actively exploited items"
          aria-label={`Review ${summary.kevFindings} active CISA KEV vulnerabilities`}
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-amber-400 transition">CISA KEV</span>
            <Flame className="w-3.5 h-3.5 text-amber-500/80" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span className="text-amber-400/90">{summary.kevFindings}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-amber-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-amber-500/80 mt-1 font-medium">Active in Wild</div>
        </button>

        {/* 4. Automated Notifications -> Email / Webhook Log */}
        <button
          type="button"
          onClick={() => setActiveTab('emails')}
          className="group w-full cursor-pointer rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-4 text-left shadow-sm transition hover:border-emerald-600/60 hover:bg-zinc-900/70 dark:border-zinc-800/80 dark:bg-zinc-900/40 dark:hover:border-emerald-600/60 light:border-zinc-200 light:bg-white light:hover:border-emerald-400"
          title="Click to view automated email & notification log"
          aria-label={`View ${summary.deliveredEmails} accepted notifications`}
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-emerald-400 transition">Auto-Dispatched</span>
            <MailCheck className="w-3.5 h-3.5 text-emerald-500/80" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span className="text-emerald-400/90">{summary.deliveredEmails}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-emerald-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">Provider Accepted</div>
        </button>

        {/* 5. Threat Feeds -> Threat Feeds View */}
        <button
          type="button"
          onClick={() => setActiveTab('feeds')}
          className="group w-full cursor-pointer rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-4 text-left shadow-sm transition hover:border-zinc-600 hover:bg-zinc-900/70 dark:border-zinc-800/80 dark:bg-zinc-900/40 dark:hover:border-zinc-600 light:border-zinc-200 light:bg-white light:hover:border-zinc-400"
          title="Click to inspect and manage Threat Feeds"
          aria-label={`Inspect ${feeds.length} threat feeds`}
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-zinc-200 transition">Threat Feeds</span>
            <Radio className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-200 transition" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span>
              {feeds.filter((f) => f.enabled).length}/{feeds.length}
            </span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">SSRF Guard Active</div>
        </button>

        {/* 6. Generated Advisories -> Advisories View */}
        <button
          type="button"
          onClick={() => setActiveTab('advisories')}
          className="group w-full cursor-pointer rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-4 text-left shadow-sm transition hover:border-zinc-600 hover:bg-zinc-900/70 dark:border-zinc-800/80 dark:bg-zinc-900/40 dark:hover:border-zinc-600 light:border-zinc-200 light:bg-white light:hover:border-zinc-400"
          title="Click to view generated security advisories"
          aria-label={`View ${counts.advisories} generated advisories`}
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-zinc-200 transition">Advisories</span>
            <FileText className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-200 transition" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span>{counts.advisories}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">Generated &amp; Logged</div>
        </button>
      </div>

      {/* Two Column Section: Correlated Vulnerabilities + Monitored Product Protection Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Monitored Product Vulnerabilities (2 cols) */}
        <div className="ui-panel lg:col-span-2 bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm transition-colors">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
            <div className="flex items-center space-x-2">
              <Shield className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              <h2 className="text-xs font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider">
                Correlated Product Vulnerabilities
              </h2>
            </div>
            <button
              onClick={() => setActiveTab('findings')}
              className="text-xs text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900 font-medium flex items-center space-x-1"
            >
              <span>View All Vulnerabilities</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {activeVulnerabilities.slice(0, 4).map((finding) => {
              const isKev = finding.cve.cisaKev?.isKev ?? false;

              return (
                <div
                  key={finding.id}
                  className="w-full p-3.5 rounded-xl border border-zinc-800/70 dark:border-zinc-800/70 light:border-zinc-200 bg-zinc-950/40 dark:bg-zinc-950/40 light:bg-zinc-50 hover:bg-zinc-900/60 dark:hover:bg-zinc-900/60 light:hover:bg-zinc-100 hover:border-zinc-700 dark:hover:border-zinc-700 light:hover:border-zinc-400 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-sm text-left"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <CveLink cveId={finding.cveId} />
                      {isKev && (
                        <span className="text-[10px] font-medium bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 px-2 py-0.5 rounded-full flex items-center gap-1">
                          <Flame className="w-3 h-3 text-amber-500" />
                          CISA KEV
                        </span>
                      )}
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800/80 dark:bg-zinc-800/80 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700/60 dark:border-zinc-700/60 light:border-zinc-300">
                        {finding.cve.cvss.version === 'UNKNOWN'
                          ? 'CVSS not scored'
                          : `CVSS ${finding.cve.cvss.score.toFixed(1)} (${finding.cve.cvss.severity})`}
                      </span>
                    </div>
                    <div className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700 line-clamp-1">
                      {finding.cve.title}
                    </div>
                    <div className="text-[10px] text-zinc-400 dark:text-zinc-400 light:text-zinc-500 font-mono flex items-center gap-2">
                      <span>
                        Published: {formatDate(finding.cve.publishedDate, settings.timezone)}
                      </span>
                      <span>•</span>
                      <span>
                        Modified: {formatDate(finding.cve.modifiedDate, settings.timezone)}
                      </span>
                    </div>
                    <div className="text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-500 font-mono flex items-center gap-2">
                      <span>
                        Product:{' '}
                        <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
                          {finding.matchedAssetName}
                        </strong>
                      </span>
                      <span>•</span>
                      <span>
                        Protection:{' '}
                        <span className="text-emerald-400 font-medium">
                          {settings.schedulerEnabled ? 'Scheduled matching' : 'Manual matching'}
                        </span>
                      </span>
                    </div>
                  </div>

                  <div className="sm:text-right shrink-0">
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full bg-zinc-800/80 dark:bg-zinc-800/80 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700/60 dark:border-zinc-700/60 light:border-zinc-300">
                      <Send className="w-3 h-3 text-emerald-400" />
                      <span>{finding.notificationStatus.replace(/_/g, ' ')}</span>
                    </span>
                    <div className="text-[10px] text-zinc-500 font-mono mt-1">
                      {['REVIEW_REQUIRED', 'NOT_APPLICABLE'].includes(finding.notificationStatus)
                        ? 'Not eligible for automatic dispatch'
                        : finding.autoDispatchedAt
                          ? 'Provider accepted notification'
                          : 'Notification pending'}
                    </div>
                    <button
                      type="button"
                      onClick={() => handleSelectFinding(finding)}
                      className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-zinc-400 hover:text-zinc-100 light:text-zinc-600 light:hover:text-zinc-900"
                      aria-label={`Inspect ${finding.cveId} affecting ${finding.matchedAssetName}`}
                    >
                      Inspect <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Monitored Products Protection Status (All products treated equally) */}
        <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm flex flex-col justify-between transition-colors">
          <div>
            <div className="flex items-center space-x-2 mb-4 pb-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
              <Server className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              <h2 className="text-xs font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider">
                Product Inventory Protection Telemetry
              </h2>
            </div>

            <div className="space-y-3">
              <button
                type="button"
                onClick={() => setActiveTab('watchlist')}
                className="w-full cursor-pointer p-3 rounded-xl bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-700 transition text-left"
                aria-label={`Open product inventory: ${watchlist.length} assets`}
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Protected Product Assets</span>
                  </span>
                  <span className="font-mono text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-bold text-sm">
                    {watchlist.length} Assets
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 light:text-zinc-600 mt-1 pl-6">
                  All enterprise software products treated with uniform priority.
                </div>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('watchlist')}
                className="w-full cursor-pointer p-3 rounded-xl bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-700 transition text-left"
                aria-label={`Open product inventory: ${totalCpesCount} CPE identifiers`}
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium flex items-center gap-2">
                    <Code className="w-4 h-4 text-sky-400 shrink-0" />
                    <span>Active Strict CPE 2.3 Strings</span>
                  </span>
                  <span className="font-mono text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-bold text-sm">
                    {totalCpesCount}
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 light:text-zinc-600 mt-1 pl-6">
                  Precise component matching across Vendor, Product, and SemVer ranges.
                </div>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('watchlist')}
                className="w-full cursor-pointer p-3 rounded-xl bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-700 transition text-left"
                aria-label={`Open product inventory: ${totalPurlsCount} package URLs`}
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium flex items-center gap-2">
                    <Package className="w-4 h-4 text-purple-400 shrink-0" />
                    <span>Supply Chain PURLs Monitored</span>
                  </span>
                  <span className="font-mono text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-bold text-sm">
                    {totalPurlsCount}
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 light:text-zinc-600 mt-1 pl-6">
                  Maven, NPM, PyPI, and Golang dependency signatures.
                </div>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('pipeline')}
                className="w-full cursor-pointer p-3 rounded-xl bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-700 transition text-left"
                aria-label={`Open pipeline executions; scheduler ${settings.schedulerEnabled ? 'enabled' : 'disabled'}`}
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Autonomous Detection Engine</span>
                  </span>
                  <span className="font-mono text-emerald-400 font-bold text-xs bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/60">
                    {settings.schedulerEnabled ? 'Scheduled' : 'Manual'}
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 light:text-zinc-600 mt-1 pl-6">
                  Server scheduler • Configure interval in Settings.
                </div>
              </button>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
            <button
              onClick={() => setActiveTab('watchlist')}
              className="w-full text-xs py-2 bg-zinc-800/70 hover:bg-zinc-700/70 dark:bg-zinc-800/70 dark:hover:bg-zinc-700/70 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 rounded-xl font-medium border border-zinc-700/40 dark:border-zinc-700/40 light:border-zinc-300 transition text-center"
            >
              Configure Monitored Products →
            </button>
          </div>
        </div>
      </div>

      {/* Autonomous Pipeline Steps (CLICKABLE CARDS) */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm transition-colors">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
          <div className="flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
            <h2 className="text-xs font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider">
              Autonomous Pipeline Architecture (Click Step to Inspect)
            </h2>
          </div>
          <span className="text-[11px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-500">
            Interval: {settings.schedulerIntervalMinutes}m • Auto-Dispatch:{' '}
            {settings.autoDispatchEnabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {[
            { phase: '1. Ingress & SSRF', desc: 'Configured HTTPS feed adapters', targetTab: 'feeds' },
            {
              phase: '2. Deduplication',
              desc: 'Canonical CVE IDs, O(1) set check',
              targetTab: 'alerted-cves',
            },
            { phase: '3. Auto-Enrichment', desc: 'NVD CVSS, EPSS & CISA KEV', targetTab: 'threat-data' },
            { phase: '4. Product Match', desc: 'Strict component matching & PURL', targetTab: 'watchlist' },
            { phase: '5. Auto-Dispatch', desc: 'Durable SMTP & webhook outbox', targetTab: 'emails' },
          ].map((step, idx) => (
            <button
              type="button"
              key={idx}
              onClick={() => setActiveTab(step.targetTab)}
              className="group w-full cursor-pointer bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/70 dark:border-zinc-800/70 light:border-zinc-200 rounded-xl p-3 hover:border-zinc-600 dark:hover:border-zinc-600 light:hover:border-zinc-400 hover:bg-zinc-900/60 dark:hover:bg-zinc-900/60 light:hover:bg-zinc-100 transition relative shadow-sm text-left"
              title={`Click to open ${step.phase}`}
              aria-label={`Open ${step.phase}: ${step.desc}`}
            >
              <div className="text-[10px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-500 flex items-center justify-between">
                <span>PHASE {idx + 1}</span>
                <ChevronRight className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
              </div>
              <div className="font-semibold text-xs text-zinc-200 dark:text-zinc-200 light:text-zinc-900 mt-1 group-hover:text-zinc-100">
                {step.phase}
              </div>
              <div className="text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1 leading-snug">
                {step.desc}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
