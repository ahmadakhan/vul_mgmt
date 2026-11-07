import { PageHeading } from './PageHeading';
import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { NormalizedCVE, IntelligenceArticle, IntelligenceMatch } from '../types';
import { useCollection } from '../hooks/useCollection';
import {
  Database,
  Search,
  Flame,
  FileJson,
  X,
  Copy,
  Check,
  Clock,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  RotateCcw,
  Newspaper,
  ExternalLink,
  Inbox,
  Calendar,
} from 'lucide-react';
import { Pagination } from './Pagination';
import { copyText } from '../utils/clipboard';
import { CveLink } from './CveLink';

type DateFilter = 'ALL' | 'IN_SCOPE' | 'RECENT_MODIFIED' | 'RECENT_PUBLISHED';
type SortKey = 'score' | 'published' | 'modified';
type SortOrder = 'asc' | 'desc';

const NEWS_PAGE_SIZE = 20;
const DAY_MS = 24 * 60 * 60 * 1000;

import { formatDate as fmtDate, formatDateTime as fmtDateTime } from '../utils/dateTime';

const timeFormatter = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
const formatTime = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : timeFormatter.format(date);
};

const formatDate = (value: string, timezone?: string) => fmtDate(value, timezone);
const formatDateTime = (value: string, timezone?: string) => fmtDateTime(value, timezone);

const ordinal = (value: number) => {
  const mod100 = value % 100;
  if (mod100 >= 11 && mod100 <= 13) return `${value}th`;
  switch (value % 10) {
    case 1:
      return `${value}st`;
    case 2:
      return `${value}nd`;
    case 3:
      return `${value}rd`;
    default:
      return `${value}th`;
  }
};

const formatEpss = (value: number) => `${(value * 100).toFixed(1)}%`;

const formatPercentile = (value: number) => {
  const percentile = value * 100;
  const rounded = Math.round(percentile);
  const shown = Math.abs(percentile - rounded) < 0.05 ? rounded : Math.round(percentile * 10) / 10;
  return `${ordinal(shown)} pct`;
};

const hasEpssData = (epss: NormalizedCVE['epss'] | undefined) =>
  !!epss && (epss.score > 0 || epss.percentile > 0);

const severityTone = (severity: NormalizedCVE['cvss']['severity']) => {
  switch (severity) {
    case 'CRITICAL':
      return 'border-rose-500/30 bg-rose-500/10 text-rose-300 light:text-rose-800';
    case 'HIGH':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-300 light:text-orange-800';
    case 'MEDIUM':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300 light:text-amber-800';
    case 'LOW':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 light:text-emerald-800';
    default:
      return 'border-zinc-700/60 bg-zinc-800/60 text-zinc-400 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-600';
  }
};

const exploitTone = (status: NormalizedCVE['exploitStatus']) => {
  switch (status) {
    case 'Active Weaponized':
      return 'border-rose-500/30 bg-rose-500/10 text-rose-300 light:text-rose-800';
    case 'Reported In Wild':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-300 light:text-orange-800';
    case 'POC Available':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300 light:text-amber-800';
    default:
      return 'border-zinc-700/60 bg-zinc-800/40 text-zinc-400 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-600';
  }
};

const panel = 'bg-zinc-900/50 light:bg-white border border-zinc-800/80 light:border-zinc-200';
const inputClass =
  'w-full rounded-[10px] border border-zinc-800 bg-zinc-950 py-2 pl-9 pr-9 text-xs text-zinc-100 placeholder-zinc-500 transition focus:border-zinc-600 focus:outline-none light:border-zinc-300 light:bg-zinc-50 light:text-zinc-900';
const filterButtonClass =
  'inline-flex min-h-10 items-center gap-1.5 whitespace-nowrap rounded-[10px] border px-3 text-xs font-medium transition';
const filterButtonIdle =
  'border-zinc-800 bg-zinc-950 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200 light:border-zinc-300 light:bg-white light:text-zinc-600 light:hover:bg-zinc-100 light:hover:text-zinc-900';
const sourceBadgeClass =
  'rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-700';

const CveCacheView: React.FC = () => {
  const { counts, settings, setActiveTab } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [kevFilter, setKevFilter] = useState<'ALL' | 'KEV_ONLY'>('ALL');
  const [epssFilter, setEpssFilter] = useState<'ALL' | 'HIGH_EPSS'>('ALL');
  const [dateFilter, setDateFilter] = useState<DateFilter>('ALL');
  const [sortBy, setSortBy] = useState<SortKey>('modified');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [inspectCve, setInspectCve] = useState<NormalizedCVE | null>(null);
  const [copied, setCopied] = useState(false);

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const scopeHours = settings.scopeHours || 24;
  const now = Date.now();
  const scopeMillis = scopeHours * 60 * 60 * 1000;
  const {
    items: cveData,
    total,
    loading,
  } = useCollection<NormalizedCVE>('cveData', {
    page: currentPage,
    pageSize,
    search: searchTerm,
    sort: sortBy,
    order: sortOrder,
    filters: {
      kev: kevFilter === 'KEV_ONLY',
      epssMin: epssFilter === 'HIGH_EPSS' ? 0.4 : undefined,
      dateFilter,
      scopeHours,
    },
  });

  const totalCves = counts.cveData;
  const startRecord = total === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endRecord = Math.min(total, currentPage * pageSize);
  const hasActiveFilters =
    searchTerm.trim() !== '' || kevFilter !== 'ALL' || epssFilter !== 'ALL' || dateFilter !== 'ALL';

  useEffect(() => {
    if (!inspectCve) return;
    const previousOverflow = document.body.style.overflow;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setInspectCve(null);
    };
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [inspectCve]);

  const resetFilters = () => {
    setSearchTerm('');
    setKevFilter('ALL');
    setEpssFilter('ALL');
    setDateFilter('ALL');
    setCurrentPage(1);
  };

  const handleCopyJson = async () => {
    if (inspectCve && (await copyText(JSON.stringify(inspectCve, null, 2)))) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const openInspector = (cve: NormalizedCVE) => {
    setCopied(false);
    setInspectCve(cve);
  };

  const toggleSort = (column: SortKey) => {
    if (sortBy === column) {
      setSortOrder((previous) => (previous === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortBy(column);
      setSortOrder('desc');
    }
    setCurrentPage(1);
  };

  const sortIcon = (column: SortKey) => {
    if (sortBy !== column) return <ArrowUpDown className="h-3 w-3 opacity-50" aria-hidden="true" />;
    return sortOrder === 'asc' ? (
      <ArrowUp className="h-3 w-3" aria-hidden="true" />
    ) : (
      <ArrowDown className="h-3 w-3" aria-hidden="true" />
    );
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className={`rounded-2xl p-3 shadow-sm transition-colors sm:p-4 ${panel}`}>
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="relative w-full xl:max-w-md">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500"
              aria-hidden="true"
            />
            <input
              type="text"
              aria-label="Search cached CVEs"
              placeholder="Search by CVE, title, source, or CPE…"
              value={searchTerm}
              onChange={(event) => {
                setSearchTerm(event.target.value);
                setCurrentPage(1);
              }}
              className={inputClass}
            />
            {searchTerm && (
              <button
                type="button"
                aria-label="Clear search"
                onClick={() => {
                  setSearchTerm('');
                  setCurrentPage(1);
                }}
                className="absolute right-2 top-1/2 grid h-6 w-6 -translate-y-1/2 place-items-center rounded-md text-zinc-500 transition hover:bg-zinc-800 hover:text-zinc-200 light:hover:bg-zinc-200 light:hover:text-zinc-900"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              id="cve-timeline-filter"
              aria-label="Filter by timeline"
              value={dateFilter}
              onChange={(event) => {
                setDateFilter(event.target.value as DateFilter);
                setCurrentPage(1);
              }}
              className="min-w-[186px] text-xs font-medium text-zinc-200 light:text-zinc-800"
            >
              <option value="ALL">All timeline windows</option>
              <option value="IN_SCOPE">In pipeline scope ({scopeHours}h)</option>
              <option value="RECENT_MODIFIED">Modified in last 7 days</option>
              <option value="RECENT_PUBLISHED">Published in last 7 days</option>
            </select>

            <button
              type="button"
              aria-pressed={kevFilter === 'KEV_ONLY'}
              onClick={() => {
                setKevFilter((value) => (value === 'ALL' ? 'KEV_ONLY' : 'ALL'));
                setCurrentPage(1);
              }}
              className={`${filterButtonClass} ${
                kevFilter === 'KEV_ONLY'
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-300 light:text-amber-800'
                  : filterButtonIdle
              }`}
            >
              <Flame className="h-3.5 w-3.5 text-amber-500" aria-hidden="true" />
              <span>CISA KEV only</span>
            </button>

            <button
              type="button"
              aria-pressed={epssFilter === 'HIGH_EPSS'}
              onClick={() => {
                setEpssFilter((value) => (value === 'ALL' ? 'HIGH_EPSS' : 'ALL'));
                setCurrentPage(1);
              }}
              className={`${filterButtonClass} ${
                epssFilter === 'HIGH_EPSS'
                  ? 'border-sky-500/40 bg-sky-500/10 text-sky-300 light:text-sky-800'
                  : filterButtonIdle
              }`}
            >
              <span>High EPSS ≥ 40%</span>
            </button>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-zinc-800/60 pt-3 text-[11px] text-zinc-500 light:border-zinc-200">
          <span>
            {total === 0 ? (
              'No matching cached CVEs'
            ) : (
              <>
                Showing{' '}
                <strong className="font-mono text-zinc-300 light:text-zinc-800">
                  {startRecord}–{endRecord}
                </strong>{' '}
                of <strong className="font-mono text-zinc-300 light:text-zinc-800">{total}</strong>{' '}
                {hasActiveFilters && <span className="text-zinc-500">({totalCves} total)</span>}
              </>
            )}
          </span>

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="hidden items-center gap-1.5 sm:inline-flex">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
              Published in scope
            </span>
            <span className="hidden items-center gap-1.5 sm:inline-flex">
              <span className="h-1.5 w-1.5 rounded-full bg-sky-500" aria-hidden="true" />
              Modified in scope
            </span>
            {hasActiveFilters && (
              <button
                type="button"
                onClick={resetFilters}
                className="inline-flex items-center gap-1 rounded text-zinc-400 underline-offset-4 transition hover:text-zinc-200 hover:underline light:text-zinc-600 light:hover:text-zinc-900"
              >
                <RotateCcw className="h-3 w-3" aria-hidden="true" />
                Reset filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className={`overflow-hidden rounded-2xl shadow-sm transition-colors ${panel}`}>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1120px] text-left text-xs">
            <caption className="sr-only">Threat intelligence feed cache records</caption>
            <thead className="border-b border-zinc-800/80 bg-zinc-950/80 text-[11px] font-mono uppercase text-zinc-400 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-600">
              <tr>
                <th scope="col" className="min-w-[220px] px-4 py-3">
                  Canonical CVE
                </th>
                <th
                  scope="col"
                  aria-sort={sortBy === 'score' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}
                  className="px-4 py-3"
                >
                  <button
                    type="button"
                    onClick={() => toggleSort('score')}
                    className="-mx-1 flex select-none items-center gap-1 whitespace-nowrap rounded px-1 py-0.5 transition hover:bg-zinc-800/40 hover:text-zinc-200 light:hover:bg-zinc-200/60 light:hover:text-zinc-900"
                    title="Sort by CVSS score, then EPSS"
                  >
                    <span>CVSS score</span>
                    {sortIcon('score')}
                  </button>
                </th>
                <th scope="col" className="px-4 py-3">
                  EPSS percentile
                </th>
                <th
                  scope="col"
                  aria-sort={
                    sortBy === 'published' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'
                  }
                  className="px-4 py-3"
                >
                  <button
                    type="button"
                    onClick={() => toggleSort('published')}
                    className="-mx-1 flex select-none items-center gap-1 whitespace-nowrap rounded px-1 py-0.5 transition hover:bg-zinc-800/40 hover:text-zinc-200 light:hover:bg-zinc-200/60 light:hover:text-zinc-900"
                    title="Sort by published date"
                  >
                    <span>Published</span>
                    {sortIcon('published')}
                  </button>
                </th>
                <th
                  scope="col"
                  aria-sort={
                    sortBy === 'modified' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'
                  }
                  className="px-4 py-3"
                >
                  <button
                    type="button"
                    onClick={() => toggleSort('modified')}
                    className="-mx-1 flex select-none items-center gap-1 whitespace-nowrap rounded px-1 py-0.5 transition hover:bg-zinc-800/40 hover:text-zinc-200 light:hover:bg-zinc-200/60 light:hover:text-zinc-900"
                    title="Sort by last modified date"
                  >
                    <span>Last modified</span>
                    {sortIcon('modified')}
                  </button>
                </th>
                <th scope="col" className="px-4 py-3">
                  Exploit status
                </th>
                <th scope="col" className="px-4 py-3">
                  Sources ingested
                </th>
                <th scope="col" className="px-4 py-3 text-right">
                  Inspect
                </th>
              </tr>
            </thead>
            <tbody>
              {cveData.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-16 text-center">
                    <div className="mx-auto flex max-w-sm flex-col items-center">
                      <span className="grid h-11 w-11 place-items-center rounded-xl border border-zinc-800 bg-zinc-950 text-zinc-500 light:border-zinc-300 light:bg-zinc-100">
                        <Inbox className="h-5 w-5" aria-hidden="true" />
                      </span>
                      <p className="mt-3 text-sm font-semibold text-zinc-300 light:text-zinc-800">
                        {totalCves === 0 ? 'No cached CVE records yet' : 'No CVEs match these filters'}
                      </p>
                      <p className="mt-1 text-xs leading-relaxed text-zinc-500">
                        {totalCves === 0
                          ? 'Run a pipeline to ingest and normalize threat feed records into the cache.'
                          : 'Adjust the timeline, KEV, EPSS, or search filters to widen the result set.'}
                      </p>
                      <button
                        type="button"
                        onClick={hasActiveFilters ? resetFilters : () => setActiveTab('pipeline')}
                        className="mt-4 inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800 px-3 text-xs font-medium text-zinc-200 transition hover:bg-zinc-700 light:border-zinc-300 light:bg-white light:text-zinc-800 light:hover:bg-zinc-100"
                      >
                        {hasActiveFilters ? (
                          <>
                            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                            Reset filters
                          </>
                        ) : (
                          'Open pipeline'
                        )}
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                cveData.map((cve) => {
                  const pubTime = new Date(cve.publishedDate).getTime();
                  const modTime = new Date(cve.modifiedDate).getTime();
                  const pubInScope = now - pubTime <= scopeMillis;
                  const modInScope = now - modTime <= scopeMillis;
                  // Legacy cache rows can predate fields that are now required
                  // by the schema; default them rather than crashing the table.
                  const cvss = cve.cvss ?? {
                    version: 'UNKNOWN' as const,
                    score: 0,
                    vector: '',
                    severity: 'UNKNOWN' as const,
                  };
                  const epss = cve.epss ?? { score: 0, percentile: 0 };
                  const isKev = cve.cisaKev?.isKev ?? false;
                  const scored = cvss.version !== 'UNKNOWN';
                  const epssScored = hasEpssData(epss);

                  return (
                    <tr key={cve.cveId} className="transition hover:bg-zinc-800/30 light:hover:bg-zinc-50">
                      <td className="min-w-[220px] px-4 py-3">
                        <div className="flex items-center gap-2">
                          <CveLink cveId={cve.cveId} className="whitespace-nowrap" />
                          {isKev && (
                            <span
                              className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-medium text-amber-300 light:text-amber-800"
                              title="Listed in the CISA Known Exploited Vulnerabilities catalog"
                            >
                              <Flame className="h-3 w-3" aria-hidden="true" />
                              KEV
                            </span>
                          )}
                        </div>
                        <div className="mt-0.5 line-clamp-1 max-w-xs text-xs text-zinc-400 light:text-zinc-600">
                          {cve.title || 'No title provided'}
                        </div>
                      </td>

                      <td className="px-4 py-3 font-mono">
                        <div className="flex items-center gap-1.5">
                          <span className="text-sm font-semibold text-zinc-200 light:text-zinc-900">
                            {scored ? cvss.score.toFixed(1) : 'Unscored'}
                          </span>
                          {scored && (
                            <span
                              className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium ${severityTone(
                                cvss.severity,
                              )}`}
                            >
                              {cvss.severity}
                            </span>
                          )}
                        </div>
                        {scored && cvss.vector && (
                          <div
                            className="mt-0.5 max-w-[150px] truncate text-[10px] text-zinc-500"
                            title={cvss.vector}
                          >
                            {cvss.vector}
                          </div>
                        )}
                      </td>

                      <td className="px-4 py-3 font-mono">
                        {epssScored ? (
                          <>
                            <div
                              className={`font-medium ${
                                epss.score >= 0.4
                                  ? 'text-amber-300 light:text-amber-800'
                                  : 'text-zinc-300 light:text-zinc-800'
                              }`}
                            >
                              {formatEpss(epss.score)}
                            </div>
                            <div className="text-[10px] text-zinc-500" title="EPSS percentile">
                              {formatPercentile(epss.percentile)}
                            </div>
                          </>
                        ) : (
                          <span className="text-zinc-500" title="No EPSS score available">
                            Not scored
                          </span>
                        )}
                      </td>

                      <td className="px-4 py-3 font-mono text-[11px]">
                        <div className="flex items-center gap-1.5 whitespace-nowrap text-zinc-300 light:text-zinc-800">
                          <span>{formatDate(cve.publishedDate)}</span>
                          {pubInScope && (
                            <span
                              className="h-1.5 w-1.5 rounded-full bg-emerald-500"
                              title="Published inside the current pipeline scope window"
                              aria-label="Published inside the current pipeline scope window"
                            />
                          )}
                        </div>
                        <div className="text-[10px] text-zinc-500">{formatTime(cve.publishedDate)}</div>
                      </td>

                      <td className="px-4 py-3 font-mono text-[11px]">
                        <div className="flex items-center gap-1.5 whitespace-nowrap text-zinc-300 light:text-zinc-800">
                          <span>{formatDate(cve.modifiedDate)}</span>
                          {modInScope && (
                            <span
                              className="h-1.5 w-1.5 rounded-full bg-sky-500"
                              title="Last modified inside the current pipeline scope window"
                              aria-label="Last modified inside the current pipeline scope window"
                            />
                          )}
                        </div>
                        <div className="text-[10px] text-zinc-500">{formatTime(cve.modifiedDate)}</div>
                      </td>

                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex rounded-full border px-2 py-0.5 font-mono text-[10px] font-medium ${exploitTone(
                            cve.exploitStatus,
                          )}`}
                        >
                          {cve.exploitStatus}
                        </span>
                      </td>

                      <td className="px-4 py-3">
                        {cve.sourceFeeds.length ? (
                          <div
                            className="flex max-w-[220px] flex-wrap gap-1"
                            title={cve.sourceFeeds.join(', ')}
                          >
                            {cve.sourceFeeds.map((source, index) => (
                              <span key={`${source}-${index}`} className={sourceBadgeClass}>
                                {source}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-zinc-500">—</span>
                        )}
                      </td>

                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => openInspector(cve)}
                          aria-label={`Inspect normalized JSON for ${cve.cveId}`}
                          className="inline-flex items-center gap-1.5 rounded-[10px] border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs font-medium text-zinc-400 transition hover:border-zinc-700 hover:text-zinc-200 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-600 light:hover:bg-zinc-200 light:hover:text-zinc-900"
                        >
                          <FileJson className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <Pagination
          currentPage={currentPage}
          totalItems={total}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
          pageSizeOptions={[10, 25, 50]}
        />
      </div>

      {/* Raw JSON Modal */}
      {inspectCve && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/75 p-3 backdrop-blur-sm sm:p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setInspectCve(null);
          }}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="cve-inspector-title"
            className="flex max-h-[calc(100dvh-1.5rem)] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-900 shadow-2xl light:border-zinc-200 light:bg-white sm:max-h-[calc(100dvh-2rem)]"
          >
            <div className="flex flex-col gap-3 border-b border-zinc-800/80 px-4 py-4 light:border-zinc-200 sm:flex-row sm:items-start sm:justify-between sm:px-5">
              <div className="min-w-0">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
                  Normalized ingestion record
                </p>
                <h2
                  id="cve-inspector-title"
                  className="mt-1 flex flex-wrap items-center gap-2 text-base font-semibold text-zinc-100 light:text-zinc-900"
                >
                  <CveLink cveId={inspectCve.cveId} />
                </h2>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopyJson}
                  aria-live="polite"
                  className="inline-flex min-h-8 items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800 px-2.5 py-1 text-xs font-medium text-zinc-200 transition hover:bg-zinc-700 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-800 light:hover:bg-zinc-200"
                >
                  {copied ? (
                    <Check
                      className="h-3.5 w-3.5 text-emerald-400 light:text-emerald-700"
                      aria-hidden="true"
                    />
                  ) : (
                    <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setInspectCve(null)}
                  aria-label="Close record inspector"
                  className="grid h-8 w-8 place-items-center rounded-lg text-zinc-500 transition hover:bg-zinc-800 hover:text-zinc-200 light:hover:bg-zinc-100 light:hover:text-zinc-900"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>
            </div>

            <div className="overflow-y-auto">
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-b border-zinc-800/80 bg-zinc-950/40 px-4 py-4 text-[11px] light:border-zinc-200 light:bg-zinc-50 sm:grid-cols-4 sm:px-5">
                <div>
                  <dt className="text-zinc-500">Published</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200 light:text-zinc-800">
                    {formatDate(inspectCve.publishedDate)}
                    <span className="block text-[10px] text-zinc-500">
                      {formatTime(inspectCve.publishedDate)}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Last modified</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200 light:text-zinc-800">
                    {formatDate(inspectCve.modifiedDate)}
                    <span className="block text-[10px] text-zinc-500">
                      {formatTime(inspectCve.modifiedDate)}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">EPSS</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200 light:text-zinc-800">
                    {hasEpssData(inspectCve.epss)
                      ? `${formatEpss(inspectCve.epss?.score ?? 0)} · ${formatPercentile(
                          inspectCve.epss?.percentile ?? 0,
                        )}`
                      : 'Not scored'}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">CISA KEV</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200 light:text-zinc-800">
                    {inspectCve.cisaKev?.isKev ? 'Known exploited' : '—'}
                  </dd>
                </div>
                <div className="col-span-2 sm:col-span-4">
                  <dt className="text-zinc-500">Ingested from</dt>
                  <dd className="mt-1 flex flex-wrap gap-1">
                    {inspectCve.sourceFeeds?.length ? (
                      inspectCve.sourceFeeds.map((source, index) => (
                        <span key={`${source}-${index}`} className={sourceBadgeClass}>
                          {source}
                        </span>
                      ))
                    ) : (
                      <span className="text-zinc-500">No source metadata</span>
                    )}
                  </dd>
                </div>
              </dl>

              <div className="px-4 pb-4 pt-4 sm:px-5 sm:pb-5">
                <div className="mb-2 flex items-center justify-between gap-2 text-[11px] text-zinc-500">
                  <span className="font-mono">JSON payload</span>
                  <span>{formatDateTime(inspectCve.modifiedDate)}</span>
                </div>
                <pre className="max-h-[55dvh] overflow-auto rounded-xl border border-zinc-800 bg-zinc-950 p-4 font-mono text-[11px] leading-relaxed text-zinc-300 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-800">
                  {JSON.stringify(inspectCve, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const NewsEvidenceView: React.FC = () => {
  const { counts, fetchCollection, setActiveTab, settings } = useApp();
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const { items: articles, total } = useCollection<IntelligenceArticle>('intelligenceArticles', {
    page,
    pageSize: NEWS_PAGE_SIZE,
    search: query,
    sort: 'published',
    order: 'desc',
  });
  const [matches, setMatches] = useState<IntelligenceMatch[]>([]);
  useEffect(() => {
    if (!articles.length) {
      setMatches([]);
      return;
    }
    let active = true;
    fetchCollection<IntelligenceMatch>('intelligenceMatches', {
      page: 1,
      pageSize: 500,
      filters: { articleIds: articles.map((article) => article.id) },
    })
      .then((result) => {
        if (active) setMatches(result.items);
      })
      .catch(() => {
        if (active) setMatches([]);
      });
    return () => {
      active = false;
    };
  }, [articles, fetchCollection]);

  return (
    <div role="tabpanel" id="threat-news-panel" aria-labelledby="threat-news-tab" className="space-y-4">
      <div className={`rounded-2xl p-3 shadow-sm transition-colors sm:p-4 ${panel}`}>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full sm:max-w-md">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500"
              aria-hidden="true"
            />
            <input
              type="text"
              aria-label="Search news and advisory evidence"
              placeholder="Search title, CVE, or summary…"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
              className={inputClass}
            />
            {query && (
              <button
                type="button"
                aria-label="Clear search"
                onClick={() => {
                  setQuery('');
                  setPage(1);
                }}
                className="absolute right-2 top-1/2 grid h-6 w-6 -translate-y-1/2 place-items-center rounded-md text-zinc-500 transition hover:bg-zinc-800 hover:text-zinc-200 light:hover:bg-zinc-200 light:hover:text-zinc-900"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>
          <p className="text-[11px] text-zinc-500">
            {total === counts.intelligenceArticles
              ? `${total} article${total === 1 ? '' : 's'}`
              : `${total} of ${counts.intelligenceArticles} articles`}
          </p>
        </div>
      </div>

      {total === 0 ? (
        <div className={`rounded-2xl px-4 py-16 text-center shadow-sm ${panel}`}>
          <div className="mx-auto flex max-w-sm flex-col items-center">
            <span className="grid h-11 w-11 place-items-center rounded-xl border border-zinc-800 bg-zinc-950 text-zinc-500 light:border-zinc-300 light:bg-zinc-100">
              <Newspaper className="h-5 w-5" aria-hidden="true" />
            </span>
            <p className="mt-3 text-sm font-semibold text-zinc-300 light:text-zinc-800">
              {counts.intelligenceArticles === 0
                ? 'No news or advisory evidence'
                : 'No articles match your search'}
            </p>
            <p className="mt-1 text-xs leading-relaxed text-zinc-500">
              {counts.intelligenceArticles === 0
                ? 'Enable an RSS or Atom source and run ingestion to collect vendor advisories.'
                : 'Try a broader title, CVE, or summary search.'}
            </p>
            <button
              type="button"
              onClick={counts.intelligenceArticles === 0 ? () => setActiveTab('feeds') : () => setQuery('')}
              className="mt-4 inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800 px-3 text-xs font-medium text-zinc-200 transition hover:bg-zinc-700 light:border-zinc-300 light:bg-white light:text-zinc-800 light:hover:bg-zinc-100"
            >
              {counts.intelligenceArticles === 0 ? 'Open feed sources' : 'Clear search'}
            </button>
          </div>
        </div>
      ) : (
        <div className="grid gap-3">
          {articles.map((article) => {
            const articleMatches = matches.filter((match) => match.articleIds.includes(article.id));
            return (
              <article
                key={article.id}
                className={`rounded-2xl p-4 shadow-sm transition-colors sm:p-5 ${panel}`}
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <a
                    className="group inline-flex min-w-0 items-start gap-1.5 text-sm font-semibold text-blue-400 underline-offset-4 hover:underline light:text-blue-700"
                    href={(() => {
                      try {
                        const u = new URL(article.url);
                        return ['http:', 'https:'].includes(u.protocol) ? article.url : '#';
                      } catch {
                        return '#';
                      }
                    })()}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <span>{article.title}</span>
                    <ExternalLink
                      className="mt-0.5 h-3.5 w-3.5 shrink-0 opacity-60 transition group-hover:opacity-100"
                      aria-hidden="true"
                    />
                  </a>
                  <div className="flex flex-wrap gap-1">
                    {article.sourceFeeds.map((source, index) => (
                      <span key={`${source}-${index}`} className={sourceBadgeClass}>
                        {source}
                      </span>
                    ))}
                  </div>
                </div>

                <p className="mt-1.5 flex items-center gap-1.5 text-[11px] text-zinc-500">
                  <Calendar className="h-3 w-3" aria-hidden="true" />
                  {formatDateTime(article.publishedDate, settings.timezone)}
                </p>

                <p className="mt-3 text-xs leading-relaxed text-zinc-400 light:text-zinc-600">
                  {article.summary}
                </p>

                <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px]">
                  <span className="font-medium text-zinc-500">CVE references</span>
                  {article.cveIds.length ? (
                    <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      {article.cveIds.map((cveId, index) => (
                        <React.Fragment key={cveId}>
                          {index > 0 && <span className="text-zinc-600">·</span>}
                          <CveLink cveId={cveId} />
                        </React.Fragment>
                      ))}
                    </span>
                  ) : (
                    <span className="text-zinc-500">No explicit CVE reference</span>
                  )}
                </div>

                {articleMatches.length > 0 && (
                  <div className="mt-3 space-y-2 border-t border-zinc-800/60 pt-3 light:border-zinc-200">
                    {articleMatches.map((match) => (
                      <div key={match.id} className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3">
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs font-medium text-zinc-200 light:text-zinc-800">
                          <span>{match.assetName}</span>
                          <span className="text-zinc-600">·</span>
                          {match.cveId ? (
                            <CveLink cveId={match.cveId} />
                          ) : (
                            <span className="text-zinc-500">CVE unassigned</span>
                          )}
                          <span
                            className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                              match.status === 'CORROBORATED'
                                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 light:text-emerald-800'
                                : 'border-amber-500/30 bg-amber-500/10 text-amber-300 light:text-amber-800'
                            }`}
                          >
                            {match.status === 'CORROBORATED' ? 'Corroborated' : 'Review required'}
                          </span>
                        </div>
                        <p className="mt-1 text-xs leading-relaxed text-zinc-500">{match.evidence}</p>
                      </div>
                    ))}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}

      {total > 0 && (
        <div className={`overflow-hidden rounded-2xl shadow-sm ${panel}`}>
          <Pagination
            currentPage={page}
            totalItems={total}
            pageSize={NEWS_PAGE_SIZE}
            onPageChange={setPage}
          />
        </div>
      )}
    </div>
  );
};

export const ThreatDataView: React.FC = () => {
  const [tab, setTab] = useState<'cves' | 'news'>('cves');
  const { counts, settings } = useApp();
  const scopeHours = settings.scopeHours || 24;

  const tabClass = (active: boolean) =>
    `inline-flex min-h-9 flex-1 items-center justify-center gap-2 rounded-[9px] px-3 text-xs font-semibold transition sm:flex-none ${
      active
        ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-white light:text-zinc-900'
        : 'text-zinc-400 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
    }`;

  return (
    <div className="space-y-5">
      <header className="ui-page-header">
        <PageHeading page="threat-data">
          Normalized CVE records unified from NVD, OpenCVE, FIRST.org EPSS, CISA KEV, and VulnCheck. Records
          are correlated by both published and last-modified dates.
        </PageHeading>

        <span className="inline-flex items-center gap-2 self-start rounded-xl border border-zinc-800 bg-zinc-900/60 px-3 py-2 text-[11px] font-medium text-zinc-400 shadow-sm light:border-zinc-200 light:bg-white light:text-zinc-600">
          <Clock className="h-3.5 w-3.5 text-emerald-400 light:text-emerald-700" aria-hidden="true" />
          <span>{scopeHours}h pipeline scope</span>
          <span className="h-3 w-px bg-zinc-700 light:bg-zinc-300" aria-hidden="true" />
          <span className="font-mono text-zinc-300 light:text-zinc-800">{counts.cveData} cached</span>
        </span>
      </header>

      <div
        role="tablist"
        aria-label="Threat intelligence views"
        className="inline-flex w-full max-w-full flex-wrap gap-1 rounded-xl border border-zinc-800/80 bg-zinc-950/60 p-1 light:border-zinc-200 light:bg-zinc-100 sm:w-auto"
      >
        <button
          type="button"
          role="tab"
          id="threat-cves-tab"
          aria-selected={tab === 'cves'}
          aria-controls="threat-cves-panel"
          onClick={() => setTab('cves')}
          className={tabClass(tab === 'cves')}
        >
          <Database className="h-3.5 w-3.5" aria-hidden="true" />
          <span>CVE cache</span>
          <span
            className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] ${
              tab === 'cves'
                ? 'bg-zinc-950/80 text-zinc-300 light:bg-zinc-100 light:text-zinc-700'
                : 'bg-zinc-800/60 text-zinc-500 light:bg-zinc-200/70 light:text-zinc-600'
            }`}
          >
            {counts.cveData}
          </span>
        </button>
        <button
          type="button"
          role="tab"
          id="threat-news-tab"
          aria-selected={tab === 'news'}
          aria-controls="threat-news-panel"
          onClick={() => setTab('news')}
          className={tabClass(tab === 'news')}
        >
          <Newspaper className="h-3.5 w-3.5" aria-hidden="true" />
          <span>News &amp; advisory evidence</span>
          <span
            className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] ${
              tab === 'news'
                ? 'bg-zinc-950/80 text-zinc-300 light:bg-zinc-100 light:text-zinc-700'
                : 'bg-zinc-800/60 text-zinc-500 light:bg-zinc-200/70 light:text-zinc-600'
            }`}
          >
            {counts.intelligenceArticles}
          </span>
        </button>
      </div>

      {tab === 'cves' ? (
        <div role="tabpanel" id="threat-cves-panel" aria-labelledby="threat-cves-tab">
          <CveCacheView />
        </div>
      ) : (
        <NewsEvidenceView />
      )}
    </div>
  );
};
