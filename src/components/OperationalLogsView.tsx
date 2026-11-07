import { PageHeading } from './PageHeading';
import React, { useState, useEffect, useRef } from 'react';
import { useApp } from '../context/AppContext';
import { EVENT_CATEGORIES, OperationalEvent, AuditLog } from '../types';
import {
  FileCode2,
  Search,
  Download,
  Filter,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RotateCw,
  Cpu,
  LogOut,
  ChevronRight,
  X,
  UserRound,
  Clock3,
  Brain,
  Server,
  Trash2,
} from 'lucide-react';
import { Pagination } from './Pagination';
import { csvCell } from '../utils/csv';
import { useCollection } from '../hooks/useCollection';
import { LogDetailModal } from './LogDetailModal';
import { EventDetailPanel } from './EventDetailPanel';
import { formatEventContext } from '../utils/eventText';
import { SecondaryButton } from './SecondaryButton';
import { formatDateTime as fmtDateTime, formatDate, timezoneLabel, resolveTimezone, utcOffsetLabel } from '../utils/dateTime';
import './investigation-pages.css';
import './audit-trail.css';
import './logs-view.css';
import { MlLogsView } from './MlLogsView';
import { SystemLogsView } from './SystemLogsView';

const AUDIT_CATEGORIES: Record<AuditLog['category'], string> = {
  PIPELINE: 'Pipeline',
  SECURITY: 'Security',
  FEED: 'Feed ingestion',
  WATCHLIST: 'Monitored products',
  EMAIL: 'Email dispatch',
  WEBHOOK: 'Webhooks',
};
const auditCategory = (category: AuditLog['category']) => AUDIT_CATEGORIES[category] || category;
const auditLevel = (level: AuditLog['level']) => (
  <span className={`audit-level level-${level.toLowerCase()}`}>
    <span aria-hidden="true" />
    {level === 'INFO' ? 'Info' : level === 'WARNING' ? 'Warning' : 'Error'}
  </span>
);

const AuditTrailView: React.FC = () => {
  const { fetchCollection, verifyAuditChainRemote, settings, csrfToken, session } = useApp();
  const canDeleteLogs = session?.role === 'ADMIN';
  const [searchTerm, setSearchTerm] = useState('');
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState('');
  const displayTimezone = timezoneLabel(settings.timezone);
  const timestampFormatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: resolveTimezone(settings.timezone),
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  });
  const formatAuditTimestamp = (value: string) => {
    const date = new Date(value);
    if (!value || Number.isNaN(date.getTime())) return 'Not recorded';
    return `${timestampFormatter.format(date)} ${utcOffsetLabel(date, settings.timezone)}`;
  };
  const outcomeLabel = (log: AuditLog) => {
    switch (log.context?.outcome) {
      case 'SUCCESS': return 'Success';
      case 'FAILURE': return 'Failure';
      case 'DENIED': return 'Denied';
      case 'RECORDED': return 'Recorded';
      default: return 'Not recorded';
    }
  };
  const resourceLabel = (log: AuditLog) =>
    [log.context?.resourceType, log.context?.resourceId].filter(Boolean).join(' / ');
  const compactDetails = (log: AuditLog) => {
    const resourcePrefix = log.context?.resourceId ? `Resource: ${log.context.resourceId}.` : '';
    return resourcePrefix && log.details?.startsWith(resourcePrefix)
      ? log.details.slice(resourcePrefix.length).trim()
      : log.details;
  };
  const renderOutcome = (log: AuditLog) => (
    <span className={`audit-outcome outcome-${(log.context?.outcome || 'unknown').toLowerCase()}`}>
      {outcomeLabel(log)}
    </span>
  );

  // Cryptographic Chain Verification State
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [chainVerified, setChainVerified] = useState<boolean | null>(null);
  const [verificationSnapshot, setVerificationSnapshot] = useState<{ logCount: number; checkedAt: string; root: string } | null>(null);
  const [verificationError, setVerificationError] = useState('');
  const hasFilters = Boolean(searchTerm || categoryFilter !== 'ALL' || levelFilter !== 'ALL');
  const clearFilters = () => {
    setSearchTerm('');
    setCategoryFilter('ALL');
    setLevelFilter('ALL');
    setCurrentPage(1);
  };

  // Verification always runs against the full server-side chain; the snapshot
  // only contains the newest capped slice and cannot prove global integrity.

  const handleVerifyChain = async () => {
    setVerifyingChain(true);
    setChainVerified(null);
    setVerificationSnapshot(null);
    setVerificationError('');
    try {
      const result = await verifyAuditChainRemote();
      if (result) {
        setChainVerified(result.verified);
        setVerificationSnapshot({ logCount: result.logCount, checkedAt: new Date().toISOString(), root: result.merkleRoot });
      }
      else
        setVerificationError('Verification could not be completed. Try again when the server is available.');
    } catch {
      setVerificationError('Verification could not be completed. Please retry.');
    } finally {
      setVerifyingChain(false);
    }
  };

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const filters = { category: categoryFilter, level: levelFilter };
  const {
    items: paginatedLogs,
    total,
    loading: logsLoading,
    reload,
  } = useCollection<AuditLog>('auditLogs', {
    page: currentPage,
    pageSize,
    search: searchTerm,
    filters,
  });

  useEffect(() => {
    const lastPage = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > lastPage) setCurrentPage(lastPage);
  }, [currentPage, total, pageSize]);

  /** Exports honor the active filters and walk every server page. */
  const loadAllLogs = async () => {
    const size = 1000;
    const first = await fetchCollection<AuditLog>('auditLogs', {
      page: 1,
      pageSize: size,
      search: searchTerm,
      filters,
    });
    const all = [...first.items];
    for (let page = 2; all.length < first.total; page++) {
      const next = await fetchCollection<AuditLog>('auditLogs', {
        page,
        pageSize: size,
        search: searchTerm,
        filters,
      });
      if (!next.items.length) break;
      all.push(...next.items);
    }
    return all;
  };

  const downloadExport = (content: string, format: 'json' | 'csv') => {
    const url = URL.createObjectURL(new Blob([content], {
      type: format === 'json' ? 'application/json;charset=utf-8' : 'text/csv;charset=utf-8',
    }));
    const anchor = document.createElement('a');
    try {
      anchor.href = url;
      anchor.download = `audit-trail-${new Date().toISOString().split('T')[0]}.${format}`;
      document.body.appendChild(anchor);
      anchor.click();
    } finally {
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  };

  const handleExportJson = async () => {
    if (total === 0 || logsLoading || exporting) return;
    setExporting(true);
    setExportError('');
    try {
      const logs = await loadAllLogs();
      downloadExport(JSON.stringify(logs, null, 2), 'json');
    } catch {
      setExportError('Could not export the audit trail. Please retry.');
    } finally {
      setExporting(false);
    }
  };

  const handleExportCsv = async () => {
    if (total === 0 || logsLoading || exporting) return;
    setExporting(true);
    setExportError('');
    try {
      const logs = await loadAllLogs();
      const headers = [
        'ID', 'Timestamp (ISO 8601)', 'Category', 'Level', 'Event', 'Details', 'Actor', 'IP',
        'Action', 'Resource type', 'Resource ID', 'Request ID', 'Outcome', 'Fields supplied (JSON)',
        'Entry hash', 'Previous entry hash',
      ];
      const rows = logs.map((l) => [
        l.id,
        l.timestamp,
        l.category,
        l.level,
        l.event,
        l.details,
        l.actor,
        l.ipAddress,
        l.context?.action || '',
        l.context?.resourceType || '',
        l.context?.resourceId || '',
        l.context?.requestId || '',
        l.context?.outcome || '',
        l.context?.fields ? JSON.stringify(l.context.fields) : '',
        l.hash || '',
        l.prevHash || '',
      ]);
      const csvContent = [headers.join(','), ...rows.map((e) => e.map(csvCell).join(','))].join('\n');
      downloadExport(csvContent, 'csv');
    } catch {
      setExportError('Could not export the audit trail. Please retry.');
    } finally {
      setExporting(false);
    }
  };

  const [deleteDropdownOpen, setDeleteDropdownOpen] = useState(false);
  const [deleteDays, setDeleteDays] = useState<string>('30');
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [deleteSuccess, setDeleteSuccess] = useState('');

  const handleDeleteLogs = async () => {
    if (!canDeleteLogs || deleting || total === 0) return;
    const days = parseInt(deleteDays, 10);
    if (!Number.isFinite(days) || days <= 0) {
      setDeleteError('Please select a valid number of days');
      return;
    }
    setDeleting(true);
    setDeleteError('');
    setDeleteSuccess('');
    try {
      const response = await fetch('/api/audit/cleanup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify({ days }),
      });
      if (!response.ok) {
        const error = await response.json().catch(() => ({ message: 'Failed to delete logs' }));
        throw new Error(error.message || 'Failed to delete logs');
      }
      const result = await response.json();
      setDeleteSuccess(`Deleted ${result.deleted} audit log entries older than ${days} days`);
      reload();
    } catch (error) {
      setDeleteError(error instanceof Error ? error.message : 'Failed to delete logs. Please retry.');
    } finally {
      setDeleting(false);
      setDeleteDropdownOpen(false);
    }
  };

  return (
    <div
      id="logs-audit-panel"
      role="tabpanel"
      aria-labelledby="logs-audit-tab"
      className="audit-trail-panel space-y-6"
    >
      {/* Header */}
      <div className="ui-page-header audit-page-header">
        <div className="audit-page-heading">
          <span className="audit-page-icon" aria-hidden="true">
            <ShieldCheck size={20} />
          </span>
          <div>
            <h2 className="investigation-section-title">Administrative actions</h2>
            <p className="investigation-section-description">
              Review workspace activity, actors and request outcomes. Times in {displayTimezone}.
            </p>
          </div>
        </div>

        <div
          className="audit-header-actions flex flex-wrap items-center gap-2"
          role="group"
          aria-label="Audit trail actions"
        >
          <SecondaryButton title="Refresh audit entries" icon={<RotateCw size={14} />} loading={logsLoading} onClick={reload}>
            Refresh
          </SecondaryButton>
          <SecondaryButton
            title={total === 0 ? 'No matching entries' : 'Export all matching entries as CSV'}
            disabled={total === 0 || logsLoading}
            icon={<Download className="h-3.5 w-3.5" />}
            loading={exporting}
            onClick={() => void handleExportCsv()}
          >
            Export CSV
          </SecondaryButton>
          <SecondaryButton
            title={total === 0 ? 'No matching entries' : 'Export all matching entries as JSON'}
            disabled={total === 0 || logsLoading}
            icon={<Download className="h-3.5 w-3.5" />}
            loading={exporting}
            onClick={() => void handleExportJson()}
          >
            Export JSON
          </SecondaryButton>
          <div className="relative" role="group" aria-label="Delete audit logs" hidden={!canDeleteLogs}>
            <SecondaryButton
              title="Delete audit logs older than selected days"
              disabled={total === 0 || logsLoading || deleting}
              icon={<Trash2 className="h-3.5 w-3.5" />}
              onClick={() => setDeleteDropdownOpen(!deleteDropdownOpen)}
              className="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 light:hover:bg-rose-500/10"
            >
              Delete logs
            </SecondaryButton>
            {deleteDropdownOpen && (
              <div className="absolute right-0 top-full mt-1 z-20 rounded-xl border border-zinc-700 bg-zinc-900 py-1.5 shadow-lg min-w-[180px] light:border-zinc-200 light:bg-white">
                <div className="px-3 py-2 border-b border-zinc-700 light:border-zinc-200">
                  <p className="text-xs font-medium text-zinc-400 light:text-zinc-600">Delete logs older than</p>
                </div>
                <select
                  value={deleteDays}
                  onChange={(e) => setDeleteDays(e.target.value)}
                  onBlur={() => setTimeout(() => setDeleteDropdownOpen(false), 100)}
                  className="w-full px-3 py-2 text-xs text-zinc-100 bg-zinc-900 border-none focus:outline-none light:text-zinc-900 light:bg-white"
                >
                  <option value="7">7 days</option>
                  <option value="30">30 days</option>
                  <option value="90">90 days</option>
                  <option value="365">1 year</option>
                </select>
                <div className="px-3 py-2 border-t border-zinc-700 light:border-zinc-200 flex gap-1.5">
                  <SecondaryButton
                    disabled={deleting}
                    loading={deleting}
                    onClick={handleDeleteLogs}
                    className="flex-1 text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 light:hover:bg-rose-500/10"
                  >
                    {deleting ? 'Deleting…' : 'Confirm delete'}
                  </SecondaryButton>
                  <SecondaryButton
                    disabled={deleting}
                    onClick={() => setDeleteDropdownOpen(false)}
                    className="flex-1"
                  >
                    Cancel
                  </SecondaryButton>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div
        className={`audit-integrity ${chainVerified === true ? 'is-verified' : chainVerified === false ? 'is-failed' : ''}`}
        role="region"
        aria-label="Audit trail integrity"
      >
        <span className="investigation-icon">
          <ShieldCheck size={23} aria-hidden="true" />
        </span>
        <div aria-live="polite" aria-atomic="true">
          <h3>
            {verifyingChain
              ? 'Checking audit integrity…'
              : chainVerified === true
                ? 'Last retained-chain check passed'
                : chainVerified === false
                  ? 'Last retained-chain check failed'
                  : 'Retained chain integrity'}
          </h3>
          <p>
            {chainVerified === false
              ? 'The retained records did not pass verification. Review the audit chain before relying on this export.'
              : 'Checks the full retained server-side chain, not just this page. External anchoring is not checked.'}
          </p>
          {verificationSnapshot && (
            <>
              <p>
                {verificationSnapshot.logCount.toLocaleString()} retained entries checked at{' '}
                {formatAuditTimestamp(verificationSnapshot.checkedAt)}.
                {' '}Later entries are not covered by this check.
              </p>
              <details className="audit-integrity-proof">
                <summary>Verification fingerprint</summary>
                <code aria-label="Audit Merkle root">{verificationSnapshot.root}</code>
              </details>
            </>
          )}
        </div>
        <div className="audit-integrity-actions">
          <SecondaryButton
            title="Verify the full retained server-side audit chain"
            icon={
              verifyingChain ? (
                <RotateCw className="h-3.5 w-3.5 animate-spin text-zinc-400" />
              ) : chainVerified === true ? (
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              ) : chainVerified === false ? (
                <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
              ) : (
                <ShieldCheck className="h-3.5 w-3.5 text-zinc-400" />
              )
            }
            disabled={verifyingChain}
            onClick={() => void handleVerifyChain()}
          >
            {verifyingChain ? 'Verifying chain…' : 'Verify chain'}
          </SecondaryButton>
        </div>
      </div>
      {verificationError && (
        <p role="alert" className="investigation-error">
          {verificationError}
        </p>
      )}
      {exportError && (
        <p role="alert" className="investigation-error">
          {exportError}
        </p>
      )}
      {deleteError && (
        <p role="alert" className="investigation-error">
          {deleteError}
        </p>
      )}
      {deleteSuccess && (
        <p role="status" className="investigation-success">
          {deleteSuccess}
        </p>
      )}

      {/* Filter Bar */}
      <div className="ui-panel audit-filter-panel rounded-2xl border border-zinc-800/80 bg-zinc-900/50 p-4 shadow-sm transition-colors light:border-zinc-200 light:bg-white">
        <div className="mb-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
          <Filter className="h-3.5 w-3.5" />
          Filter administrative actions
        </div>
        <div className="audit-filter-grid grid gap-4 sm:grid-cols-2 xl:grid-cols-[minmax(280px,1fr)_220px_180px]">
          <div className="audit-query-field relative min-w-0">
            <label
              htmlFor="audit-query"
              className="mb-1.5 block text-xs font-medium text-zinc-400 light:text-zinc-600"
            >
              Search entries
            </label>
            <div className="audit-query-control">
              <Search className="h-4 w-4 text-zinc-500" aria-hidden="true" />
              <input
                ref={searchInputRef}
                autoComplete="off"
                type="search"
                id="audit-query"
                aria-label="Search audit trail"
                title="Search event, details, actor, IP, entry ID, action, resource, request ID or outcome"
                placeholder="Search event, actor, resource"
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full rounded-xl border border-zinc-800 bg-zinc-950 py-2.5 pl-9 pr-10 text-xs text-zinc-100 placeholder-zinc-500 transition focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-900"
              />
              {searchTerm && (
                <button
                  type="button"
                  className="audit-query-clear"
                  aria-label="Clear audit search"
                  title="Clear audit search"
                  onClick={() => {
                    setSearchTerm('');
                    setCurrentPage(1);
                    searchInputRef.current?.focus();
                  }}
                >
                  <X size={14} aria-hidden="true" />
                </button>
              )}
            </div>
          </div>

          <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
            Category
            <select
              id="audit-category"
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-200 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-800"
            >
              <option value="ALL">All categories</option>
              <option value="PIPELINE">Pipeline</option>
              <option value="SECURITY">Security</option>
              <option value="FEED">Feed ingestion</option>
              <option value="WATCHLIST">Monitored products</option>
              <option value="EMAIL">Email dispatch</option>
              <option value="WEBHOOK">Webhooks</option>
            </select>
          </label>

          <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
            Event level
            <select
              id="audit-level"
              value={levelFilter}
              onChange={(e) => {
                setLevelFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-200 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-800"
            >
              <option value="ALL">All levels</option>
              <option value="INFO">Info</option>
              <option value="WARNING">Warning</option>
              <option value="ERROR">Error</option>
            </select>
          </label>
        </div>
        <div className="audit-filter-summary">
          <p>
            <Filter size={13} aria-hidden="true" />{' '}
            {hasFilters
              ? 'Filters apply to all retained entries and exports.'
              : 'Search all retained entries. Exports include every matching record.'}
          </p>
          {hasFilters && (
            <button type="button" title="Reset all audit filters" className="audit-clear-filters" onClick={clearFilters}>
              <RotateCw size={13} aria-hidden="true" /> Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Logs Table */}
      <div className="ui-panel audit-entries-panel overflow-hidden rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white">
        <div className="audit-entries-heading flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800/70 px-4 py-3.5 light:border-zinc-200 sm:px-5">
          <div>
            <h2 className="text-sm font-semibold">Retained entries</h2>
            <p className="mt-0.5 text-[11px] text-zinc-500">Most recently retained first · Times in {displayTimezone}</p>
          </div>
          <span className="rounded-full border border-zinc-700/80 bg-zinc-950/60 px-2.5 py-1 text-[11px] tabular-nums text-zinc-400 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-600">
            {logsLoading ? 'Updating…' : `${total.toLocaleString()} ${total === 1 ? 'entry' : 'entries'}`}
          </span>
        </div>
        <div className="audit-desktop-table overflow-x-auto" aria-busy={logsLoading}>
          <table className="audit-actions-table w-full text-left text-xs">
            <caption className="sr-only">
              Administrative actions. Most recently retained first. All timestamps in {displayTimezone}.
            </caption>
            <thead>
              <tr>
                <th scope="col">Timestamp ({displayTimezone})</th>
                <th scope="col">Action &amp; resource details</th>
                <th scope="col">Actor &amp; source</th>
                <th scope="col">Outcome &amp; level</th>
              </tr>
            </thead>
                    <tbody>
                      {paginatedLogs.length === 0 ? (
                        <tr>
                          <td colSpan={4}>
                            <div className="audit-empty" role="status">
                              <Search size={24} strokeWidth={1.5} aria-hidden="true" />
                              <h3>
                                {logsLoading
                                  ? 'Loading audit entries…'
                                  : hasFilters
                                    ? 'No entries match these filters'
                                    : 'No administrative actions recorded'}
                              </h3>
                              <p>
                                {hasFilters
                                  ? 'Try a broader search or clear your filters.'
                                  : 'Administrative activity will appear here as your workspace changes.'}
                              </p>
                              {hasFilters && (
                                <button type="button" className="ui-secondary" onClick={clearFilters}>
                                  Clear filters
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ) : (
                        paginatedLogs.map((log) => (
                          <tr
                            key={log.id}
                            onClick={() => setSelectedLog(log)}
                            className="cursor-pointer transition hover:bg-zinc-800/25 light:hover:bg-zinc-50"
                          >
                    <td>
                      <time dateTime={log.timestamp} title={log.timestamp} className="audit-timestamp">
                        {formatAuditTimestamp(log.timestamp)}
                      </time>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="audit-event-link"
                        title={`View audit details: ${log.event}`}
                        onClick={() => setSelectedLog(log)}
                        aria-label={`View audit details: ${log.event}`}
                      >
                        <span>{log.event}</span>
                        <ChevronRight size={14} aria-hidden="true" />
                      </button>
                      {(compactDetails(log) || !resourceLabel(log)) && (
                        <p className="audit-event-description" title={log.details}>
                          {compactDetails(log) || 'No additional details recorded.'}
                        </p>
                      )}
                      {resourceLabel(log) && (
                        <p className="audit-resource" title={resourceLabel(log)}>
                          <span>Resource</span> <code>{resourceLabel(log)}</code>
                        </p>
                      )}
                    </td>
                    <td>
                      <div className="audit-actor">
                        <UserRound size={14} aria-hidden="true" />
                        <span title={log.actor}>{log.actor || 'System'}</span>
                      </div>
                      <p className="audit-source-ip" title={log.ipAddress}>
                        {log.ipAddress || 'Not recorded'}
                      </p>
                    </td>
                    <td>
                      <div className="audit-classification">
                        {renderOutcome(log)}
                        <span className="audit-category">{auditCategory(log.category)}</span>
                        {auditLevel(log.level)}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="audit-mobile-list" aria-busy={logsLoading}>
          {paginatedLogs.length ? (
            paginatedLogs.map((log) => (
              <article key={log.id} className="audit-mobile-entry">
                <div>
                  {auditLevel(log.level)}
                  <span className="audit-category">{auditCategory(log.category)}</span>
                  {renderOutcome(log)}
                </div>
                <button
                  type="button"
                  className="audit-event-link"
                  title={`View audit details: ${log.event}`}
                  onClick={() => setSelectedLog(log)}
                  aria-label={`View audit details: ${log.event}`}
                >
                  <span>{log.event}</span>
                  <ChevronRight size={14} aria-hidden="true" />
                </button>
                {(compactDetails(log) || !resourceLabel(log)) && (
                  <p className="audit-event-description" title={log.details}>
                    {compactDetails(log) || 'No additional details recorded.'}
                  </p>
                )}
                {resourceLabel(log) && (
                  <p className="audit-resource" title={resourceLabel(log)}>
                    <span>Resource</span> <code>{resourceLabel(log)}</code>
                  </p>
                )}
                <footer>
                  <span className="audit-actor">
                    <UserRound size={13} aria-hidden="true" />
                    {log.actor || 'System'}
                  </span>
                  <span className="audit-source-ip">Source: {log.ipAddress || 'Not recorded'}</span>
                  <time dateTime={log.timestamp} title={log.timestamp}>
                    <Clock3 size={13} aria-hidden="true" />
                    {formatAuditTimestamp(log.timestamp)}
                  </time>
                </footer>
              </article>
            ))
          ) : (
            <div className="audit-empty" role="status">
              <Search size={24} aria-hidden="true" />
              <h3>{logsLoading ? 'Loading audit entries…' : 'No entries found'}</h3>
              <p>
                {hasFilters
                  ? 'Try a broader search or clear your filters.'
                  : 'Administrative activity will appear here.'}
              </p>
              {hasFilters && (
                <button type="button" className="ui-secondary" onClick={clearFilters}>
                  Clear filters
                </button>
              )}
            </div>
          )}
        </div>

        {total > 0 && (
          <div className="border-t border-zinc-800/70 light:border-zinc-200">
          <Pagination
            currentPage={currentPage}
            totalItems={total}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setCurrentPage(1);
            }}
            pageSizeOptions={[10, 25, 50]}
          />
          </div>
        )}
      </div>

      {selectedLog && (
        <LogDetailModal
          icon={<FileCode2 className="h-4 w-4" />}
          eyebrow={auditCategory(selectedLog.category)}
          title={selectedLog.event}
          level={selectedLog.level}
          timestamp={selectedLog.timestamp}
          timestampDisplay={formatAuditTimestamp(selectedLog.timestamp)}
          timezone={settings.timezone}
          onClose={() => setSelectedLog(null)}
          fields={[
            { label: 'Category', value: auditCategory(selectedLog.category) },
            { label: `Timestamp (${displayTimezone})`, value: formatAuditTimestamp(selectedLog.timestamp) },
            { label: 'Outcome', value: renderOutcome(selectedLog) },
            { label: 'Action code', value: selectedLog.context?.action, mono: true, hidden: !selectedLog.context?.action },
            { label: 'Resource type', value: selectedLog.context?.resourceType, mono: true, hidden: !selectedLog.context?.resourceType },
            { label: 'Resource ID', value: selectedLog.context?.resourceId, mono: true, hidden: !selectedLog.context?.resourceId },
            { label: 'Request reference', value: selectedLog.context?.requestId, mono: true, hidden: !selectedLog.context?.requestId },
            {
              label: 'Fields supplied',
              value: selectedLog.context?.fields?.length ? selectedLog.context.fields.join('\n') : 'None supplied',
              mono: true,
              block: true,
              hidden: !selectedLog.context?.fields,
            },
            { label: 'Actor', value: selectedLog.actor || 'System', mono: true },
            { label: 'Source IP', value: selectedLog.ipAddress || 'Not recorded', mono: true },
            { label: 'Entry ID', value: selectedLog.id, mono: true },
            {
              label: 'Details',
              value: selectedLog.details || 'No additional details recorded.',
              block: true,
            },
            { label: 'Entry hash (not a verification result)', value: selectedLog.hash || 'Not recorded', mono: true, block: true },
            { label: 'Previous entry hash', value: selectedLog.prevHash || 'Not recorded', mono: true, block: true },
          ]}
        />
      )}
    </div>
  );
};

export const OperationalLogsView: React.FC = () => {
  const { fetchEvents, settings, csrfToken, session } = useApp();
  const canDeleteLogs = session?.role === 'ADMIN';
  const [tab, setTab] = useState<'events' | 'audit' | 'ml' | 'system'>('events');
  const [category, setCategory] = useState('');
  const [level, setLevel] = useState('');
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState('');
  const [runId, setRunId] = useState('');
  const [next, setNext] = useState<string | null>(null);
  const [events, setEvents] = useState<OperationalEvent[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [eventsDeleteDropdownOpen, setEventsDeleteDropdownOpen] = useState(false);
  const [eventsDeleteDays, setEventsDeleteDays] = useState<string>('30');
  const [eventsDeleting, setEventsDeleting] = useState(false);
  const [eventsDeleteError, setEventsDeleteError] = useState('');
  const [eventsDeleteSuccess, setEventsDeleteSuccess] = useState('');
  const validRunId = !runId || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(runId);
  const [selectedEvent, setSelectedEvent] = useState<OperationalEvent | null>(null);

  const handleEventsDeleteLogs = async () => {
    if (!canDeleteLogs || eventsDeleting || events.length === 0) return;
    const days = parseInt(eventsDeleteDays, 10);
    if (!Number.isFinite(days) || days <= 0) {
      setEventsDeleteError('Please select a valid number of days');
      return;
    }
    setEventsDeleting(true);
    setEventsDeleteError('');
    setEventsDeleteSuccess('');
    try {
      const response = await fetch('/api/events/cleanup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify({ days, scope: 'OPERATIONS' }),
      });
      if (!response.ok) {
        const error = await response.json().catch(() => ({ message: 'Failed to delete logs' }));
        throw new Error(error.message || 'Failed to delete logs');
      }
      const result = await response.json();
      setEventsDeleteSuccess(`Deleted ${result.deleted} operational event entries older than ${days} days`);
      setRefresh((value) => value + 1);
    } catch (error) {
      setEventsDeleteError(error instanceof Error ? error.message : 'Failed to delete logs. Please retry.');
    } finally {
      setEventsDeleting(false);
      setEventsDeleteDropdownOpen(false);
    }
  };
  useEffect(() => {
    if (tab !== 'events' || !validRunId) {
      setLoading(false);
      return;
    }
    let disposed = false;
    const timer = setTimeout(() => {
      setLoading(true);
      setError('');
      fetchEvents(
        new URLSearchParams({
          scope: 'OPERATIONS',
          ...(category && { category }),
          ...(level && { level }),
          ...(query && { q: query }),
          ...(runId && { runId }),
          ...(cursor && { before: cursor }),
        }).toString(),
      )
        .then((result) => {
          if (!disposed) {
            setEvents(result.events);
            setNext(result.nextCursor);
          }
        })
        .catch((error) => {
          if (!disposed) setError(error.message);
        })
        .finally(() => {
          if (!disposed) setLoading(false);
        });
    }, 250);
    const interval = setInterval(() => {
      if (document.visibilityState !== 'hidden' && !cursor) setRefresh((value) => value + 1);
    }, 10_000);
    const onVisibility = () => {
      if (document.visibilityState === 'visible' && !cursor) setRefresh((value) => value + 1);
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      disposed = true;
      clearTimeout(timer);
      clearInterval(interval);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [tab, category, level, query, runId, cursor, refresh]);
  return (
    <div className="logs-workspace space-y-6">
      <PageHeading page="logs">
        Investigate operational activity, inspect ML and system diagnostics, and verify retained audit records.
      </PageHeading>
      <div
        onKeyDown={(event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const tabs = ['events', 'audit', 'ml', 'system'] as const;
    const nextTab =
      event.key === 'Home'
        ? tabs[0]
        : event.key === 'End'
          ? tabs[3]
          : tabs[(tabs.indexOf(tab) + (event.key === 'ArrowLeft' ? 3 : 1)) % tabs.length];
    setTab(nextTab);
    document.getElementById(`logs-${nextTab}-tab`)?.focus();
        }}
        className="investigation-tabs inline-flex rounded-xl border border-zinc-800 bg-zinc-950/70 p-1 light:border-zinc-200 light:bg-white"
        role="tablist"
        aria-label="Log views"
      >
        <button
          role="tab"
          id="logs-events-tab"
          aria-controls="logs-events-panel"
          tabIndex={tab === 'events' ? 0 : -1}
          aria-selected={tab === 'events'}
          onClick={() => setTab('events')}
          className={`rounded-lg px-3.5 py-2 text-xs font-medium transition ${tab === 'events' ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-blue-50 light:text-blue-800' : 'text-zinc-400 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'}`}
        >
          <Cpu size={16} aria-hidden="true" /> Operational events
        </button>
        <button
          role="tab"
          id="logs-audit-tab"
          aria-controls="logs-audit-panel"
          tabIndex={tab === 'audit' ? 0 : -1}
          aria-selected={tab === 'audit'}
          onClick={() => setTab('audit')}
          className={`rounded-lg px-3.5 py-2 text-xs font-medium transition ${tab === 'audit' ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-blue-50 light:text-blue-800' : 'text-zinc-400 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'}`}
        >
          <ShieldCheck size={16} aria-hidden="true" /> Audit logs
        </button>
        <button
          role="tab"
          id="logs-ml-tab"
          aria-controls="logs-ml-panel"
          tabIndex={tab === 'ml' ? 0 : -1}
          aria-selected={tab === 'ml'}
          onClick={() => setTab('ml')}
          className={`rounded-lg px-3.5 py-2 text-xs font-medium transition ${tab === 'ml' ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-blue-50 light:text-blue-800' : 'text-zinc-400 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'}`}
        >
          <Brain size={16} aria-hidden="true" /> ML logs
        </button>
        <button
          role="tab"
          id="logs-system-tab"
          aria-controls="logs-system-panel"
          tabIndex={tab === 'system' ? 0 : -1}
          aria-selected={tab === 'system'}
          onClick={() => setTab('system')}
          className={`rounded-lg px-3.5 py-2 text-xs font-medium transition ${tab === 'system' ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-blue-50 light:text-blue-800' : 'text-zinc-400 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'}`}
        >
          <Server size={16} aria-hidden="true" /> System logs
        </button>
      </div>
      {tab === 'audit' ? (
        <AuditTrailView />
      ) : tab === 'ml' ? (
        <MlLogsView />
      ) : tab === 'system' ? (
        <SystemLogsView />
      ) : (
        <div id="logs-events-panel" role="tabpanel" aria-labelledby="logs-events-tab" className="audit-trail-panel space-y-6">
          <div className="ui-page-header audit-page-header">
            <div className="audit-page-heading">
              <span className="audit-page-icon" aria-hidden="true"><Cpu size={20} /></span>
              <div>
                <h2 className="investigation-section-title">Operational events</h2>
                <p className="investigation-section-description">
                  Inspect pipeline, feed, matching, and delivery activity. Latest events refresh every 10
                  seconds.
                </p>
              </div>
            </div>
            <div className="operational-events-status" aria-live="polite">
              {loading && <RotateCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
              {events.length > 0 && !loading && error === '' && (
                <>
                  <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/20 bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-medium text-rose-300 light:text-rose-700">
                    {events.filter((e) => e.level === 'ERROR').length} errors
                  </span>
                  <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-400 light:text-amber-700">
                    {events.filter((e) => e.level === 'WARNING').length} warnings
                  </span>
                </>
              )}
              <span>{loading ? 'Loading events…' : `${events.length} events in this view`}</span>
            </div>
            <div className="relative" role="group" aria-label="Delete operational events" hidden={!canDeleteLogs}>
              <SecondaryButton
                title="Delete operational events older than selected days"
                disabled={events.length === 0 || loading || eventsDeleting}
                icon={<Trash2 className="h-3.5 w-3.5" />}
                onClick={() => setEventsDeleteDropdownOpen(!eventsDeleteDropdownOpen)}
                className="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 light:hover:bg-rose-500/10"
              >
                Delete logs
              </SecondaryButton>
              {eventsDeleteDropdownOpen && (
                <div className="absolute right-0 top-full mt-1 z-20 rounded-xl border border-zinc-700 bg-zinc-900 py-1.5 shadow-lg min-w-[180px] light:border-zinc-200 light:bg-white">
                  <div className="px-3 py-2 border-b border-zinc-700 light:border-zinc-200">
                    <p className="text-xs font-medium text-zinc-400 light:text-zinc-600">Delete logs older than</p>
                  </div>
                  <select
                    value={eventsDeleteDays}
                    onChange={(e) => setEventsDeleteDays(e.target.value)}
                    onBlur={() => setTimeout(() => setEventsDeleteDropdownOpen(false), 100)}
                    className="w-full px-3 py-2 text-xs text-zinc-100 bg-zinc-900 border-none focus:outline-none light:text-zinc-900 light:bg-white"
                  >
                    <option value="7">7 days</option>
                    <option value="30">30 days</option>
                    <option value="90">90 days</option>
                    <option value="365">1 year</option>
                  </select>
                  <div className="px-3 py-2 border-t border-zinc-700 light:border-zinc-200 flex gap-1.5">
                    <SecondaryButton
                      disabled={eventsDeleting}
                      loading={eventsDeleting}
                      onClick={handleEventsDeleteLogs}
                      className="flex-1 text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 light:hover:bg-rose-500/10"
                    >
                      {eventsDeleting ? 'Deleting…' : 'Confirm delete'}
                    </SecondaryButton>
                    <SecondaryButton
                      disabled={eventsDeleting}
                      onClick={() => setEventsDeleteDropdownOpen(false)}
                      className="flex-1"
                    >
                      Cancel
                    </SecondaryButton>
                  </div>
                </div>
              )}
            </div>
          </div>
          <div className="ui-panel operational-events-filter">
            <div className="audit-filter-title">
              <Filter className="h-3.5 w-3.5" />
              Filter operational activity
            </div>
            <div className="operational-events-filter-grid">
              <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
                Search events
                <input
                  aria-label="Search operational events"
                  maxLength={200}
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    setCursor('');
                  }}
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-900"
                  placeholder="Code, message or context"
                />
              </label>
              <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
                Category
                <select
                  value={category}
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-200 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-800"
                  onChange={(e) => {
                    setCategory(e.target.value);
                    setCursor('');
                  }}
                >
                  <option value="">All categories</option>
                  {EVENT_CATEGORIES.filter((item) => item !== 'ML' && item !== 'SYSTEM').map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
                Level
                <select
                  value={level}
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-800"
                  onChange={(e) => {
                    setLevel(e.target.value);
                    setCursor('');
                  }}
                >
                  <option value="">All levels</option>
                  {['INFO', 'WARNING', 'ERROR'].map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
                Execution ID
                <input
                  aria-label="Filter by execution ID"
                  aria-invalid={!validRunId}
                  aria-describedby={!validRunId ? 'execution-id-help' : undefined}
                  value={runId}
                  placeholder="Execution UUID"
                  maxLength={36}
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-900"
                  onChange={(e) => {
                    setRunId(e.target.value);
                    setCursor('');
                  }}
                />
              </label>
              <button
                className="inline-flex h-[38px] items-center justify-center gap-2 rounded-xl border border-zinc-700 bg-zinc-800 px-3.5 text-xs font-medium text-zinc-100 transition hover:bg-zinc-700 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-800 light:hover:bg-zinc-200"
                disabled={loading}
                onClick={() => {
                  setCursor('');
                  setRefresh((value) => value + 1);
                }}
              >
                <RotateCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>
          {!validRunId && (
            <p id="execution-id-help" role="status" className="text-xs text-amber-400">
              Enter a complete execution UUID to apply this filter.
            </p>
          )}
          {(query || category || level || runId) && (
            <button
              className="ui-secondary"
              onClick={() => {
                setQuery('');
                setCategory('');
                setLevel('');
                setRunId('');
                setCursor('');
              }}
            >
              Clear filters
            </button>
          )}
          {error && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-xl border border-rose-500/20 bg-rose-500/[0.06] px-4 py-3 text-xs text-rose-300 light:text-rose-800"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                <p className="font-semibold">Could not load operational events</p>
                <p className="mt-0.5 opacity-80">{error}</p>
              </div>
            </div>
          )}
          {eventsDeleteError && (
            <p role="alert" className="investigation-error">
              {eventsDeleteError}
            </p>
          )}
          {eventsDeleteSuccess && (
            <p role="status" className="investigation-success">
              {eventsDeleteSuccess}
            </p>
          )}
          <div aria-busy={loading} className="space-y-3">
            {loading && events.length === 0 && (
              <div className="ui-panel investigation-empty" role="status">
                <RotateCw className="animate-spin" size={22} />
                <p>Loading operational events…</p>
              </div>
            )}
            {events.length === 0 && !loading && !error && (
              <div className="p-8 text-center text-zinc-500">
                <LogOut className="mx-auto h-6 w-6" />
                <p className="mt-3 text-sm font-medium text-zinc-300 light:text-zinc-700">
                  No matching events.
                </p>
                <p className="mt-1 text-xs text-zinc-600">Adjust your search or filters to see results.</p>
              </div>
            )}
            {events.length > 0 && (
              <div className="ui-panel audit-entries-panel overflow-hidden rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white">
                <div className="audit-desktop-table overflow-x-auto">
                  <table className="audit-actions-table operational-events-table w-full text-left text-xs">
                    <caption className="sr-only">
                      Operational events, newest first. All timestamps are in {timezoneLabel(settings.timezone)}.
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">Timestamp ({timezoneLabel(settings.timezone)})</th>
                        <th scope="col">Level</th>
                        <th scope="col">Message &amp; error details</th>
                        <th scope="col">Category</th>
                        <th scope="col">Event code</th>
                        <th scope="col">Execution ID</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono">
                      {events.map((event) => (
                        <tr
                          key={event.id}
                          onClick={() => setSelectedEvent(event)}
                          className="cursor-pointer transition hover:bg-zinc-800/25 light:hover:bg-zinc-50"
                        >
                          <td data-label={`Timestamp · ${timezoneLabel(settings.timezone)}`} className="operational-event-timestamp px-4 py-3.5 align-top text-[11px] leading-tight text-zinc-400 light:text-zinc-600">
                            {/* Two lines, not one nowrap line: at the narrow
                                column width the single-line form clipped the
                                value ("Oct 25, 2026, 9:"). */}
                            <div className="whitespace-nowrap tabular-nums">
                              {formatDate(event.timestamp, settings.timezone)}
                            </div>
                            <div className="mt-0.5 whitespace-nowrap font-mono text-[10px] tabular-nums text-zinc-500">
                              {fmtDateTime(event.timestamp, settings.timezone)}{' '}
                              {timezoneLabel(settings.timezone)}
                            </div>
                          </td>
                          <td data-label="Level" className="operational-event-level px-4 py-3.5">
                            <span
                              className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold ${
                                event.level === 'ERROR'
                                  ? 'border-rose-500/20 bg-rose-500/10 text-rose-400 light:text-rose-700'
                                  : event.level === 'WARNING'
                                    ? 'border-amber-500/20 bg-amber-500/10 text-amber-400 light:text-amber-700'
                                    : 'border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700'
                              }`}
                            >
                              {event.level}
                            </span>
                          </td>
                          <td data-label="Message & error details" className="operational-event-message-cell px-4 py-3.5 font-sans">
                            <div className="text-xs font-semibold text-zinc-200 light:text-zinc-900">
                              {event.message}
                            </div>
                            {event.level === 'ERROR' && event.context?.error !== undefined && (
                              <div className="operational-event-error mt-1 font-mono text-[10px] text-rose-300 light:text-rose-700">
                                {
                                  (typeof event.context.error === 'object'
                                    ? formatEventContext(event.context.error as Record<string, unknown>)
                                    : String(event.context.error)
                                  ).split('\n').slice(0, 2).join(' · ')
                                }
                              </div>
                            )}
                            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                              {event.context?.errorCode !== undefined && (
                                <span className="operational-event-reference">Error {String(event.context.errorCode)}</span>
                              )}
                              {event.context?.reference !== undefined && (
                                <span className="operational-event-reference">Ref {String(event.context.reference)}</span>
                              )}
                              {event.totalDatabaseTimeMs !== undefined && (
                                <span className="rounded border-zinc-700/60 bg-zinc-800/50 px-1.5 py-0.5 font-mono text-[9px] text-zinc-400 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-600">
                                  DB {event.totalDatabaseTimeMs.toFixed(0)} ms
                                </span>
                              )}
                              {event.extractionLatencyMs !== undefined && (
                                <span className="rounded border-zinc-700/60 bg-zinc-800/50 px-1.5 py-0.5 font-mono text-[9px] text-zinc-400 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-600">
                                  extract {event.extractionLatencyMs.toFixed(0)} ms
                                </span>
                              )}
                              {event.trackingId && (
                                <span className="rounded border-teal-500/20 bg-teal-500/10 px-1.5 py-0.5 font-mono text-[9px] text-teal-300 light:text-teal-700" title={event.trackingId}>
                                  Trace {event.trackingId.slice(0, 8)}
                                </span>
                              )}
                              {Object.keys(event.context ?? {}).length > 0 && (
                                <span className="font-mono text-[9px] text-zinc-500">
                                  {Object.keys(event.context).length} field
                                  {Object.keys(event.context).length === 1 ? '' : 's'}
                                </span>
                              )}
                            </div>
                          </td>
                          <td data-label="Category" className="operational-event-category px-4 py-3.5 align-top text-[11px] text-zinc-300 light:text-zinc-700">
                            <span className="inline-block max-w-full rounded-md border-zinc-700/70 bg-zinc-800/60 px-2 py-1 light:border-zinc-200 light:bg-zinc-100">
                              {event.category}
                            </span>
                          </td>
                          <td data-label="Event code" className="operational-event-code px-4 py-3.5 font-mono text-[11px] text-zinc-300 light:text-zinc-700">
                            <button
                              type="button"
                              className="text-left underline decoration-dotted underline-offset-4 break-all"
                              aria-label={`View event details: ${event.code}`}
                              onClick={() => setSelectedEvent(event)}
                            >
                              {event.code}
                            </button>
                          </td>
                          <td data-label="Execution ID" className="operational-event-execution px-4 py-3.5 align-top font-mono text-[11px] text-zinc-400 light:text-zinc-600">
                            {event.runId ? (
                              /* min-w-0 + truncate keeps a UUID inside its cell;
                                 a bare inline-flex row previously overran the
                                 table's right edge. */
                              <span className="flex min-w-0 items-center gap-1" title={event.runId}>
                                <Cpu className="h-3 w-3 shrink-0 text-indigo-400 light:text-indigo-600" />
                                <span className="truncate">{event.runId.slice(0, 8)}</span>
                              </span>
                            ) : (
                              '—'
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-800/70 bg-zinc-900/30 px-4 py-3 light:border-zinc-200 light:bg-white/70">
            <p className="text-[11px] text-zinc-500">
              {cursor ? 'Viewing an older page' : 'Showing the latest events'}
            </p>
            <div className="flex gap-2">
              <button
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40 light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100"
                disabled={!cursor || loading}
                onClick={() => setCursor('')}
              >
                <RotateCw className="h-3.5 w-3.5" />
                Latest
              </button>
              <button
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40 light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100"
                disabled={!next || loading}
                onClick={() => setCursor(next!)}
              >
                Older events <span aria-hidden="true">→</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          timezone={settings.timezone}
          onClose={() => setSelectedEvent(null)}
          onFilterByTrackingId={(trackingId) => {
            setSelectedEvent(null);
            setRunId('');
            setQuery(trackingId);
            setCursor('');
          }}
        />
      )}
    </div>
  );
};
