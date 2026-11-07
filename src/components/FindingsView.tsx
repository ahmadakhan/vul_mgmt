import { PageHeading } from './PageHeading';
import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { Finding, FindingStatus } from '../types';
import {
  Flame,
  ExternalLink,
  ChevronRight,
  Filter,
  Search,
  Terminal,
  FileCheck,
  Copy,
  Check,
  X,
  Send,
  Trash2,
  Mail,
} from 'lucide-react';
import { Pagination } from './Pagination';
import { useCollection } from '../hooks/useCollection';
import { copyText } from '../utils/clipboard';
import { CveLink } from './CveLink';
import { formatDateTime as fmtDateTime, formatTime as fmtTime } from '../utils/dateTime';

export const FindingsView: React.FC = () => {
  const {
    selectedFinding,
    setSelectedFinding,
    updateFindingStatus,
    resendNotification,
    deleteFinding,
    sendBulkNotification,
    settings,
    latestExecution,
  } = useApp();
  const [removeFeedback, setRemoveFeedback] = useState<{ type: 'error' | 'success'; message: string } | null>(
    null,
  );

  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sortFilter, setSortFilter] = useState('modified');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const [statusModalOpen, setStatusModalOpen] = useState(false);
  const [targetStatus, setTargetStatus] = useState<FindingStatus>('REMEDIATION_AVAILABLE');
  const [statusNote, setStatusNote] = useState('');

  const [resendModalOpen, setResendModalOpen] = useState(false);
  const [resendReason, setResendReason] = useState('');

  const [removeConfirm, setRemoveConfirm] = useState<Finding | null>(null);
  const [selectedFindings, setSelectedFindings] = useState<Set<string>>(new Set());
  const [bulkNotifyModalOpen, setBulkNotifyModalOpen] = useState(false);
  const [bulkNotifyReason, setBulkNotifyReason] = useState('');
  const [bulkRecipientMode, setBulkRecipientMode] = useState<'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE'>(
    'SECURITY_TEAM',
  );
  const [bulkCustomEmail, setBulkCustomEmail] = useState('');

  const { items: findings, total, reload } = useCollection<Finding>('findings', {
    page: currentPage,
    pageSize,
    search: searchTerm,
    sort: sortFilter,
    order: 'desc',
    filters: { severity: severityFilter, status: statusFilter },
  });

  // Reload findings whenever the latest execution changes.
  useEffect(() => {
    reload();
  }, [reload]);

  const handleCopy = async (text: string) => {
    if (await copyText(text)) {
      setCopiedCmd(text);
      setTimeout(() => setCopiedCmd(null), 2000);
    }
  };

  const handleOpenStatusChange = (status: FindingStatus) => {
    setTargetStatus(status);
    setStatusNote('');
    setStatusModalOpen(true);
  };

  const handleConfirmStatusChange = async () => {
    if (selectedFinding) {
      if (!(await updateFindingStatus(selectedFinding.id, targetStatus, statusNote))) return;
      setSelectedFinding({
        ...selectedFinding,
        status: targetStatus,
      });
      await reload();
    }
    setStatusModalOpen(false);
  };

  const handleConfirmResend = async () => {
    if (selectedFinding && resendReason.trim()) {
      if (!(await resendNotification(selectedFinding.cveId, resendReason))) return;
      setResendModalOpen(false);
      setResendReason('');
      await reload();
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="ui-page-header">
        <PageHeading page="findings">
          Correlated vulnerabilities matching monitored products with uniform enterprise protection. Confirmed
          matches can enter configured delivery channels; uncertain applicability requires review.
        </PageHeading>
      </div>

      {/* Filter and Search Bar */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm transition-colors">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by CVE, product, or title..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Status Filter */}
          <div className="flex items-center space-x-1.5 text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            <span>Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-2.5 py-1.5 text-xs text-zinc-200 dark:text-zinc-200 light:text-zinc-800 focus:outline-none focus:border-zinc-600"
            >
              <option value="ALL">All Statuses</option>
              <option value="MONITORED">Monitored</option>
              <option value="REMEDIATION_AVAILABLE">Remediation Available</option>
              <option value="PATCH_APPLIED">Patch Applied</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center space-x-1.5 text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-2.5 py-1.5 text-xs text-zinc-200 dark:text-zinc-200 light:text-zinc-800 focus:outline-none focus:border-zinc-600"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical (9.0 - 10.0)</option>
              <option value="HIGH">High (7.0 - 8.9)</option>
              <option value="MEDIUM">Medium (4.0 - 6.9)</option>
              <option value="LOW">Low</option>
              <option value="UNKNOWN">Unscored</option>
            </select>
          </div>

          {/* Sort Filter */}
          <div className="flex items-center space-x-1.5 text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            <span>Sort by:</span>
            <select
              value={sortFilter}
              onChange={(e) => {
                setSortFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-2.5 py-1.5 text-xs text-zinc-200 dark:text-zinc-200 light:text-zinc-800 focus:outline-none focus:border-zinc-600"
            >
              <option value="latest">Latest</option>
              <option value="published">Published</option>
              <option value="modified">Last Modified</option>
            </select>
          </div>

          {/* Clear Filters */}
          {(severityFilter !== 'ALL' || statusFilter !== 'ALL' || sortFilter !== 'modified' || searchTerm) && (
            <button
              onClick={() => {
                setSeverityFilter('ALL');
                setStatusFilter('ALL');
                setSortFilter('modified');
                setSearchTerm('');
                setCurrentPage(1);
              }}
              className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 transition flex items-center space-x-1.5"
              title="Clear all filters and search"
            >
              <X className="w-3 h-3" />
              <span>Clear</span>
            </button>
          )}

          {/* Bulk Actions */}
          {selectedFindings.size > 0 && (
            <div className="flex items-center space-x-3 text-xs">
              <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                {selectedFindings.size} finding{selectedFindings.size !== 1 ? 's' : ''} selected
              </span>
              <button
                onClick={() => {
                  setBulkNotifyReason('');
                  setBulkRecipientMode('SECURITY_TEAM');
                  setBulkCustomEmail('');
                  setBulkNotifyModalOpen(true);
                }}
                className="px-2.5 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-200 dark:text-zinc-200 light:text-zinc-900 font-medium border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 transition flex items-center space-x-1"
                title="Send notification for selected findings"
              >
                <Mail className="w-3.5 h-3.5" />
                <span>Send Notification</span>
              </button>
              <button
                onClick={() => setSelectedFindings(new Set())}
                className="px-2.5 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 transition"
                title="Clear selection"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Main Layout: Findings Table + Details Drawer */}
      <div className="grid grid-cols-1 gap-6 items-start">
        {/* Table column */}
        <div className="w-full min-w-0">
          <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1320px] text-left text-xs">
                <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-3.5 w-[40px]">
                      <input
                        type="checkbox"
                        checked={findings.length > 0 && findings.every((f) => selectedFindings.has(f.id))}
                        onChange={(e) => {
                          if (e.target.checked)
                            setSelectedFindings(new Set(findings.map((f) => f.id)));
                          else setSelectedFindings(new Set());
                        }}
                        className="w-4 h-4 rounded border-zinc-600 text-zinc-800 focus:ring-zinc-500"
                      />
                    </th>
                    <th className="py-3 px-3.5 whitespace-nowrap">CVE Identifier</th>
                    <th className="py-3 px-3.5 whitespace-nowrap">Published</th>
                    <th className="py-3 px-3.5 whitespace-nowrap">Modified</th>
                    <th className="py-3 px-3.5 whitespace-nowrap">Monitored Product</th>
                    <th className="py-3 px-3.5 whitespace-nowrap">CVSS / EPSS</th>
                    <th className="py-3 px-3.5 whitespace-nowrap">Exploit Risk</th>
                    <th className="py-3 px-3.5 whitespace-nowrap">Auto-Notification</th>
                    <th className="py-3 px-3.5 text-right whitespace-nowrap">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="py-8 text-center text-zinc-500 text-xs">
                        No product vulnerabilities match the current filter.
                      </td>
                    </tr>
                  ) : (
                    findings.map((finding) => {
                      const isSelected = selectedFinding?.id === finding.id;
                      const isBulkSelected = selectedFindings.has(finding.id);
                      const isKev = finding.cve.cisaKev?.isKev ?? false;

                      return (
                        <tr
                          key={finding.id}
                          onClick={() => setSelectedFinding(finding)}
                          className={`cursor-pointer transition ${
                            isSelected
                              ? 'bg-zinc-800/70 dark:bg-zinc-800/70 light:bg-zinc-200/80 border-l-2 border-zinc-400'
                              : 'hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50'
                          }`}
                        >
                          {/* Bulk select checkbox */}
                          <td className="py-3 px-3.5" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={isBulkSelected}
                              onChange={(e) => {
                                const next = new Set(selectedFindings);
                                if (e.target.checked) next.add(finding.id);
                                else next.delete(finding.id);
                                setSelectedFindings(next);
                              }}
                              className="w-4 h-4 rounded border-zinc-600 text-zinc-800 focus:ring-zinc-500"
                            />
                          </td>

                          {/* CVE ID */}
                          <td className="py-3 px-3.5 align-top whitespace-nowrap">
                            <div className="font-mono font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 flex items-center gap-1.5 whitespace-nowrap">
                              <CveLink cveId={finding.cveId} />
                              {isKev && (
                                <span title="CISA KEV Catalog">
                                  <Flame className="w-3.5 h-3.5 text-amber-500/80" />
                                </span>
                              )}
                            </div>
                            <div className="text-[10px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 line-clamp-1 max-w-[160px]">
                              {finding.cve.title}
                            </div>
                          </td>

                          {/* CVE dates */}
                          <td className="py-3 px-3.5 whitespace-nowrap text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-mono text-[11px]">
                            {fmtDateTime(finding.cve.publishedDate, settings.timezone)}
                          </td>
                          <td className="py-3 px-3.5 whitespace-nowrap text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-mono text-[11px]">
                            {fmtDateTime(finding.cve.modifiedDate, settings.timezone)}
                          </td>

                          {/* Matched Product */}
                          <td className="py-3 px-3.5 align-top">
                            <div className="font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800 line-clamp-1 max-w-[240px]" title={finding.matchedAssetName}>
                              {finding.matchedAssetName}
                            </div>
                            <div className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono truncate max-w-[240px]" title={finding.matchedCpe}>
                              {finding.matchedCpe}
                            </div>
                          </td>

                          {/* CVSS / EPSS */}
                          <td className="py-3 px-3.5 font-mono">
                            <div className="flex items-center gap-1.5 whitespace-nowrap">
                              <span
                                className={`font-bold ${
                                  finding.cve.cvss.score >= 9.0
                                    ? 'text-rose-400'
                                    : finding.cve.cvss.score >= 7.0
                                      ? 'text-amber-400'
                                      : 'text-zinc-300 dark:text-zinc-300 light:text-zinc-800'
                                }`}
                              >
                                {finding.cve.cvss.version === 'UNKNOWN'
                                  ? '—'
                                  : finding.cve.cvss.score.toFixed(1)}
                              </span>
                              <span className="text-[10px] text-zinc-500">{finding.cve.cvss.severity}</span>
                            </div>
                            <div className="text-[10px] text-zinc-400 dark:text-zinc-400 light:text-zinc-500">
                              EPSS:{' '}
                              {finding.cve.epss?.score != null
                                ? `${(finding.cve.epss.score * 100).toFixed(1)}%`
                                : '—'}
                            </div>
                          </td>

                          {/* Exploit Risk */}
                          <td className="py-3 px-3.5">
                            <span
                              className={`inline-block text-[10px] font-mono px-2 py-0.5 rounded-full border whitespace-nowrap ${
                                finding.exploitRisk === 'CISA_KEV_EXPLOITED'
                                  ? 'bg-amber-950/40 text-amber-300 border-amber-800/80 font-semibold'
                                  : finding.exploitRisk === 'REPORTED_IN_WILD_EXPLOIT'
                                    ? 'bg-orange-950/40 text-orange-300 border-orange-800/80 font-semibold'
                                    : finding.exploitRisk === 'WEAPONIZED_EXPLOIT'
                                      ? 'bg-rose-950/40 text-rose-300 border-rose-800/80 font-semibold'
                                      : 'bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border-zinc-700 dark:border-zinc-700 light:border-zinc-300'
                              }`}
                            >
                              {finding.exploitRisk.replace(/_/g, ' ')}
                            </span>
                          </td>

                          {/* Auto-Notification */}
                          <td className="py-3 px-3.5 font-mono text-[11px]">
                            <div className="flex items-center gap-1 text-emerald-400 dark:text-emerald-400 light:text-emerald-600 font-medium">
                              <Send className="w-3 h-3 shrink-0" />
                              <span className="truncate max-w-[130px]" title={finding.notificationStatus.replace(/_/g, ' ')}>
                                {finding.notificationStatus.replace(/_/g, ' ')}
                              </span>
                            </div>
                            {finding.autoDispatchedAt && (
                              <div className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600">
                                {fmtTime(finding.autoDispatchedAt, settings.timezone)}
                              </div>
                            )}
                          </td>

                          {/* Details */}
                          <td className="py-3 px-3.5 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedFinding(finding);
                              }}
                              className="text-xs text-zinc-400 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 inline-flex items-center space-x-1"
                            >
                              <ChevronRight className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <Pagination
              currentPage={currentPage}
              totalItems={total}
              pageSize={pageSize}
              onPageChange={setCurrentPage}
              onPageSizeChange={setPageSize}
              pageSizeOptions={[10, 25, 50]}
            />
          </div>
        </div>

        {/* Detailed Drawer Column */}
        {selectedFinding && (
          <div className="ui-panel w-full bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm space-y-4 transition-colors">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 pb-3">
              <div>
                <div className="flex items-center space-x-2">
                  <CveLink cveId={selectedFinding.cveId} className="text-base" />
                  {selectedFinding.cve.cisaKev?.isKev && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-950/40 text-amber-300 border border-amber-800/80 flex items-center gap-1 font-semibold">
                      <Flame className="w-3 h-3 text-amber-500" />
                      CISA KEV
                    </span>
                  )}
                </div>
                <div className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1 line-clamp-2">
                  {selectedFinding.cve.title}
                </div>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-zinc-500 hover:text-zinc-300 dark:hover:text-zinc-300 light:hover:text-zinc-900"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Status & Resend Actions */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <select
                value={selectedFinding.status}
                onChange={(e) => handleOpenStatusChange(e.target.value as FindingStatus)}
                className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-700/80 dark:border-zinc-700/80 light:border-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 text-xs rounded-xl px-2.5 py-1.5 font-medium focus:outline-none"
              >
                <option value="MONITORED">Status: Monitored</option>
                <option value="REMEDIATION_AVAILABLE">Status: Remediation Available</option>
                <option value="PATCH_APPLIED">Status: Patch Applied</option>
                <option value="RESOLVED">Status: Resolved</option>
                <option value="FALSE_POSITIVE">Status: False Positive</option>
              </select>

              <button
                onClick={() => setResendModalOpen(true)}
                className="text-xs bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 px-2.5 py-1.5 rounded-xl flex items-center space-x-1.5 transition"
                title="Resend notification to distribution list"
              >
                <Send className="w-3 h-3 text-zinc-400" />
                <span>Resend Notification</span>
              </button>
              <button
                onClick={() => setRemoveConfirm(selectedFinding)}
                className="text-xs bg-rose-600/10 hover:bg-rose-600/20 border border-rose-800/50 text-rose-300 hover:text-rose-200 px-2.5 py-1.5 rounded-xl flex items-center space-x-1.5 transition"
                title="Remove this vulnerability entry from findings"
              >
                <Trash2 className="w-3 h-3" />
                <span>Remove</span>
              </button>
            </div>

            {/* Matched Product Details & Matching Evidence */}
            <div className="bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-xl p-3 text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[10px] uppercase">
                  Monitored Product Asset
                </span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-800">
                  {selectedFinding.matchingMethod || 'STRICT_CPE'}
                </span>
              </div>
              <div className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900 font-semibold">
                {selectedFinding.matchedAssetName}
              </div>
              <div className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[10px] break-all">
                CPE: {selectedFinding.matchedCpe}
              </div>
              {selectedFinding.matchingEvidence && (
                <div className="pt-2 border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono flex items-start gap-1.5">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-semibold shrink-0">
                    Evidence:
                  </span>
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                    {selectedFinding.matchingEvidence}
                  </span>
                </div>
              )}
              {selectedFinding.cve.vex && (
                <div className="text-[10px] font-mono bg-zinc-900/90 dark:bg-zinc-900/90 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-2 rounded text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                  <span className="text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-semibold">
                    CSAF 2.0 VEX Status:{' '}
                  </span>
                  <span className="uppercase text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                    {selectedFinding.cve.vex.status}
                  </span>
                  {selectedFinding.cve.vex.justification && (
                    <div className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-0.5">
                      • {selectedFinding.cve.vex.justification}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Vendor Advisory link */}
            <div className="flex items-center justify-between text-xs bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-3 rounded-xl">
              <div>
                <div className="font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-900">
                  Vendor Advisory Reference
                </div>
                <div className="text-[11px] text-zinc-500 font-mono">
                  Ref: {selectedFinding.cve.remediation.vendorAdvisoryRef}
                </div>
              </div>
              {/^https:\/\//i.test(selectedFinding.cve.remediation.patchUrl) ? (
                <a
                  href={selectedFinding.cve.remediation.patchUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1 bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 rounded-xl font-medium flex items-center space-x-1 transition border border-zinc-700 dark:border-zinc-700 light:border-zinc-300"
                >
                  <span>Vendor Advisory</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              ) : (
                <span className="text-zinc-500">No vendor link supplied</span>
              )}
            </div>

            {/* Immediate Mitigation Commands */}
            <div className="space-y-2">
              <div className="flex items-center space-x-1.5 text-xs font-semibold text-zinc-300 dark:text-zinc-300 light:text-zinc-800 uppercase tracking-wider">
                <Terminal className="w-3.5 h-3.5 text-zinc-400" />
                <span>Immediate Mitigation Actions</span>
              </div>
              <div className="space-y-1.5">
                {selectedFinding.cve.remediation.immediateActions.map((action, i) => (
                  <div
                    key={i}
                    className="group bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-xl p-2.5 font-mono text-[11px] text-zinc-300 dark:text-zinc-300 light:text-zinc-800 flex items-center justify-between"
                  >
                    <span className="truncate mr-2">{action}</span>
                    <button
                      onClick={() => handleCopy(action)}
                      className="opacity-0 group-hover:opacity-100 p-1 hover:text-white transition"
                      title="Copy command"
                    >
                      {copiedCmd === action ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5 text-zinc-500" />
                      )}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Step-by-Step Remediation Plan */}
            <div className="space-y-2">
              <div className="flex items-center space-x-1.5 text-xs font-semibold text-zinc-300 dark:text-zinc-300 light:text-zinc-800 uppercase tracking-wider">
                <FileCheck className="w-3.5 h-3.5 text-zinc-400" />
                <span>Step-by-Step Patch Procedure</span>
              </div>
              <ol className="list-decimal list-inside space-y-1 text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 p-3 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
                {selectedFinding.cve.remediation.stepByStep.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </div>

            {/* Audit Trail Timeline */}
            <div className="space-y-2 pt-2 border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
              <div className="text-[11px] font-mono text-zinc-500 uppercase">
                Autonomous Dispatch &amp; Detection History
              </div>
              <div className="space-y-2">
                {selectedFinding.timeline.map((event, idx) => (
                  <div key={idx} className="text-xs flex items-start space-x-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-zinc-500 mt-1.5 shrink-0" />
                    <div>
                      <div className="text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-medium">
                        {event.action} •{' '}
                        <span className="text-zinc-500 font-mono text-[10px]">{event.system}</span>
                      </div>
                      <div className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px]">
                        {event.details}
                      </div>
                      <div className="text-zinc-500 font-mono text-[10px]">
                        {fmtDateTime(event.timestamp, settings.timezone)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Change Status Modal */}
      {statusModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setStatusModalOpen(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              Update Vulnerability Lifecycle Status
            </h3>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Target Status
                </label>
                <div className="p-2 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-900 font-mono font-semibold">
                  {targetStatus}
                </div>
              </div>

              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Audit Note
                </label>
                <textarea
                  rows={3}
                  placeholder="e.g. Verified vendor patch rollout in maintenance window."
                  value={statusNote}
                  onChange={(e) => setStatusNote(e.target.value)}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-2 mt-4 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
              <button
                onClick={() => setStatusModalOpen(false)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmStatusChange}
                className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs transition"
              >
                Confirm Update
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Resend Notification Modal */}
      {resendModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setResendModalOpen(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2">
              <Send className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              Resend Notification: {selectedFinding && <CveLink cveId={selectedFinding.cveId} />}
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Dispatches an updated alert for this product vulnerability with re-alert tracking.
            </p>

            <label className="block text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-mono mb-1">
              Dispatch Rationale / Update Reason *
            </label>
            <textarea
              rows={3}
              required
              placeholder="e.g. Critical patch update released by vendor."
              value={resendReason}
              onChange={(e) => setResendReason(e.target.value)}
              className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            />

            <div className="flex justify-end space-x-2 mt-4 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200 text-xs">
              <button
                onClick={() => setResendModalOpen(false)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmResend}
                disabled={!resendReason.trim()}
                className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold disabled:opacity-50 transition"
              >
                Dispatch Notification
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Remove Finding Confirmation Modal */}
      {removeConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-rose-300 dark:text-rose-300 light:text-rose-700 mb-2">
              Remove Vulnerability Entry?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to remove <strong>{removeConfirm.cveId}</strong>? This permanently deletes
              the finding from the database. The correlation pipeline may regenerate it on the next run if the
              CVE still matches a monitored product.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                onClick={() => setRemoveConfirm(null)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  const success = await deleteFinding(removeConfirm.id);
                  if (success) {
                    setRemoveFeedback({
                      type: 'success',
                      message: `Removed vulnerability ${removeConfirm.cveId} from findings.`,
                    });
                    setTimeout(() => setRemoveFeedback(null), 5000);
                  } else {
                    setRemoveFeedback({
                      type: 'error',
                      message: 'Failed to remove vulnerability. Please try again.',
                    });
                  }
                  setRemoveConfirm(null);
                }}
                className="px-3 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold"
              >
                Remove Entry
              </button>
            </div>
          </div>
        </div>
      )}

       {/* Remove Feedback */}
      {removeFeedback && (
        <div className="fixed bottom-4 right-4 z-50 max-w-sm">
          <div
            className={`p-3 rounded-xl shadow-lg text-xs flex items-center space-x-2 ${
              removeFeedback.type === 'success'
                ? 'bg-emerald-900/90 border border-emerald-800 text-emerald-200'
                : 'bg-rose-900/90 border border-rose-800 text-rose-200'
            }`}
          >
            {removeFeedback.type === 'success' ? (
              <Check className="w-4 h-4 shrink-0" />
            ) : (
              <X className="w-4 h-4 shrink-0" />
            )}
            <span>{removeFeedback.message}</span>
          </div>
        </div>
      )}

      {/* Bulk Notification Modal */}
      {bulkNotifyModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setBulkNotifyModalOpen(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2">
              <Mail className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              Send Notification for {selectedFindings.size} Finding{selectedFindings.size !== 1 ? 's' : ''}
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Dispatches a security advisory email for the selected findings to the chosen recipient group.
            </p>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-mono mb-1">
                  Recipient Group
                </label>
                <select
                  value={bulkRecipientMode}
                  onChange={(e) => {
                    setBulkRecipientMode(e.target.value as typeof bulkRecipientMode);
                    if (e.target.value !== 'SINGLE_EMAIL') setBulkCustomEmail('');
                  }}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                >
                  <option value="SINGLE_EMAIL">Specific Email Address</option>
                  <option value="SECURITY_TEAM">Security Team</option>
                  <option value="EVERYONE">Everyone</option>
                </select>
              </div>

              {bulkRecipientMode === 'SINGLE_EMAIL' && (
                <div>
                  <label className="block text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-mono mb-1">
                    Custom Email Address
                  </label>
                  <input
                    type="email"
                    placeholder="e.g. analyst@example.com"
                    value={bulkCustomEmail}
                    onChange={(e) => setBulkCustomEmail(e.target.value)}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                  />
                </div>
              )}

              <div>
                <label className="block text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-mono mb-1">
                  Dispatch Rationale / Reason
                </label>
                <textarea
                  rows={3}
                  placeholder="e.g. Manual dispatch for quarterly vendor review. (optional)"
                  value={bulkNotifyReason}
                  onChange={(e) => setBulkNotifyReason(e.target.value)}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-2 mt-4 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200 text-xs">
              <button
                onClick={() => setBulkNotifyModalOpen(false)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  const ok = await sendBulkNotification(
                    Array.from(selectedFindings),
                    bulkNotifyReason,
                    bulkRecipientMode,
                    bulkRecipientMode === 'SINGLE_EMAIL' ? bulkCustomEmail : undefined,
                  );
                  if (ok) {
                    setSelectedFindings(new Set());
                    setBulkNotifyModalOpen(false);
                  }
                }}
                className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition flex items-center space-x-1"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Send Notification</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
