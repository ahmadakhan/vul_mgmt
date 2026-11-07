import { PageHeading } from './PageHeading';
import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { useCollection } from '../hooks/useCollection';
import { RotateCw, CheckCircle2, Search, ShieldCheck, Inbox, RefreshCw } from 'lucide-react';
import { Pagination } from './Pagination';
import type { EmailDeliveryLog } from '../types';
import { formatDateTime as fmtDateTime } from '../utils/dateTime';

export const EmailHistoryView: React.FC = () => {
  const { retryEmailDelivery, emailConfig, setActiveTab, refresh, settings } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [retryingId, setRetryingId] = useState<string | null>(null);
  /** Pending retry confirmation for a single email log. */
  const [confirmingRetryId, setConfirmingRetryId] = useState<string | null>(null);

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const {
    items: emailLogs,
    total,
    loading,
    reload,
  } = useCollection<EmailDeliveryLog>('emailLogs', {
    page: currentPage,
    pageSize,
    search: searchTerm,
    filters: { status: statusFilter },
  });

  const handleRetry = async (logId: string) => {
    setConfirmingRetryId(logId);
  };

  /** Execute a confirmed retry for a single email log. */
  const handleConfirmedRetry = async () => {
    if (!confirmingRetryId) return;
    setRetryingId(confirmingRetryId);
    try {
      await retryEmailDelivery(confirmingRetryId);
      await reload();
    } finally {
      setRetryingId(null);
      setConfirmingRetryId(null);
    }
  };

  // A queued/retrying log with attempts already spent is waiting on the retry
  // backoff. Operators can send it now instead of waiting for the schedule.
  const awaitingRetry = (log: EmailDeliveryLog) =>
    (log.status === 'QUEUED' || log.status === 'RETRYING') &&
    log.attemptCount > 0 &&
    !!log.nextRetryTime &&
    new Date(log.nextRetryTime).getTime() > Date.now();

  const handleRefresh = async () => {
    await refresh();
    await reload();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="ui-page-header">
        <PageHeading page="emails">
          Provider acceptance is not confirmation of inbox delivery. Notification attempts with retry
          schedules (1m / 2m / 4m / 8m / 16m).
        </PageHeading>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center space-x-2 text-xs font-mono bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-3 py-1.5 rounded-xl shadow-sm">
            <ShieldCheck className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-400 light:text-zinc-600" />
            <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              {emailConfig.provider === 'SMTP' ? 'SMTP relay' : emailConfig.provider} transport
            </span>
          </div>
          <button
            type="button"
            onClick={() => void handleRefresh()}
            disabled={loading}
            className="ui-secondary min-h-8 px-3 py-1.5 text-[11px]"
            title="Refresh delivery log"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('email-queue')}
            className="ui-secondary min-h-8 px-3 py-1.5 text-[11px]"
          >
            <Inbox className="h-3.5 w-3.5" aria-hidden="true" />
            Open queue
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm transition-colors">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search logs by recipient, subject, or advisory..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>

        <div className="text-xs font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
          Total Dispatches:{' '}
          <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900">{total}</strong>
        </div>
      </div>

      {/* Email History Table */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Recipient Email</th>
                <th className="py-3 px-4">Subject &amp; Advisory</th>
                <th className="py-3 px-4">Provider</th>
                <th className="py-3 px-4">Delivery Status</th>
                <th className="py-3 px-4">Dispatched Timestamp</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading && emailLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-zinc-500">
                    Loading delivery log...
                  </td>
                </tr>
              ) : emailLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-zinc-500">
                    No delivery records found.
                  </td>
                </tr>
              ) : (
                emailLogs.map((log) => {
                  const isDelivered = log.status === 'DELIVERED';

                  return (
                    <tr
                      key={log.id}
                      className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition"
                    >
                      {/* Recipient */}
                      <td className="py-3 px-4 font-mono font-medium text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                        {log.recipientEmail}
                      </td>

                      {/* Subject & Advisory */}
                      <td className="py-3 px-4">
                        <div className="font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800 line-clamp-1 max-w-sm">
                          {log.subject}
                        </div>
                        <div className="text-[10px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mt-0.5">
                          Ref: {log.advisoryId}
                        </div>
                      </td>

                      {/* Provider */}
                      <td className="py-3 px-4 font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px]">
                        {log.provider}
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4 font-mono">
                        <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-medium bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300">
                          {isDelivered && <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
                          <span>{log.status}</span>
                        </span>
                      </td>

                      {/* Timestamp */}
                      <td className="py-3 px-4 font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px]">
                        {log.sentAt ? fmtDateTime(log.sentAt, settings.timezone) : 'Not accepted yet'}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right">
                        {log.status === 'FAILED' && (
                          <button
                            onClick={() => handleRetry(log.id)}
                            disabled={retryingId === log.id || confirmingRetryId !== null && confirmingRetryId !== log.id}
                            className="px-2.5 py-1 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 text-xs font-medium inline-flex items-center space-x-1 transition"
                          >
                            <RotateCw className={`w-3 h-3 ${retryingId === log.id ? 'animate-spin' : ''}`} />
                            <span>Retry</span>
                          </button>
                        )}
                        {awaitingRetry(log) && (
                          <button
                            onClick={() => handleRetry(log.id)}
                            disabled={retryingId === log.id || confirmingRetryId !== null && confirmingRetryId !== log.id}
                            title="Send now instead of waiting for the scheduled retry"
                            className="px-2.5 py-1 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 text-xs font-medium inline-flex items-center space-x-1 transition"
                          >
                            <RotateCw className={`w-3 h-3 ${retryingId === log.id ? 'animate-spin' : ''}`} />
                            <span>Retry now</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <Pagination
          currentPage={currentPage}
          totalItems={total}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
          pageSizeOptions={[10, 25, 50]}
        />
        {/* Confirmation modal for retry */}
        {confirmingRetryId && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) setConfirmingRetryId(null);
            }}
          >
            <section
              role="dialog"
              aria-modal="true"
              aria-labelledby="confirm-retry-title"
              className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
            >
              <h2 id="confirm-retry-title" className="text-sm font-semibold">
                Retry email delivery?
              </h2>
              <p className="mt-2 text-xs leading-relaxed text-zinc-400">
                This will queue a new delivery attempt. A delivery audit record will be created.
              </p>
              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  className="ui-secondary"
                  disabled={retryingId !== null}
                  onClick={() => setConfirmingRetryId(null)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-60"
                  disabled={retryingId !== null}
                  onClick={() => void handleConfirmedRetry()}
                >
                  {retryingId !== null ? 'Sending…' : 'Confirm retry'}
                </button>
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
};
