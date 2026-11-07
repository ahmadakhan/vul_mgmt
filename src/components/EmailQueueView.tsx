import { PageHeading } from './PageHeading';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Clock3,
  Edit3,
  Inbox,
  RefreshCw,
  RotateCw,
  Search,
  Send,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { EmailQueueItem, ReviewEdits } from '../types';
import { CveLink } from './CveLink';

import { formatDateTime as fmtDateTime } from '../utils/dateTime';

const panel =
  'rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white';
const date = (value: string | null | undefined) => {
  if (!value) return 'Not scheduled';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? 'Not scheduled' : fmtDateTime(parsed);
};

export function EmailQueueView() {
  const {
    listEmailQueue,
    retryEmailDelivery,
    deleteEmailQueueItem,
    clearEmailQueue,
    approveEmailDelivery,
    rejectEmailDelivery,
     editEmailReview,
    previewEmailReview,
    previewEmailEdits,
    session,
  } = useApp();
  const [items, setItems] = useState<EmailQueueItem[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [retryingId, setRetryingId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<EmailQueueItem | null>(null);
  const [confirmClearAll, setConfirmClearAll] = useState(false);
  const [clearAllBusy, setClearAllBusy] = useState(false);
  const [reviewing, setReviewing] = useState<EmailQueueItem | null>(null);
  const [rejecting, setRejecting] = useState<EmailQueueItem | null>(null);
  /** Pending confirmation: { id, action } for manual email sends. */
  const [confirming, setConfirming] = useState<{ id: string; action: 'retry' | 'approve' | 'reject' } | null>(null);
  const [editing, setEditing] = useState<EmailQueueItem | null>(null);
  const [previewHtml, setPreviewHtml] = useState<string>('');
  const [edits, setEdits] = useState<ReviewEdits>({});
  const [previewLoading, setPreviewLoading] = useState(false);
  const [editBusy, setEditBusy] = useState(false);
  const [livePreviewDebounce, setLivePreviewDebounce] = useState<NodeJS.Timeout | null>(null);

  const triggerLivePreview = useCallback(
    (newEdits: ReviewEdits) => {
      if (livePreviewDebounce) clearTimeout(livePreviewDebounce);
      const timer = setTimeout(() => {
        if (!editing) return;
        setPreviewLoading(true);
        void previewEmailEdits(editing.id, newEdits).then((result) => {
          if (result) setPreviewHtml(result.html);
          setPreviewLoading(false);
        });
      }, 500);
      setLivePreviewDebounce(timer);
    },
    [editing, livePreviewDebounce, previewEmailEdits],
  );
  const [reviewBusy, setReviewBusy] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const canManage = session?.role === 'ADMIN' || session?.role === 'OPERATOR';
  const REFRESH_INTERVAL_MS = 10_000;
  const [lastRefreshedAt, setLastRefreshedAt] = useState<number>(Date.now());

  const refresh = async () => {
    setLoading(true);
    const result = await listEmailQueue();
    if (result) {
      setItems(result);
      setLoadError(false);
      setLastRefreshedAt(Date.now());
    } else {
      setLoadError(true);
    }
    setLoading(false);
  };

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => {
      if (document.visibilityState !== 'hidden') void refresh();
    }, REFRESH_INTERVAL_MS);
    const onVisibility = () => {
      if (document.visibilityState === 'visible') void refresh();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  useEffect(() => {
    if (editing) {
      setEdits(editing.edits || {});
      setPreviewLoading(true);
      void previewEmailReview(editing.id).then((preview) => {
        if (preview) {
          setPreviewHtml(preview.html);
          setEdits(preview.edits);
        } else {
          setPreviewHtml(editing.preview || '');
        }
        setPreviewLoading(false);
      });
    }
  }, [editing]);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return items;
    return items.filter((item) =>
      [item.recipientEmail, item.subject, item.advisoryId, item.status, item.error || '']
        .join(' ')
        .toLowerCase()
        .includes(term),
    );
  }, [items, search]);
  const queued = items.filter((item) => item.status === 'QUEUED').length;
  const sending = items.filter((item) => item.status === 'SENDING').length;
  const failed = items.filter((item) => item.status === 'FAILED').length;
  const review = items.filter((item) => item.status === 'REVIEW').length;

  const retry = async (id: string) => {
    setConfirming({ id, action: 'retry' });
  };

  /** Execute a confirmed retry for a queue item. */
  const handleConfirmedRetry = async () => {
    if (!confirming || confirming.action !== 'retry') return;
    setRetryingId(confirming.id);
    try {
      const result = await retryEmailDelivery(confirming.id);
      if (result) await refresh();
    } finally {
      setRetryingId(null);
      setConfirming(null);
    }
  };

  // A queued job with attempts already spent is waiting on the retry backoff.
  // Operators can send it now instead of waiting for the scheduled attempt.
  const awaitingRetry = (item: EmailQueueItem) =>
    item.status === 'QUEUED' &&
    item.attempts > 0 &&
    !!item.nextAttemptAt &&
    new Date(item.nextAttemptAt).getTime() > Date.now();

  const confirmDelete = async () => {
    if (!deleting || deleteBusy) return;
    setDeleteBusy(true);
    const result = await deleteEmailQueueItem(deleting.id);
    if (result) {
      setItems((current) => current.filter((item) => item.id !== deleting.id));
      setDeleting(null);
    }
    setDeleteBusy(false);
  };

  const clearAllQueued = async () => {
    if (clearAllBusy) return;
    setClearAllBusy(true);
    try {
      const result = await clearEmailQueue();
      if (result?.success) {
        setConfirmClearAll(false);
        await refresh();
      }
    } finally {
      setClearAllBusy(false);
    }
  };

  const decideReview = async (item: EmailQueueItem, decision: 'approve' | 'reject') => {
    setReviewing(null);
    setRejecting(null);
    setConfirming({ id: item.id, action: decision });
  };

  /** Execute a confirmed approve/reject review decision. */
  const handleConfirmedReview = async () => {
    if (!confirming) return;
    const { id, action } = confirming;
    setReviewBusy(true);
    const item = items.find((i) => i.id === id);
    if (!item) {
      setConfirming(null);
      setReviewBusy(false);
      return;
    }
    const result =
      action === 'approve' ? await approveEmailDelivery(item.id) : await rejectEmailDelivery(item.id);
    if (result) {
      setItems((current) => current.filter((entry) => entry.id !== id));
      setReviewing(null);
      setRejecting(null);
      await refresh();
    }
    setConfirming(null);
    setReviewBusy(false);
  };

  return (
    <div className="space-y-6">
      <header className="ui-page-header">
        <PageHeading page="email-queue">
          Review notifications for everyone before delivery, and track pending and failed email jobs.
        </PageHeading>
        {canManage && (
          <button
            type="button"
            onClick={() => setConfirmClearAll(true)}
            disabled={clearAllBusy || loading}
            title="Cancel all queued, failed, and review emails; emails already sending are left untouched"
            className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-rose-500/30 px-3 text-xs font-medium text-rose-300 hover:bg-rose-500/10 disabled:opacity-50 light:text-rose-700"
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" /> Remove all
          </button>
        )}
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={loading}
          className="ui-secondary self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
          {loading ? 'Refreshing…' : 'Refresh queue'}
        </button>
        <span
          className="self-start text-xs text-zinc-500 light:text-zinc-600 sm:self-auto"
          aria-label="Auto-refreshing every 10 seconds"
          title="Auto-refreshing every 10 seconds"
        >
          <Clock3 className="inline h-3.5 w-3.5" aria-hidden="true" />
          Auto-refresh in{' '}
          {Math.max(0, Math.ceil((REFRESH_INTERVAL_MS - (Date.now() - lastRefreshedAt)) / 1000))}s
        </span>
      </header>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Email queue totals">
        {[
          { label: 'Needs security review', count: review, tone: 'text-violet-300 light:text-violet-700' },
          { label: 'Queued', count: queued, tone: 'text-blue-300 light:text-blue-700' },
          { label: 'Sending', count: sending, tone: 'text-amber-300 light:text-amber-700' },
          { label: 'Failed', count: failed, tone: 'text-rose-300 light:text-rose-700' },
        ].map((entry) => (
          <div key={entry.label} className={`${panel} flex items-center justify-between p-4`}>
            <span className="text-xs text-zinc-400 light:text-zinc-600">{entry.label}</span>
            <span className={`text-xl font-semibold tabular-nums ${entry.tone}`}>{entry.count}</span>
          </div>
        ))}
      </section>

      <section className={`${panel} overflow-hidden`} aria-label="Email queue jobs">
        <div className="flex flex-col gap-3 border-b border-zinc-800/80 p-4 sm:flex-row sm:items-center sm:justify-between light:border-zinc-200">
          <div className="relative w-full sm:max-w-sm">
            <Search className="absolute left-3 top-3 h-4 w-4 text-zinc-500" aria-hidden="true" />
            <input
              type="search"
              aria-label="Search email queue"
              placeholder="Search recipient, subject, or advisory…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              className="w-full pl-9"
            />
          </div>
          <p className="text-xs text-zinc-500">
            {filtered.length} {filtered.length === 1 ? 'job' : 'jobs'}
            {!canManage && <span> · Read only</span>}
          </p>
        </div>

        {loadError ? (
          <div role="alert" className="flex flex-col items-center gap-3 px-6 py-12 text-center">
            <AlertTriangle className="h-5 w-5 text-amber-400" aria-hidden="true" />
            <p className="text-sm font-medium">Queue could not be loaded</p>
            <p className="text-xs text-zinc-500">Check the connection and try again.</p>
            <button type="button" className="ui-secondary" onClick={() => void refresh()}>
              Try again
            </button>
          </div>
        ) : loading && !items.length ? (
          <div
            role="status"
            className="flex items-center justify-center gap-2 px-6 py-12 text-sm text-zinc-500"
          >
            <RefreshCw className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading email queue…
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-6 py-12 text-center">
            <Inbox className="h-6 w-6 text-zinc-500" aria-hidden="true" />
            <p className="text-sm font-medium">
              {search ? 'No matching email jobs' : 'The email queue is clear'}
            </p>
            <p className="text-xs text-zinc-500">
              {search
                ? 'Try a different search term.'
                : 'Pending and failed email deliveries will appear here.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-xs">
              <thead className="border-b border-zinc-800/80 bg-zinc-950/50 text-[10px] uppercase tracking-wider text-zinc-500 light:border-zinc-200 light:bg-zinc-50">
                <tr>
                  <th scope="col" className="px-4 py-3">
                    Recipient / subject
                  </th>
                  <th scope="col" className="px-4 py-3">
                    Advisory
                  </th>
                  <th scope="col" className="px-4 py-3">
                    Status
                  </th>
                  <th scope="col" className="px-4 py-3">
                    Attempts / next attempt
                  </th>
                  <th scope="col" className="px-4 py-3">
                    Last error
                  </th>
                  <th scope="col" className="px-4 py-3 text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => (
                  <tr key={item.id} className="align-top hover:bg-zinc-800/20 light:hover:bg-zinc-50">
                    <td className="max-w-sm px-4 py-3">
                      <p
                        className="truncate font-medium text-zinc-200 light:text-zinc-800"
                        title={item.recipientEmail}
                      >
                        {item.recipientEmail || 'Recipient unavailable'}
                      </p>
                      <p className="mt-1 line-clamp-2 text-zinc-500" title={item.subject}>
                        {item.subject}
                      </p>
                    </td>
                    <td className="px-4 py-3 font-mono text-zinc-400 break-all">{item.advisoryId}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-medium ${
                          item.status === 'REVIEW'
                            ? 'border-violet-500/20 bg-violet-500/10 text-violet-300 light:text-violet-700'
                            : item.status === 'FAILED'
                              ? 'border-rose-500/20 bg-rose-500/10 text-rose-300 light:text-rose-700'
                              : item.status === 'SENDING'
                                ? 'border-amber-500/20 bg-amber-500/10 text-amber-300 light:text-amber-700'
                                : 'border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700'
                        }`}
                      >
                        {item.status === 'REVIEW' ? 'REVIEW REQUIRED' : item.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-zinc-400">
                      <span className="block tabular-nums">
                        {item.attempts} {item.attempts === 1 ? 'attempt' : 'attempts'}
                      </span>
                      <span className="mt-1 block text-[10px] text-zinc-500">
                        {item.status === 'REVIEW' ? 'Awaiting approval' : date(item.nextAttemptAt || '')}
                      </span>
                    </td>
                    <td className="max-w-xs px-4 py-3 text-zinc-500">
                      {item.error ? (
                        <span className="line-clamp-2" title={item.error}>
                          {item.error}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {canManage && (
                        <div className="inline-flex items-center justify-end gap-2">
                          {item.status === 'REVIEW' && (
                            <>
                              <button
                                type="button"
                                onClick={() => setEditing(item)}
                                className="inline-flex min-h-8 items-center gap-1.5 rounded-lg border border-sky-500/30 px-2.5 py-1 text-[11px] font-medium text-sky-300 transition hover:bg-sky-500/10 light:text-sky-700"
                              >
                                <Edit3 className="h-3 w-3" aria-hidden="true" /> Edit
                              </button>
                              <button
                                type="button"
                                onClick={() => setReviewing(item)}
                                className="inline-flex min-h-8 items-center gap-1.5 rounded-lg border border-violet-500/30 px-2.5 py-1 text-[11px] font-medium text-violet-300 transition hover:bg-violet-500/10 light:text-violet-700"
                              >
                                <ShieldCheck className="h-3 w-3" aria-hidden="true" /> Review
                              </button>
                            </>
                          )}
                          {item.status === 'FAILED' && (
                            <button
                              type="button"
                              onClick={() => void retry(item.id)}
                              disabled={retryingId === item.id || confirming !== null}
                              className="ui-secondary min-h-8 px-2.5 py-1 text-[11px]"
                            >
                              <RotateCw
                                className={`h-3 w-3 ${retryingId === item.id ? 'animate-spin' : ''}`}
                                aria-hidden="true"
                              />
                              Retry
                            </button>
                          )}
                          {awaitingRetry(item) && (
                            <button
                              type="button"
                              onClick={() => void retry(item.id)}
                              disabled={retryingId === item.id || confirming !== null}
                              title="Send now instead of waiting for the scheduled retry"
                              className="ui-secondary min-h-8 px-2.5 py-1 text-[11px]"
                            >
                              <RotateCw
                                className={`h-3 w-3 ${retryingId === item.id ? 'animate-spin' : ''}`}
                                aria-hidden="true"
                              />
                              Retry now
                            </button>
                          )}
                          {item.status !== 'SENDING' && item.status !== 'REVIEW' && (
                            <button
                              type="button"
                              onClick={() => setDeleting(item)}
                              className="inline-flex min-h-8 items-center gap-1.5 rounded-lg border border-rose-500/20 px-2.5 py-1 text-[11px] font-medium text-rose-300 transition hover:bg-rose-500/10 light:text-rose-700"
                              aria-label={`Delete queued email to ${item.recipientEmail}`}
                            >
                              <Trash2 className="h-3 w-3" aria-hidden="true" /> Delete
                            </button>
                          )}
                          {item.status === 'SENDING' && (
                            <span className="inline-flex items-center gap-1.5 text-[10px] text-zinc-500">
                              <Clock3 className="h-3 w-3" aria-hidden="true" /> In progress
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {deleting && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !deleteBusy) setDeleting(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-email-title"
            className={`${panel} w-full max-w-md p-5`}
          >
            <h2 id="delete-email-title" className="text-sm font-semibold">
              Delete queued email?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This removes the delivery job for{' '}
              <span className="font-medium text-zinc-200 light:text-zinc-800">{deleting.recipientEmail}</span>{' '}
              from the queue and marks it cancelled in the delivery history.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                className="ui-secondary"
                disabled={deleteBusy}
                onClick={() => setDeleting(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 text-xs font-semibold text-rose-300 hover:bg-rose-500/20 light:text-rose-700"
                disabled={deleteBusy}
                onClick={() => void confirmDelete()}
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                {deleteBusy ? 'Deleting…' : 'Delete job'}
              </button>
            </div>
          </section>
        </div>
      )}

      {confirmClearAll && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !clearAllBusy) setConfirmClearAll(false);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="clear-email-queue-title"
            className={`${panel} w-full max-w-md p-5`}
          >
            <h2 id="clear-email-queue-title" className="text-sm font-semibold">
              Remove all pending email jobs?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This cancels all queued, failed, and review email jobs and marks their delivery history as cancelled.
              Emails already sending are left untouched; provider-accepted emails cannot be recalled.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                className="ui-secondary"
                disabled={clearAllBusy}
                onClick={() => setConfirmClearAll(false)}
              >
                Keep queue
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 text-xs font-semibold text-rose-300 hover:bg-rose-500/20 disabled:opacity-50 light:text-rose-700"
                disabled={clearAllBusy}
                onClick={() => void clearAllQueued()}
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                {clearAllBusy ? 'Removing…' : 'Remove all'}
              </button>
            </div>
          </section>
        </div>
      )}

      {reviewing && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !reviewBusy) setReviewing(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="review-email-title"
            className={`${panel} w-full max-w-2xl p-5`}
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-violet-300 light:text-violet-700">
                  Security review required
                </p>
                <h2 id="review-email-title" className="mt-1 text-base font-semibold">
                  {reviewing.subject}
                </h2>
                <p className="mt-1 text-xs text-zinc-500">
                  To {reviewing.recipientEmail} · Advisory {reviewing.advisoryId}
                </p>
              </div>
              <button
                type="button"
                aria-label="Close review"
                className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800"
                disabled={reviewBusy}
                onClick={() => setReviewing(null)}
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            {reviewing.cveIds?.length ? (
              <p className="mt-4 text-xs text-zinc-400">
                CVEs:{' '}
                {reviewing.cveIds.map((cveId, index) => (
                  <React.Fragment key={cveId}>
                    {index > 0 && ', '}
                    <CveLink cveId={cveId} />
                  </React.Fragment>
                ))}
              </p>
            ) : null}
            <pre className="mt-4 max-h-[45vh] overflow-auto whitespace-pre-wrap rounded-xl border border-zinc-800 bg-zinc-950/60 p-4 text-xs leading-relaxed text-zinc-300 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-700">
              {reviewing.preview || 'Message preview unavailable.'}
            </pre>
            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                className="ui-secondary"
                disabled={reviewBusy || confirming !== null}
                onClick={() => setReviewing(null)}
              >
                Close
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-rose-500/30 px-4 text-xs font-semibold text-rose-300 hover:bg-rose-500/10 light:text-rose-700"
                disabled={reviewBusy || confirming !== null}
                onClick={() => {
                  setRejecting(reviewing);
                  setReviewing(null);
                }}
              >
                <X className="h-3.5 w-3.5" /> Reject
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-emerald-600 px-4 text-xs font-semibold text-white hover:bg-emerald-500"
                disabled={reviewBusy || confirming !== null}
                onClick={() => void decideReview(reviewing, 'approve')}
              >
                <Check className="h-3.5 w-3.5" />
                {reviewBusy ? 'Saving…' : 'Approve and queue'}
              </button>
            </div>
          </section>
        </div>
      )}

      {editing && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !editBusy) setEditing(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="edit-email-title"
            className={`${panel} w-full max-w-5xl p-0 flex flex-col max-h-[90vh]`}
          >
            <div className="flex items-start justify-between gap-4 p-5 pb-3">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-sky-300 light:text-sky-700">
                  Edit for EVERYONE distribution
                </p>
                <h2 id="edit-email-title" className="mt-1 text-base font-semibold">
                  {editing.subject}
                </h2>
                <p className="mt-1 text-xs text-zinc-500">
                  To {editing.recipientEmail} · Advisory {editing.advisoryId}
                </p>
              </div>
              <button
                type="button"
                aria-label="Close editor"
                className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800"
                disabled={editBusy}
                onClick={() => {
                  if (!editBusy) setEditing(null);
                }}
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto">
              <div className="grid grid-cols-1 gap-0 p-5 pt-3 xl:grid-cols-2">
                <div className="xl:pr-4 xl:border-r xl:border-zinc-800/80 light:xl:border-zinc-200">
                  <div className="space-y-4">
                    <div>
                      <label
                        htmlFor="audience-notice"
                        className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                      >
                        Audience notice
                      </label>
                      <textarea
                        id="audience-notice"
                        rows={4}
                        placeholder="Notice shown above the advisory body for all recipients"
                         value={edits.audienceNotice || ''}
                         onChange={(e) => {
                           const updated = { ...edits, audienceNotice: e.target.value || undefined };
                           setEdits(updated);
                           triggerLivePreview(updated);
                         }}
                         className="mt-1 w-full resize-y font-mono text-xs"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="reviewer-comment"
                        className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                      >
                        Reviewer comment
                      </label>
                      <textarea
                        id="reviewer-comment"
                        rows={3}
                        placeholder="Optional context added at the bottom of the email"
                         value={edits.reviewerComment || ''}
                         onChange={(e) => {
                           const updated = { ...edits, reviewerComment: e.target.value || undefined };
                           setEdits(updated);
                           triggerLivePreview(updated);
                         }}
                         className="mt-1 w-full resize-y font-mono text-xs"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="reviewer-name"
                        className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                      >
                        Reviewer name
                      </label>
                      <input
                        id="reviewer-name"
                        type="text"
                         maxLength={100}
                         placeholder="Name attached to the reviewer comment"
                         value={edits.reviewerName || ''}
                         onChange={(e) => {
                           const updated = { ...edits, reviewerName: e.target.value || undefined };
                           setEdits(updated);
                           triggerLivePreview(updated);
                         }}
                         className="mt-1 w-full text-xs"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="custom-body"
                        className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                      >
                        Custom body override (advanced)
                      </label>
                      <textarea
                        id="custom-body"
                        rows={6}
                         placeholder="Override the entire HTML body — leave empty to keep the template"
                         value={edits.customBodyOverride || ''}
                         onChange={(e) => {
                           const updated = { ...edits, customBodyOverride: e.target.value || undefined };
                           setEdits(updated);
                           triggerLivePreview(updated);
                         }}
                         className="mt-1 w-full resize-y font-mono text-xs"
                      />
                    </div>

                    <button
                       type="button"
                       onClick={async () => {
                         const preview = await previewEmailReview(editing.id);
                         if (preview) {
                           setPreviewHtml(preview.html);
                           setEdits(preview.edits);
                         }
                       }}
                       className="ui-secondary w-full"
                     >
                       <RefreshCw className="h-3.5 w-3.5" /> Reset to saved edits
                     </button>
                  </div>
                </div>

                <div className="xl:pl-4">
                  <p className="mb-2 text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Live preview (email + PDF)
                  </p>
                  {previewLoading ? (
                    <div className="flex h-60 items-center justify-center text-xs text-zinc-500">
                      <RefreshCw className="h-4 w-4 animate-spin" /> Generating preview…
                    </div>
                  ) : (
                    <iframe
                      title="Email preview"
                      sandbox="allow-same-origin allow-scripts"
                      className="h-[480px] w-full rounded-xl border border-zinc-800/80 light:border-zinc-200"
                      srcDoc={previewHtml}
                    />
                  )}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 border-t border-zinc-800/80 p-4 light:border-zinc-200">
              <button
                type="button"
                className="ui-secondary"
                disabled={editBusy}
                onClick={() => setEditing(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="ui-secondary"
                disabled={editBusy}
                onClick={async () => {
                  setPreviewLoading(true);
                  const preview = await previewEmailReview(editing.id);
                  if (preview) {
                    setPreviewHtml(preview.html);
                    setEdits(preview.edits);
                  }
                  setPreviewLoading(false);
                }}
              >
                <Send className="h-3.5 w-3.5" /> Preview
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white hover:bg-sky-500"
                disabled={editBusy}
                onClick={async () => {
                  setEditBusy(true);
                  const result = await editEmailReview(editing.id, edits);
                  if (result) {
                    await previewEmailReview(editing.id).then((preview) => {
                      if (preview) setPreviewHtml(preview.html);
                    });
                    setEditing(null);
                    await refresh();
                  }
                  setEditBusy(false);
                }}
              >
                {editBusy ? 'Saving…' : 'Save edits'}
              </button>
            </div>
          </section>
        </div>
      )}
      {rejecting && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="reject-email-title"
            className={`${panel} w-full max-w-md p-5`}
          >
            <h2 id="reject-email-title" className="text-sm font-semibold">
              Reject this notification?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              The email to{' '}
              <span className="font-medium text-zinc-200 light:text-zinc-800">
                {rejecting.recipientEmail}
              </span>{' '}
              will be cancelled and will not be sent.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                className="ui-secondary"
                disabled={reviewBusy}
                onClick={() => setRejecting(null)}
              >
                Keep for review
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-rose-500/30 px-4 text-xs font-semibold text-rose-300 hover:bg-rose-500/10 light:text-rose-700"
                disabled={reviewBusy || confirming !== null}
                onClick={() => void decideReview(rejecting, 'reject')}
              >
                <X className="h-3.5 w-3.5" />
                {reviewBusy ? 'Rejecting…' : 'Reject notification'}
              </button>
            </div>
          </section>
        </div>
      )}
      {/* Confirmation modal for retry/approve/reject */}
      {confirming && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirming(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-email-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-email-title" className="text-sm font-semibold">
              Send email?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This will{' '}
              {confirming.action === 'retry'
                ? 'retry delivery of this queued email'
                : confirming.action === 'approve'
                ? 'approve and send this review notification'
                : 'reject and cancel this notification'}{' '}
              . A delivery audit record will be created.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                className="ui-secondary"
                disabled={reviewBusy}
                onClick={() => setConfirming(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-60"
                disabled={reviewBusy}
                onClick={() => {
                  if (confirming.action === 'retry') {
                    void handleConfirmedRetry();
                  } else {
                    void handleConfirmedReview();
                  }
                }}
              >
                {reviewBusy ? 'Processing…' : 'Confirm'}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
