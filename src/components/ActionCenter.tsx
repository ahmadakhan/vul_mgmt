import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useApp } from '../context/AppContext';
import { useCollection } from '../hooks/useCollection';
import {
  Search,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Filter,
  TrendingUp,
  Send,
  Edit3,
  Archive,
  X,
  Activity,
  FileText,
  Mail,
  Eye,
  Bold,
  Italic,
  Underline,
  Strikethrough,
  Code,
  List,
  ListOrdered,
  Heading1,
  Heading2,
  Heading3,
  Link,
  Unlink,
  Undo,
  Redo,
  Minus,
  Quote,
  AlignLeft,
  AlignCenter,
  AlignRight,
  Superscript,
  Subscript,
  Save,
  Copy,
  RotateCcw,
  RotateCw,
  ChevronDown,
  Image,
  Table,
  Trash2,
} from 'lucide-react';
import { Pagination } from './Pagination';
import { sanitizeEmailHtml } from '../utils/sanitizeEmailHtml';

function editableEmailBody(html: string): string {
  return new DOMParser().parseFromString(sanitizeEmailHtml(html), 'text/html').body.innerHTML;
}

function emailDocumentWithBody(sourceHtml: string, bodyHtml: string): string {
  const document = new DOMParser().parseFromString(
    sourceHtml || '<!doctype html><html><body></body></html>',
    'text/html',
  );
  document.body.innerHTML = bodyHtml;
  return `<!DOCTYPE html>\n${document.documentElement.outerHTML}`;
}
import { formatDateTime as fmtDateTime } from '../utils/dateTime';
import type { EmailDeliveryLog, ReviewEdits } from '../types';
import { PageHeading } from './PageHeading';
import { isFindingDelivery } from '../utils/findingDelivery';
import { useDialogFocus } from '../hooks/useDialogFocus';

interface SLAMetrics {
  delivered: number;
  failed: number;
  queued: number;
  pendingAction: number;
  averageDeliveryTime: number;
  deliveryRate: number;
  slaCompliance: number;
  lastDeliveryWindow: { count: number; time: string };
}

interface FilterOptions {
  dateRange: 'today' | 'week' | 'month' | 'quarter' | 'year' | 'custom';
  status:
    | 'ALL'
    | 'DELIVERED'
    | 'ACCEPTED'
    | 'REVIEW_REQUIRED'
    | 'QUEUED'
    | 'SENDING'
    | 'RETRYING'
    | 'FAILED'
    | 'CANCELLED';
  provider: string;
  actionStatus: 'ALL' | 'PENDING' | 'ACTIONED';
  advisoryId?: string;
}

type RecipientMode = 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE';

/** Transport acceptance and legacy inbox confirmation both mean "delivered". */
const DELIVERED_STATUSES = new Set(['ACCEPTED', 'DELIVERED']);

const isDeliveredLog = (log: EmailDeliveryLog) => DELIVERED_STATUSES.has(log.status);

/**
 * A delivered finding email starts PENDING and stays there until an operator
 * acknowledges it or dispatches an updated copy. Legacy logs have no
 * `actionStatus`; they are PENDING by definition so older deliveries still
 * appear in the SLA queue.
 */
const isActionPending = (log: EmailDeliveryLog) =>
  isDeliveredLog(log) && (log.actionStatus ?? 'PENDING') === 'PENDING' && isFindingDelivery(log.advisoryId);

export const ActionCenter: React.FC = () => {
  const {
    settings,
    refresh,
    retryEmailDelivery,
    resendEmailDelivery,
    editEmailReview,
    previewEmailReview,
    previewEmailEdits,
    previewEmailPdf,
    acknowledgeEmailDelivery,
    updateAndSendEmail,
    approveEmailDelivery,
    deleteEmailQueueItem,
    advisories,
    findings,
  } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState<FilterOptions>({
    dateRange: 'week',
    status: 'ALL',
    provider: 'ALL',
    actionStatus: 'ALL',
  });
  const [selectedLogs, setSelectedLogs] = useState<Set<string>>(new Set());
  const [showBulkActions, setShowBulkActions] = useState(false);
  const [slaMetrics, setSLAMetrics] = useState<SLAMetrics | null>(null);
  const [isCalculatingSLA, setIsCalculatingSLA] = useState(false);
  const [editing, setEditing] = useState<EmailDeliveryLog | null>(null);
  const [edits, setEdits] = useState<ReviewEdits>({});
  const [subjectDraft, setSubjectDraft] = useState('');
  const [recipientMode, setRecipientMode] = useState<RecipientMode>('SECURITY_TEAM');
  const [customEmail, setCustomEmail] = useState('');
  const [reason, setReason] = useState('');
  const [auditReasonError, setAuditReasonError] = useState<string | null>(null);
  const [previewHtml, setPreviewHtml] = useState<string>('');
  // The preview renders server-authored email HTML via dangerouslySetInnerHTML.
  // The body embeds feed-controlled advisory text, so it passes through a
  // sanitizer that strips script/iframe/event-handler vectors before render;
  // the backend already escapes untrusted values, this is defence in depth.
  const sanitizedPreviewHtml = useMemo(() => sanitizeEmailHtml(previewHtml), [previewHtml]);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewTab, setPreviewTab] = useState<'email' | 'pdf' | 'html'>('email');
  const [pdfUrl, setPdfUrl] = useState<string | null>(null);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  const [htmlContent, setHtmlContent] = useState<string>('');
  const [htmlMode, setHtmlMode] = useState<'visual' | 'source'>('visual');
  const editDialogRef = useDialogFocus(() => {
    if (!editBusy) setEditing(null);
  }, !!editing);
  const [livePreviewDebounce, setLivePreviewDebounce] = useState<ReturnType<typeof setTimeout> | null>(null);
  const pdfUrlRef = useRef<string | null>(null);
  const editorRef = useRef<HTMLDivElement>(null);
  const [resending, setResending] = useState<{ id: string; advisoryId: string; mode: RecipientMode; email: string; reason: string } | null>(null);
  const [resendBusy, setResendBusy] = useState(false);
  const [actionBusyId, setActionBusyId] = useState<string | null>(null);
  /** Pending email-send confirmation: { id, action, label }. Null when none pending. */
  const [confirmSend, setConfirmSend] = useState<{ id: string; action: 'retry' | 'cancel' | 'send-now' | 'resend' | 'approve' | 'update-send'; label: string } | null>(null);
  
  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const {
    items: emailLogs,
    total,
    loading,
    reload,
  } = useCollection<EmailDeliveryLog>('emailLogs', {
    page: currentPage,
    pageSize,
    search: searchTerm,
    filters: {
      status: filters.status,
      provider: filters.provider === 'ALL' ? null : filters.provider,
      actionStatus: filters.actionStatus,
      advisoryId: filters.advisoryId || undefined,
      dateRange: filters.dateRange,
    },
  });

  // Calculate SLA metrics
  useEffect(() => {
    const calculateSLAMetrics = async () => {
      setIsCalculatingSLA(true);
      try {
        // SLA metrics derived from the current page of delivery logs.
        // ACCEPTED is the status the delivery worker actually writes when the
        // transport accepts a message; DELIVERED is the legacy/confirmed value.
        const delivered = emailLogs.filter(isDeliveredLog).length;
        const pendingAction = emailLogs.filter(isActionPending).length;
        const failed = emailLogs.filter(log => log.status === 'FAILED').length;
        const queued = emailLogs.filter(log => ['QUEUED', 'SENDING', 'RETRYING', 'REVIEW_REQUIRED'].includes(log.status)).length;
        const totalLogs = emailLogs.length;
        
        // Calculate delivery rate
        const deliveryRate = totalLogs > 0 ? (delivered / totalLogs) * 100 : 0;

        const now = new Date();
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        
        // Recent deliveries define the 24-hour sample everything below uses.
        const recentDeliveries = emailLogs
          .filter(log => isDeliveredLog(log) && log.sentAt && new Date(log.sentAt) >= yesterday)
          .slice(0, 50);

        // First-attempt success rate is real signal derivable from the log:
        // a job delivered on attempt 1 never needed the retry schedule.
        const firstAttemptDelivered = recentDeliveries.filter((log) => log.attemptCount === 1).length;
        const avgDeliveryTime = recentDeliveries.length > 0
          ? (firstAttemptDelivered / recentDeliveries.length) * 100
          : 0;

        // SLA compliance = deliveries that needed no retry at all, from the
        // same 24-hour sample (previously a hard-coded 100).
        const slaCompliance = avgDeliveryTime;

        const lastHour = new Date(now.getTime() - 60 * 60 * 1000);
        const lastHourDeliveries = emailLogs.filter(log =>
          isDeliveredLog(log) &&
          log.sentAt &&
          new Date(log.sentAt) >= lastHour
        );
        
        setSLAMetrics({
          delivered,
          failed,
          queued,
          pendingAction,
          averageDeliveryTime: avgDeliveryTime,
          deliveryRate,
          slaCompliance,
          lastDeliveryWindow: {
            count: lastHourDeliveries.length,
            time: lastHourDeliveries.length > 0 ? 
              `${lastHourDeliveries[0].sentAt} - ${now.toISOString()}` : 
              'No deliveries'
          }
        });
      } catch (error) {
        console.error('Error calculating SLA metrics:', error);
      } finally {
        setIsCalculatingSLA(false);
      }
    };
    
    calculateSLAMetrics();
  }, [emailLogs]);

  const handleRetry = async (logId: string) => {
    const log = emailLogs.find((l) => l.id === logId);
    setConfirmSend({ id: logId, action: 'retry', label: log?.subject || 'this email' });
  };

  const handleBulkAction = async (action: 'retry' | 'cancel' | 'send-now') => {
    // "Retry" and "send now" both force the job back onto the queue (the
    // server refuses in-flight/due jobs so this cannot double-send); "cancel"
    // removes the queued job. Failures for one id must not abandon the rest.
    setConfirmSend({ id: 'bulk', action: action === 'cancel' ? 'cancel' : 'send-now', label: `${selectedLogs.size} selected emails` });
  };

  /** Releases the blob URL backing the PDF preview. */
  const revokePdf = useCallback(() => {
    if (pdfUrlRef.current) {
      URL.revokeObjectURL(pdfUrlRef.current);
      pdfUrlRef.current = null;
    }
    setPdfUrl(null);
  }, []);

  const buildEdits = useCallback(
    (): ReviewEdits => ({
      ...edits,
      subject: subjectDraft.trim() || undefined,
      recipientMode,
      customEmail: recipientMode === 'SINGLE_EMAIL' ? customEmail.trim() || undefined : undefined,
    }),
    [edits, subjectDraft, recipientMode, customEmail],
  );

  const validateAuditReason = useCallback(() => {
    if (reason.trim()) {
      setAuditReasonError(null);
      return true;
    }
    setAuditReasonError('Enter a reason for this update before saving or sending.');
    document.getElementById('update-reason')?.focus();
    return false;
  }, [reason]);

  const saveEdit = useCallback(async () => {
    if (!editing) return;
    if (!validateAuditReason()) return;
    setEditBusy(true);
    try {
      const result = await editEmailReview(editing.id, buildEdits());
      if (result) {
        setEditing(null);
        await reload();
      }
    } finally {
      setEditBusy(false);
    }
  }, [editing, validateAuditReason, buildEdits, editEmailReview, reload]);

  /** Approve a held review job, or dispatch an updated copy of a delivered one. */
  const sendUpdated = useCallback(async () => {
    if (!editing) return;
    if (!validateAuditReason()) return;
    setConfirmSend({ id: editing.id, action: editing.status === 'REVIEW_REQUIRED' ? 'approve' : 'update-send', label: editing.subject });
  }, [editing, validateAuditReason]);

  /** Execute a previously confirmed email-send action. */
  const handleConfirmedSend = useCallback(async () => {
    if (!confirmSend) return;
    const { id, action, label } = confirmSend;
    setActionBusyId(id);
    try {
      if (id === 'bulk') {
        const results = await Promise.allSettled(
          [...selectedLogs].map((logId) =>
            action === 'cancel'
              ? deleteEmailQueueItem(logId)
              : retryEmailDelivery(logId),
          ),
        );
        const failures = results.filter((r) => r.status === 'rejected').length;
        if (failures)
          console.error(`Bulk ${action}: ${failures} of ${selectedLogs.size} operations failed`);
        setSelectedLogs(new Set());
        setShowBulkActions(false);
        await reload();
        return;
      }
      if (action === 'retry') {
        await retryEmailDelivery(id);
        await reload();
        return;
      }
      if (action === 'resend' && resending) {
        const result = await resendEmailDelivery(resending.id, {
          recipientMode: resending.mode,
          customEmail: resending.mode === 'SINGLE_EMAIL' ? resending.email : undefined,
          reason: resending.reason || undefined,
        });
        if (result) {
          setResending(null);
          await reload();
        }
        return;
      }
      if ((action === 'approve' || action === 'update-send') && editing) {
        if (!validateAuditReason()) return;
        setEditBusy(true);
        try {
          if (editing.status === 'REVIEW_REQUIRED') {
            const saved = await editEmailReview(editing.id, buildEdits());
            if (!saved) return;
            const approved = await approveEmailDelivery(editing.id);
            if (approved) {
              setEditing(null);
              await reload();
            }
            return;
          }
          const result = await updateAndSendEmail(editing.id, {
            subject: subjectDraft.trim() || undefined,
            audienceNotice: edits.audienceNotice,
            reviewerComment: edits.reviewerComment,
            reviewerName: edits.reviewerName,
            customBodyOverride: edits.customBodyOverride,
            recipientMode,
            customEmail:
              recipientMode === 'SINGLE_EMAIL' ? customEmail.trim() || undefined : undefined,
            reason: reason.trim() || undefined,
          });
          if (result) {
            setEditing(null);
            await reload();
          }
        } finally {
          setEditBusy(false);
        }
        return;
      }
    } catch (error) {
      console.error(`Error sending ${label}:`, error);
    } finally {
      setConfirmSend(null);
      setActionBusyId(null);
    }
  }, [
    confirmSend,
    resending,
    editing,
    buildEdits,
    approveEmailDelivery,
    updateAndSendEmail,
    subjectDraft,
    edits,
    recipientMode,
    customEmail,
    reason,
    validateAuditReason,
    selectedLogs,
    retryEmailDelivery,
    deleteEmailQueueItem,
    resendEmailDelivery,
    reload,
  ]);

  const refreshPdf = useCallback(async () => {
    if (!editing) return;
    setPdfLoading(true);
    setPdfError(null);
    try {
      const blob = await previewEmailPdf(editing.id, buildEdits());
      if (!blob) {
        setPdfError('PDF preview could not be generated. See the error banner for details.');
        return;
      }
      if (pdfUrlRef.current) URL.revokeObjectURL(pdfUrlRef.current);
      const url = URL.createObjectURL(blob);
      pdfUrlRef.current = url;
      setPdfUrl(url);
    } catch (caught) {
      setPdfError(caught instanceof Error ? caught.message : 'PDF preview failed');
    } finally {
      setPdfLoading(false);
    }
  }, [editing, buildEdits, previewEmailPdf]);

  const triggerLivePreview = useCallback(
    (newEdits: ReviewEdits, newSubject?: string) => {
      if (!editing) return;
      // Any edit invalidates the rendered PDF; the operator re-renders on demand.
      revokePdf();
      setPdfError(null);
      if (livePreviewDebounce) clearTimeout(livePreviewDebounce);
      const timer = setTimeout(() => {
        setPreviewLoading(true);
        void previewEmailEdits(editing.id, {
          ...newEdits,
          subject: (newSubject ?? subjectDraft).trim() || undefined,
        }).then((result) => {
          if (result) setPreviewHtml(result.html);
          setPreviewLoading(false);
        });
      }, 500);
      setLivePreviewDebounce(timer);
    },
    // livePreviewDebounce is intentionally not a dependency: the callback only
    // cancels the previous timer and setState makes the new one visible to the
    // cleanup effect without re-creating this closure.
    [editing, subjectDraft, previewEmailEdits, revokePdf],
  );

  // Pending live-preview request, debounce timer and PDF blob must not outlive
  // the editor: clear/release all three on unmount and when the editor closes.
  useEffect(() => {
    if (editing) return;
    if (livePreviewDebounce) clearTimeout(livePreviewDebounce);
    setPreviewHtml('');
    revokePdf();
  }, [editing, livePreviewDebounce, revokePdf]);
  useEffect(
    () => () => {
      if (livePreviewDebounce) clearTimeout(livePreviewDebounce);
      if (pdfUrlRef.current) URL.revokeObjectURL(pdfUrlRef.current);
    },
    [livePreviewDebounce],
  );

  const isEditable = (log: EmailDeliveryLog) =>
    log.status === 'REVIEW_REQUIRED' || log.status === 'QUEUED';

  /** Delivered finding emails remain actionable until an operator closes them. */
  const isFollowUpEligible = (log: EmailDeliveryLog) =>
    (isDeliveredLog(log) || log.status === 'FAILED') && isFindingDelivery(log.advisoryId);

  const isActionable = (log: EmailDeliveryLog) => 
    log.status === 'FAILED' || 
    (log.status === 'QUEUED' && log.attemptCount > 0) ||
    (log.status === 'RETRYING' && new Date(log.nextRetryTime || '').getTime() <= Date.now());

  /** CVEs tracked by this delivery: advisory CVE ids plus the CVEs of its findings. */
  const trackedCves = useMemo(() => {
    const byAdvisory = new Map<string, string[]>();
    for (const advisory of advisories) {
      const cves = new Set<string>(advisory.cveIds);
      for (const finding of findings) {
        if (advisory.findingIds.includes(finding.id)) cves.add(finding.cveId);
      }
      byAdvisory.set(advisory.id, [...cves].sort());
    }
    return (advisoryId: string): string[] => byAdvisory.get(advisoryId) ?? [];
  }, [advisories, findings]);

  const cveChips = (advisoryId: string) => {
    const cves = trackedCves(advisoryId);
    return cves.slice(0, 3).map((cve) => (
      <span key={cve} className="mx-0.5 inline-flex items-center rounded bg-zinc-800/60 dark:bg-zinc-800/60 light:bg-zinc-200 px-1.5 py-0.5 text-[10px] font-mono font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-900" title={`Tracking ${cve}`}>
        {cve}
      </span>
    ));
  };

  const cveOverflow = (advisoryId: string) => {
    const cves = trackedCves(advisoryId);
    return cves.length > 3 ? ` +${cves.length - 3}` : null;
  };

  const openEmailEditor = useCallback(
    (log: EmailDeliveryLog) => {
      setEditing(log);
      setEdits({});
      setSubjectDraft(log.subject);
      setReason('');
      setAuditReasonError(null);
      setRecipientMode('SECURITY_TEAM');
      setCustomEmail(log.recipientEmail);
      setPreviewTab('email');
      setHtmlMode('visual');
      setHtmlContent('');
      setPdfError(null);
      revokePdf();
      setPreviewLoading(true);
      void previewEmailReview(log.id).then((preview) => {
        if (preview) {
          setPreviewHtml(preview.html);
          setHtmlContent(preview.edits.customBodyOverride || preview.html);
          setEdits(preview.edits);
          // A saved subject override is what the recipient actually sees.
          setSubjectDraft(preview.subject || log.subject);
          if (preview.edits.recipientMode) setRecipientMode(preview.edits.recipientMode);
          if (preview.edits.customEmail) setCustomEmail(preview.edits.customEmail);
        }
        setPreviewLoading(false);
      });
    },
    [previewEmailReview, revokePdf],
  );

  useEffect(() => {
    if (!editing || previewLoading || htmlMode !== 'visual' || !editorRef.current) return;
    editorRef.current.innerHTML = editableEmailBody(htmlContent);
  }, [editing?.id, previewLoading, htmlMode]);

  // HTML Editor Functions
  const commitVisualBody = useCallback((bodyHtml: string) => {
    const updatedHtml = emailDocumentWithBody(htmlContent, bodyHtml);
    const updatedEdits = { ...edits, customBodyOverride: updatedHtml };
    setHtmlContent(updatedHtml);
    setEdits(updatedEdits);
    triggerLivePreview(updatedEdits, subjectDraft);
  }, [htmlContent, edits, subjectDraft, triggerLivePreview]);

  const execCommand = useCallback((command: string, value?: string) => {
    if (editorRef.current) {
      editorRef.current.focus();
      document.execCommand(command, false, value);
      setTimeout(() => {
        if (editorRef.current) commitVisualBody(editorRef.current.innerHTML);
      }, 0);
    }
  }, [commitVisualBody]);

  const handleHtmlInput = useCallback(() => {
    if (editorRef.current) commitVisualBody(editorRef.current.innerHTML);
  }, [commitVisualBody]);

  const insertHtml = useCallback((html: string) => {
    if (editorRef.current) {
      editorRef.current.focus();
      document.execCommand('insertHTML', false, html);
      setTimeout(() => {
        if (editorRef.current) commitVisualBody(editorRef.current.innerHTML);
      }, 0);
    }
  }, [commitVisualBody]);

  const formatBlock = useCallback((tag: string) => {
    if (editorRef.current) {
      editorRef.current.focus();
      document.execCommand('formatBlock', false, tag);
      setTimeout(() => {
        if (editorRef.current) commitVisualBody(editorRef.current.innerHTML);
      }, 0);
    }
  }, [commitVisualBody]);

  const createLink = useCallback(() => {
    const url = window.prompt('Enter URL:', 'https://');
    if (url) {
      execCommand('createLink', url);
    }
  }, [execCommand]);

  const updatePreviewFromHtml = useCallback(() => {
    if (editorRef.current) commitVisualBody(editorRef.current.innerHTML);
  }, [commitVisualBody]);

  const handleAcknowledge = useCallback(
    async (log: EmailDeliveryLog) => {
      setActionBusyId(log.id);
      try {
        const ok = await acknowledgeEmailDelivery(log.id);
        if (ok) await reload();
      } finally {
        setActionBusyId(null);
      }
    },
    [acknowledgeEmailDelivery, reload],
  );

  const slaStatusColor = (compliance: number) => {
    if (compliance >= 95) return 'text-emerald-400';
    if (compliance >= 90) return 'text-amber-400';
    return 'text-rose-400';
  };

  const deliveryStatusBadge = (log: EmailDeliveryLog) => {
    if (isDeliveredLog(log)) {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <CheckCircle2 className="w-3 h-3" />
          <span>{log.status === 'ACCEPTED' ? 'ACCEPTED' : 'DELIVERED'}</span>
        </span>
      );
    }
    if (log.status === 'FAILED') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
          <AlertTriangle className="w-3 h-3" />
          <span>FAILED</span>
        </span>
      );
    }
    if (log.status === 'REVIEW_REQUIRED') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-violet-500/10 text-violet-400 border border-violet-500/20">
          <Eye className="w-3 h-3" />
          <span>REVIEW</span>
        </span>
      );
    }
    if (log.status === 'CANCELLED') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
          <Archive className="w-3 h-3" />
          <span>CANCELLED</span>
        </span>
      );
    }
    if (isActionable(log) || log.status === 'RETRYING') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <RefreshCw className="w-3 h-3" />
          <span>{log.status === 'RETRYING' ? 'RETRYING' : 'RETRY DUE'}</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
        <Clock3 className="w-3 h-3" />
        <span>{log.status === 'SENDING' ? 'SENDING' : 'QUEUED'}</span>
      </span>
    );
  };

  /**
   * Action SLA state shown in the table. A delivered finding email is PENDING
   * until an operator acknowledges it or sends an updated copy; only failed,
   * bounced, or cancelled deliveries count as SLA violations.
   */
  const actionSlaState = (log: EmailDeliveryLog): 'PENDING' | 'COMPLIANT' | 'VIOLATION' | 'N/A' => {
    if (log.status === 'CANCELLED') return 'N/A';
    if (log.status === 'FAILED' || log.status === 'BOUNCED') return 'VIOLATION';
    if (!isDeliveredLog(log)) return 'PENDING';
    return isActionPending(log) ? 'PENDING' : 'COMPLIANT';
  };

  const actionStatusBadge = (log: EmailDeliveryLog) => {
    if (!isDeliveredLog(log) || !isFindingDelivery(log.advisoryId)) return null;
    return isActionPending(log) ? (
      <span className="inline-flex items-center space-x-1 rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-400">
        <Clock3 className="h-3 w-3" />
        <span>ACTION PENDING</span>
      </span>
    ) : (
      <span className="inline-flex items-center space-x-1 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
        <CheckCircle2 className="h-3 w-3" />
        <span>ACTIONED</span>
      </span>
    );
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedLogs(new Set(emailLogs.map(log => log.id)));
      setShowBulkActions(true);
    } else {
      setSelectedLogs(new Set());
      setShowBulkActions(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="ui-page-header">
        <PageHeading page="action-center">
          Delivered finding emails stay here as PENDING actions until an operator acknowledges them or edits
          and re-sends a corrected copy.
        </PageHeading>

        <div className="flex flex-wrap items-center gap-3">
          {/* SLA Status Indicator */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
            <TrendingUp className="w-4 h-4 text-zinc-400" />
            <span className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              SLA: {slaMetrics?.slaCompliance.toFixed(1)}%
            </span>
            <span className={`text-xs font-medium ${slaStatusColor(slaMetrics?.slaCompliance || 0)}`}>
              {slaMetrics?.averageDeliveryTime.toFixed(1)}% first-attempt
            </span>
          </div>

          {/* Delivery Metrics */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
            <Shield className="w-4 h-4 text-zinc-400" />
            <span className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              {slaMetrics?.delivered || 0} / {slaMetrics?.failed || 0} / {slaMetrics?.queued || 0}
            </span>
          </div>

          {/* Pending operator actions */}
          <button
            type="button"
            onClick={() =>
              setFilters((prev) => ({
                ...prev,
                actionStatus: prev.actionStatus === 'PENDING' ? 'ALL' : 'PENDING',
              }))
            }
            className={`flex items-center space-x-2 rounded-xl border px-3 py-1.5 transition ${
              filters.actionStatus === 'PENDING'
                ? 'border-amber-500/40 bg-amber-500/10'
                : 'border-zinc-800 bg-zinc-900/50 light:border-zinc-200 light:bg-white'
            }`}
            title="Filter deliveries awaiting an operator action"
          >
            <Mail className="w-4 h-4 text-amber-400" />
            <span className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              {slaMetrics?.pendingAction || 0} pending action
            </span>
          </button>

          {/* Last Hour Delivery */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
            <Activity className="w-4 h-4 text-zinc-400" />
            <span className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              {slaMetrics?.lastDeliveryWindow.count} delivered in last hour
            </span>
          </div>

          {/* Refresh Button */}
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={loading}
            className="ui-secondary min-h-8 px-3 py-1.5 text-[11px]"
            title="Refresh metrics and logs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 transition-colors">
        <div className="flex flex-wrap items-center gap-4">
          {/* Search */}
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by recipient, subject, or advisory..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
            />
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-zinc-400" />
              <span className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600">Filters:</span>
            </div>

            {/* Status Filter */}
            <select
              value={filters.status}
              onChange={(e) =>
                setFilters((prev) => ({ ...prev, status: e.target.value as FilterOptions['status'] }))
              }
              className="px-3 py-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            >
              <option value="ALL">All Statuses</option>
              <option value="ACCEPTED">Accepted (delivered)</option>
              <option value="DELIVERED">Delivered (confirmed)</option>
              <option value="REVIEW_REQUIRED">Awaiting review</option>
              <option value="QUEUED">Queued</option>
              <option value="SENDING">Sending</option>
              <option value="RETRYING">Retrying</option>
              <option value="FAILED">Failed</option>
              <option value="CANCELLED">Cancelled</option>
            </select>

            {/* Action Status Filter */}
            <select
              value={filters.actionStatus}
              onChange={(e) =>
                setFilters((prev) => ({
                  ...prev,
                  actionStatus: e.target.value as FilterOptions['actionStatus'],
                }))
              }
              className="px-3 py-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            >
              <option value="ALL">All Actions</option>
              <option value="PENDING">Action pending</option>
              <option value="ACTIONED">Actioned</option>
            </select>

            {/* Provider Filter */}
            <select
              value={filters.provider}
              onChange={(e) => setFilters((prev) => ({ ...prev, provider: e.target.value }))}
              className="px-3 py-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            >
              <option value="ALL">All Providers</option>
              {[...new Set(emailLogs.map((log) => log.provider))].map((provider) => (
                <option key={provider} value={provider}>
                  {provider}
                </option>
              ))}
            </select>

            {/* Date Range Filter */}
            <select
              value={filters.dateRange}
              onChange={(e) =>
                setFilters((prev) => ({ ...prev, dateRange: e.target.value as FilterOptions['dateRange'] }))
              }
              className="px-3 py-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            >
              <option value="today">Today</option>
              <option value="week">This Week</option>
              <option value="month">This Month</option>
              <option value="quarter">This Quarter</option>
              <option value="year">This Year</option>
            </select>
          </div>

          {/* Bulk Actions */}
          {selectedLogs.size > 0 && (
            <div className="flex items-center space-x-2 ml-auto">
              <span className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                {selectedLogs.size} selected
              </span>
              <button
                onClick={() => setShowBulkActions(!showBulkActions)}
                className="ui-primary px-3 py-1.5 text-xs"
              >
                Bulk Actions
              </button>
            </div>
          )}
        </div>

        {/* Expanded Bulk Actions */}
        {showBulkActions && selectedLogs.size > 0 && (
          <div className="mt-4 p-4 bg-zinc-950/50 dark:bg-zinc-950/50 light:bg-zinc-100 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => handleBulkAction('retry')}
                className="px-3 py-1.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20 text-xs font-medium transition"
              >
                <RefreshCw className="w-3 h-3 inline mr-1" /> Retry Selected
              </button>
              <button
                onClick={() => handleBulkAction('send-now')}
                className="px-3 py-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/20 text-xs font-medium transition"
              >
                <Send className="w-3 h-3 inline mr-1" /> Send Now
              </button>
              <button
                onClick={() => handleBulkAction('cancel')}
                className="px-3 py-1.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 text-xs font-medium transition"
              >
                <Archive className="w-3 h-3 inline mr-1" /> Cancel Selected
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Email Delivery Table */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4 w-8">
                  <input
                    type="checkbox"
                    checked={selectedLogs.size === emailLogs.length && emailLogs.length > 0}
                    onChange={(e) => handleSelectAll(e.target.checked)}
                    className="w-4 h-4 rounded border-zinc-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                  />
                </th>
                <th className="py-3 px-4">Recipient Email</th>
                <th className="py-3 px-4">Subject &amp; Advisory</th>
                <th className="py-3 px-4">CVE(s) · Tracking</th>
                <th className="py-3 px-4">Provider</th>
                <th className="py-3 px-4">Delivery Status</th>
                <th className="py-3 px-4">Action SLA</th>
                <th className="py-3 px-4">Dispatched</th>
                <th className="py-3 px-4">Next Attempt</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && emailLogs.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-zinc-500">
                    Loading delivery logs...
                  </td>
                </tr>
              ) : emailLogs.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-zinc-500">
                    No delivery records found.
                  </td>
                </tr>
              ) : (
                emailLogs.map((log) => {
                  const isSelected = selectedLogs.has(log.id);
                  const isDelivered = isDeliveredLog(log);
                  const isFailed = log.status === 'FAILED' || log.status === 'BOUNCED';
                  const isRetryable = isActionable(log);
                  const slaStatus = actionSlaState(log);
                  const slaColor =
                    slaStatus === 'COMPLIANT'
                      ? 'text-emerald-400'
                      : slaStatus === 'VIOLATION'
                        ? 'text-rose-400'
                        : slaStatus === 'N/A'
                          ? 'text-zinc-500'
                          : 'text-amber-400';
                  const canOpenEditor = isEditable(log) || isFollowUpEligible(log);

                  return (
                    <tr
                      key={log.id}
                      className={`hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition ${isSelected ? 'bg-blue-500/10 dark:bg-blue-500/10 light:bg-blue-50' : ''} ${canOpenEditor ? 'cursor-pointer' : ''}`}
                      onClick={() => {
                        if (canOpenEditor) openEmailEditor(log);
                      }}
                    >
                      {/* Select */}
                      <td className="py-3 px-4">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onClick={(e) => e.stopPropagation()}
                          onChange={(e) => {
                            const newSelected = new Set(selectedLogs);
                            if (e.target.checked) {
                              newSelected.add(log.id);
                            } else {
                              newSelected.delete(log.id);
                            }
                            setSelectedLogs(newSelected);
                            setShowBulkActions(newSelected.size > 0);
                          }}
                          className="w-4 h-4 rounded border-zinc-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                        />
                      </td>

                      {/* Recipient */}
                      <td className="py-3 px-4 font-mono font-medium text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                        {log.recipientEmail}
                      </td>

                      {/* Subject & Advisory */}
                      <td className="py-3 px-4 align-top">
                        {/* Two lines plus a title attribute: the subject used to be
                            clamped to one line at max-w-sm, so a long alert title
                            rendered as "[SECURITY ALERT]…" with no way to read it. */}
                        <div
                          className="font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800 line-clamp-2 max-w-md"
                          title={log.subject}
                        >
                          {log.subject}
                        </div>
                        <div className="text-[10px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mt-0.5 break-all">
                          Ref: {log.advisoryId}
                        </div>
                      </td>

                      {/* CVE tracking */}
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {cveChips(log.advisoryId)}
                          {cveOverflow(log.advisoryId) && (
                            <span className="text-[10px] text-zinc-500 font-mono">
                              {cveOverflow(log.advisoryId)}
                            </span>
                          )}
                          {trackedCves(log.advisoryId).length === 0 && (
                            <span className="text-[10px] text-zinc-500 font-mono">No CVEs</span>
                          )}
                        </div>
                      </td>

                      {/* Provider */}
                      <td className="py-3 px-4 font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px]">
                        {log.provider}
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4 font-mono">{deliveryStatusBadge(log)}</td>

                      {/* Action SLA */}
                      <td className="py-3 px-4 font-mono text-[11px]">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className={`font-medium ${slaColor}`}>{slaStatus}</span>
                          {isDelivered && !isActionPending(log) && (
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          )}
                          {isDelivered && isActionPending(log) && (
                            <Clock3 className="w-3 h-3 text-amber-400" />
                          )}
                          {isFailed && <AlertTriangle className="w-3 h-3 text-rose-400" />}
                        </div>
                        <div className="mt-1">{actionStatusBadge(log)}</div>
                        <div className="text-[10px] text-zinc-500 mt-0.5">
                          Attempt #{log.attemptCount}
                          {log.actionedAt && ` · actioned ${fmtDateTime(log.actionedAt, settings.timezone)}`}
                        </div>
                      </td>

                      {/* Timestamp */}
                      <td className="py-3 px-4 font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px]">
                        {log.sentAt ? fmtDateTime(log.sentAt, settings.timezone) : 'Not accepted yet'}
                      </td>

                      {/* Next Attempt */}
                      <td className="py-3 px-4 font-mono text-[11px]">
                        {log.nextRetryTime ? (
                          <div>
                            <span
                              className={
                                new Date(log.nextRetryTime).getTime() <= Date.now()
                                  ? 'text-rose-400'
                                  : 'text-amber-400'
                              }
                            >
                              {fmtDateTime(log.nextRetryTime, settings.timezone)}
                            </span>
                            <div className="text-[10px] text-zinc-500 mt-0.5">
                              {new Date(log.nextRetryTime).getTime() <= Date.now()
                                ? 'Due now'
                                : `In ${Math.round((new Date(log.nextRetryTime).getTime() - Date.now()) / 60000)}m`}
                            </div>
                          </div>
                        ) : (
                          <span className="text-zinc-500">No retry scheduled</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right align-top">
                        <div className="flex flex-wrap items-center justify-end gap-1.5 whitespace-nowrap">
                          {isFollowUpEligible(log) && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                openEmailEditor(log);
                              }}
                              className="inline-flex items-center space-x-1 rounded-lg border border-sky-500/20 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-400 transition hover:bg-sky-500/20"
                            >
                              <Edit3 className="h-3 w-3" />
                              <span>Update &amp; send</span>
                            </button>
                          )}
                          {isDelivered && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                setResending({
                                  id: log.id,
                                  advisoryId: log.advisoryId,
                                  mode: 'SECURITY_TEAM',
                                  email: log.recipientEmail,
                                  reason: '',
                                });
                              }}
                              disabled={resendBusy}
                              className="inline-flex items-center space-x-1 rounded-lg border border-violet-500/20 bg-violet-500/10 px-2.5 py-1 text-xs font-medium text-violet-400 transition hover:bg-violet-500/20"
                            >
                              <Send className="h-3 w-3" />
                              <span>Resend</span>
                            </button>
                          )}
                          {isActionPending(log) && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                void handleAcknowledge(log);
                              }}
                              disabled={actionBusyId === log.id}
                              title="Mark this delivery's follow-up action as done"
                              className="inline-flex items-center space-x-1 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                            >
                              <CheckCircle2 className="h-3 w-3" />
                              <span>{actionBusyId === log.id ? 'Saving…' : 'Done'}</span>
                            </button>
                          )}
                          {!isDelivered && isEditable(log) && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                openEmailEditor(log);
                              }}
                              className="inline-flex items-center space-x-1 rounded-lg border border-sky-500/20 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-400 transition hover:bg-sky-500/20"
                            >
                              <Edit3 className="h-3 w-3" />
                              <span>Edit</span>
                            </button>
                          )}
                          {!isDelivered && !isEditable(log) && isRetryable && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleRetry(log.id);
                              }}
                              className="inline-flex items-center space-x-1 rounded-lg border border-amber-500/20 bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-400 transition hover:bg-amber-500/20"
                            >
                              <RefreshCw className="h-3 w-3" />
                              <span>Retry</span>
                            </button>
                          )}
                        </div>
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
          pageSizeOptions={[10, 25, 50, 100]}
        />
        {editing && (
          <div
            ref={editDialogRef}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget && !editBusy) setEditing(null);
            }}
          >
            <section
              role="dialog"
              aria-modal="true"
              aria-labelledby="edit-email-title"
              className="flex max-h-[92vh] w-full max-w-7xl flex-col overflow-hidden rounded-2xl border border-zinc-800/80 bg-zinc-950 shadow-2xl shadow-black/30 light:border-zinc-200 light:bg-white"
            >
              <div className="flex items-start justify-between gap-4 border-b border-zinc-800/80 px-6 py-5 light:border-zinc-200">
                <div className="min-w-0">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-sky-300 light:text-sky-700">
                    Edit email before sending
                  </p>
                  <h2
                    id="edit-email-title"
                    className="mt-1 truncate text-lg font-semibold tracking-tight text-zinc-100 light:text-zinc-900"
                  >
                    {editing.subject}
                  </h2>
                  <p className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-zinc-400 light:text-zinc-600">
                    <span>To {editing.recipientEmail}</span>
                    <span aria-hidden="true" className="text-zinc-600">
                      ·
                    </span>
                    <span>Advisory {editing.advisoryId}</span>
                    <span
                      className={`ml-1 inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                        editing.status === 'REVIEW_REQUIRED'
                          ? 'border-amber-500/30 bg-amber-500/10 text-amber-300 light:text-amber-700'
                          : editing.status === 'QUEUED'
                            ? 'border-sky-500/30 bg-sky-500/10 text-sky-300 light:text-sky-700'
                            : 'border-zinc-700 bg-zinc-800/70 text-zinc-300 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-700'
                      }`}
                    >
                      {editing.status.replaceAll('_', ' ')}
                    </span>
                  </p>
                </div>
                <button
                  type="button"
                  aria-label="Close editor"
                  className="rounded-lg p-2 text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-500 disabled:cursor-not-allowed disabled:opacity-50 light:hover:bg-zinc-100 light:hover:text-zinc-800"
                  disabled={editBusy}
                  onClick={() => {
                    if (!editBusy) setEditing(null);
                  }}
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="min-h-0 flex-1 overflow-y-auto xl:overflow-hidden">
                <div className="grid grid-cols-1 gap-7 p-6 xl:h-full xl:min-h-0 xl:grid-cols-[minmax(0,0.88fr)_minmax(0,1.12fr)] xl:grid-rows-[minmax(0,1fr)]">
                  <div className="min-w-0 xl:min-h-0 xl:overflow-y-auto xl:overscroll-contain xl:border-r xl:border-zinc-800/80 xl:pr-7 light:xl:border-zinc-200">
                    <div className="space-y-4">
                      <section aria-labelledby="email-content-heading" className="space-y-4">
                        <div className="border-b border-zinc-800/70 pb-2 light:border-zinc-200">
                          <h3
                            id="email-content-heading"
                            className="text-sm font-semibold text-zinc-100 light:text-zinc-900"
                          >
                            Message details
                          </h3>
                          <p className="mt-1 text-[11px] text-zinc-500">
                            Shape the notice recipients will receive.
                          </p>
                        </div>
                        <div>
                          <label
                            htmlFor="email-subject"
                            className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                          >
                            Subject
                          </label>
                          <input
                            id="email-subject"
                            data-dialog-autofocus
                            type="text"
                            maxLength={200}
                            placeholder="Email subject line"
                            value={subjectDraft}
                            onChange={(e) => {
                              setSubjectDraft(e.target.value);
                              triggerLivePreview(edits, e.target.value);
                            }}
                            className="mt-1 w-full text-sm"
                          />
                          <p className="mt-1 text-right text-[10px] text-zinc-500">
                            {subjectDraft.length}/200
                          </p>
                        </div>
                      </section>

                      <section
                        aria-labelledby="html-editor-heading"
                        className="space-y-3 rounded-xl border border-zinc-800/80 bg-zinc-900/50 p-4 light:border-zinc-200 light:bg-zinc-50"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <h3
                              id="html-editor-heading"
                              className="text-xs font-semibold text-zinc-200 light:text-zinc-800"
                            >
                              Email body editor
                            </h3>
                            <p className="mt-1 text-[11px] leading-relaxed text-zinc-500">
                              Edit the HTML content directly. Changes reflect instantly in the preview.
                            </p>
                          </div>
                          <div className="inline-flex rounded-lg border border-zinc-800/80 bg-zinc-900 p-0.5 light:border-zinc-200 light:bg-zinc-100">
                            <button
                              type="button"
                              role="tab"
                              aria-selected={htmlMode === 'visual'}
                              tabIndex={htmlMode === 'visual' ? 0 : -1}
                              onClick={() => setHtmlMode('visual')}
                              className={`rounded-md px-2.5 py-1 text-[11px] font-medium ${
                                htmlMode === 'visual'
                                  ? 'bg-sky-600 text-white shadow-sm'
                                  : 'text-zinc-400 hover:text-zinc-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-500 light:text-zinc-600 light:hover:text-zinc-900'
                              }`}
                            >
                              <Code className="mr-1 inline h-3 w-3" /> Visual
                            </button>
                            <button
                              type="button"
                              role="tab"
                              aria-selected={htmlMode === 'source'}
                              tabIndex={htmlMode === 'source' ? 0 : -1}
                              onClick={() => setHtmlMode('source')}
                              className={`rounded-md px-2.5 py-1 text-[11px] font-medium ${
                                htmlMode === 'source'
                                  ? 'bg-sky-600 text-white shadow-sm'
                                  : 'text-zinc-400 hover:text-zinc-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-500 light:text-zinc-600 light:hover:text-zinc-900'
                              }`}
                            >
                              <FileText className="mr-1 inline h-3 w-3" /> Source
                            </button>
                          </div>
                        </div>

                        {/* Editor Toolbar */}
                        <div
                          className="flex flex-wrap gap-1 p-2 bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-zinc-100 rounded-lg border border-zinc-800/50 light:border-zinc-200"
                          role="toolbar"
                          aria-label="Editor formatting tools"
                        >
                          <div className="flex items-center gap-1">
                            <button type="button" onClick={() => formatBlock('h1')} title="Heading 1" className="editor-btn"><Heading1 className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => formatBlock('h2')} title="Heading 2" className="editor-btn"><Heading2 className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => formatBlock('h3')} title="Heading 3" className="editor-btn"><Heading3 className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => formatBlock('p')} title="Paragraph" className="editor-btn"><span className="text-xs font-medium">¶</span></button>
                          </div>
                          <div className="w-px h-6 bg-zinc-700 mx-1" />
                          <div className="flex items-center gap-1">
                            <button type="button" onClick={() => execCommand('bold')} title="Bold (Ctrl+B)" className="editor-btn"><Bold className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('italic')} title="Italic (Ctrl+I)" className="editor-btn"><Italic className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('underline')} title="Underline (Ctrl+U)" className="editor-btn"><Underline className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('strikeThrough')} title="Strikethrough" className="editor-btn"><Strikethrough className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('subscript')} title="Subscript" className="editor-btn"><Subscript className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('superscript')} title="Superscript" className="editor-btn"><Superscript className="h-3.5 w-3.5" /></button>
                          </div>
                          <div className="w-px h-6 bg-zinc-700 mx-1" />
                          <div className="flex items-center gap-1">
                            <button type="button" onClick={() => execCommand('insertUnorderedList')} title="Bullet list" className="editor-btn"><List className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('insertOrderedList')} title="Numbered list" className="editor-btn"><ListOrdered className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('indent')} title="Increase indent" className="editor-btn"><ChevronDown className="h-3.5 w-3.5 rotate-90" /></button>
                            <button type="button" onClick={() => execCommand('outdent')} title="Decrease indent" className="editor-btn"><ChevronDown className="h-3.5 w-3.5 -rotate-90" /></button>
                          </div>
                          <div className="w-px h-6 bg-zinc-700 mx-1" />
                          <div className="flex items-center gap-1">
                            <button type="button" onClick={() => execCommand('justifyLeft')} title="Align left" className="editor-btn"><AlignLeft className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('justifyCenter')} title="Align center" className="editor-btn"><AlignCenter className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('justifyRight')} title="Align right" className="editor-btn"><AlignRight className="h-3.5 w-3.5" /></button>
                          </div>
                          <div className="w-px h-6 bg-zinc-700 mx-1" />
                          <div className="flex items-center gap-1">
                            <button type="button" onClick={createLink} title="Insert link" className="editor-btn"><Link className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('unlink')} title="Remove link" className="editor-btn"><Unlink className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('formatBlock', 'blockquote')} title="Quote" className="editor-btn"><Quote className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => insertHtml('<hr />')} title="Horizontal rule" className="editor-btn"><Minus className="h-3.5 w-3.5" /></button>
                          </div>
                          <div className="w-px h-6 bg-zinc-700 mx-1" />
                          <div className="flex items-center gap-1">
                            <button type="button" onClick={() => execCommand('undo')} title="Undo (Ctrl+Z)" className="editor-btn"><Undo className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => execCommand('redo')} title="Redo (Ctrl+Y)" className="editor-btn"><Redo className="h-3.5 w-3.5" /></button>
                          </div>
                          <div className="w-px h-6 bg-zinc-700 mx-1" />
                          <div className="flex items-center gap-1 ml-auto">
                            <button type="button" onClick={updatePreviewFromHtml} title="Update preview" className="editor-btn"><RotateCcw className="h-3.5 w-3.5" /></button>
                            <button type="button" onClick={() => {
                              void navigator.clipboard.writeText(htmlContent).catch(() => {});
                            }} title="Copy HTML" className="editor-btn"><Copy className="h-3.5 w-3.5" /></button>
                          </div>
                        </div>

                        {/* Editor Content Area */}
                        <div className="relative">
                          {htmlMode === 'visual' ? (
                            <div
                              ref={editorRef}
                              contentEditable
                              suppressContentEditableWarning
                              onInput={handleHtmlInput}
                              onBlur={updatePreviewFromHtml}
                              className="min-h-[320px] max-h-[480px] overflow-y-auto p-4 bg-white rounded-lg border border-zinc-800/80 light:border-zinc-200 text-zinc-900 light:text-zinc-900 text-sm leading-relaxed focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
                              style={{
                                fontFamily: 'inherit',
                                lineHeight: '1.6',
                              }}
                              data-placeholder="Start typing your email content..."
                            />
                          ) : (
                            <textarea
                              ref={(el) => { if (el) editorRef.current = el as any; }}
                              value={htmlContent}
                              onChange={(e) => {
                                const updatedEdits = { ...edits, customBodyOverride: e.target.value };
                                setHtmlContent(e.target.value);
                                setEdits(updatedEdits);
                                triggerLivePreview(updatedEdits, subjectDraft);
                              }}
                              className="min-h-[320px] max-h-[480px] w-full p-4 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg font-mono text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent resize-y"
                              spellCheck={false}
                              placeholder="Edit HTML source..."
                            />
                          )}
                        </div>
                        <p className="mt-2 text-[10px] text-zinc-500">
                          {htmlMode === 'visual' ? 'Visual editing mode — click to edit directly' : 'Source editing mode — write raw HTML'}
                        </p>
                      </section>

                      <section aria-labelledby="delivery-audience-heading" className="space-y-4">
                        <div className="border-b border-zinc-800/70 pb-2 light:border-zinc-200">
                          <h3
                            id="delivery-audience-heading"
                            className="text-sm font-semibold text-zinc-100 light:text-zinc-900"
                          >
                            Delivery audience
                          </h3>
                          <p className="mt-1 text-[11px] text-zinc-500">
                            Choose who receives this notification.
                          </p>
                        </div>
                        <div>
                          <label
                            htmlFor="recipient-mode"
                            className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                          >
                            Send to
                          </label>
                          <select
                            id="recipient-mode"
                            value={recipientMode}
                            onChange={(e) =>
                              setRecipientMode(
                                e.target.value as 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE',
                              )
                            }
                            className="mt-1 w-full text-xs"
                          >
                            <option value="SINGLE_EMAIL">Single recipient</option>
                            <option value="SECURITY_TEAM">Security team</option>
                            <option value="EVERYONE">Everyone</option>
                          </select>
                          {recipientMode === 'SINGLE_EMAIL' && (
                            <div className="mt-3">
                              <label
                                htmlFor="recipient-email"
                                className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                              >
                                Recipient email address
                              </label>
                              <input
                                id="recipient-email"
                                type="email"
                                placeholder="name@company.com"
                                value={customEmail}
                                onChange={(e) => setCustomEmail(e.target.value)}
                                className="mt-1 w-full text-xs"
                              />
                            </div>
                          )}
                        </div>
                      </section>

                      <section
                        aria-labelledby="audit-context-heading"
                        className="space-y-3 border-t border-zinc-800/70 pt-5 light:border-zinc-200"
                      >
                        <div>
                          <h3
                            id="audit-context-heading"
                            className="text-sm font-semibold text-zinc-100 light:text-zinc-900"
                          >
                            Audit context
                          </h3>
                          <p className="mt-1 text-[11px] text-zinc-500">
                            The reason is recorded with this delivery update.
                          </p>
                        </div>
                        <div>
                          <label
                            htmlFor="update-reason"
                            className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                          >
                            Reason for update <span className="text-rose-400">(required)</span>
                          </label>
                          <input
                            id="update-reason"
                            type="text"
                            maxLength={240}
                            required
                            aria-required="true"
                            aria-invalid={!!auditReasonError}
                            aria-describedby={auditReasonError ? 'update-reason-error' : undefined}
                            placeholder="Recorded in the delivery audit trail"
                            value={reason}
                            onChange={(e) => {
                              setReason(e.target.value);
                              if (e.target.value.trim()) setAuditReasonError(null);
                            }}
                            className="mt-1 w-full text-xs"
                          />
                          <p className="mt-1 text-right text-[10px] text-zinc-500">{reason.length}/240</p>
                          {auditReasonError && (
                            <p id="update-reason-error" role="alert" className="mt-1 text-xs text-rose-400">
                              {auditReasonError}
                            </p>
                          )}
                        </div>
                      </section>
                    </div>
                  </div>

                  <div className="min-w-0 xl:min-h-0 xl:overflow-y-auto xl:overscroll-contain xl:pl-1">
                    <div className="mb-4 flex items-start justify-between gap-3">
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-sky-300 light:text-sky-700">
                          Recipient-facing preview
                        </p>
                        <h3 className="mt-1 text-sm font-semibold text-zinc-100 light:text-zinc-900">
                          Review the rendered message
                        </h3>
                        <p className="mt-1 text-[11px] text-zinc-500">
                          Preview reflects your edits; active content is sanitized.
                        </p>
                      </div>
                      <span className="mt-1 inline-flex shrink-0 items-center gap-1.5 rounded-full border border-emerald-500/25 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-medium text-emerald-300 light:text-emerald-700">
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                        Live draft
                      </span>
                    </div>

                    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                      <div
                        role="tablist"
                        aria-label="Preview format"
                        className="inline-flex rounded-lg border border-zinc-800/80 bg-zinc-900 p-0.5 light:border-zinc-200 light:bg-zinc-100"
                        onKeyDown={(event) => {
                          if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
                          event.preventDefault();
                          const nextTab =
                            event.key === 'Home'
                              ? 'email'
                              : event.key === 'End'
                                ? 'pdf'
                                : event.key === 'ArrowRight'
                                  ? previewTab === 'email' ? 'pdf' : 'email'
                                  : previewTab === 'email' ? 'pdf' : 'email';
                          setPreviewTab(nextTab);
                          event.currentTarget
                            .querySelector<HTMLButtonElement>(`[data-preview-tab="${nextTab}"]`)
                            ?.focus();
                          if (nextTab === 'pdf') void refreshPdf();
                        }}
                      >
                        <button
                          type="button"
                          role="tab"
                          data-preview-tab="email"
                          aria-selected={previewTab === 'email'}
                          tabIndex={previewTab === 'email' ? 0 : -1}
                          aria-controls="email-preview-panel"
                          onClick={() => setPreviewTab('email')}
                          className={`rounded-md px-2.5 py-1 text-[11px] font-medium ${
                            previewTab === 'email'
                              ? 'bg-sky-600 text-white shadow-sm'
                              : 'text-zinc-400 hover:text-zinc-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-500 light:text-zinc-600 light:hover:text-zinc-900'
                          }`}
                        >
                          <Mail className="mr-1 inline h-3 w-3" /> Email
                        </button>
                        <button
                          type="button"
                          role="tab"
                          data-preview-tab="pdf"
                          aria-selected={previewTab === 'pdf'}
                          tabIndex={previewTab === 'pdf' ? 0 : -1}
                          aria-controls="pdf-preview-panel"
                          onClick={() => {
                            setPreviewTab('pdf');
                            void refreshPdf();
                          }}
                          className={`rounded-md px-2.5 py-1 text-[11px] font-medium ${
                            previewTab === 'pdf'
                              ? 'bg-sky-600 text-white shadow-sm'
                              : 'text-zinc-400 hover:text-zinc-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-500 light:text-zinc-600 light:hover:text-zinc-900'
                          }`}
                        >
                          <FileText className="mr-1 inline h-3 w-3" /> PDF
                        </button>
                      </div>
                      {previewTab === 'pdf' && (
                        <button
                          type="button"
                          className="ui-secondary inline-flex items-center gap-1 px-2 py-1 text-[11px]"
                          disabled={pdfLoading}
                          onClick={() => void refreshPdf()}
                        >
                          <RefreshCw className={`h-3 w-3 ${pdfLoading ? 'animate-spin' : ''}`} />
                          Refresh PDF
                        </button>
                      )}
                    </div>

                    <div
                      role="tabpanel"
                      id="email-preview-panel"
                      aria-label="Email preview"
                      hidden={previewTab !== 'email'}
                    >
                      {previewTab === 'email' && (
                        previewLoading ? (
                          <div className="flex h-[480px] flex-col items-center justify-center gap-3 rounded-xl border border-zinc-800/80 bg-zinc-900/50 text-xs text-zinc-400 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-600">
                            <RefreshCw className="h-5 w-5 animate-spin text-sky-400" />
                            <span>Generating preview…</span>
                          </div>
                        ) : (
                          <div
                            className="h-[480px] w-full overflow-auto rounded-xl border border-zinc-800/80 bg-white p-5 shadow-inner light:border-zinc-200"
                            dangerouslySetInnerHTML={{ __html: sanitizedPreviewHtml }}
                          />
                        )
                      )}
                    </div>
                    <div
                      role="tabpanel"
                      id="pdf-preview-panel"
                      aria-label="PDF preview"
                      hidden={previewTab !== 'pdf'}
                    >
                      {previewTab === 'pdf' && (
                        <div className="h-[480px] w-full overflow-hidden rounded-xl border border-zinc-800/80 light:border-zinc-200">
                          {pdfLoading ? (
                            <div className="flex h-full items-center justify-center text-xs text-zinc-500">
                              <RefreshCw className="h-4 w-4 animate-spin" /> Rendering PDF…
                            </div>
                          ) : pdfError ? (
                            <div className="flex h-full items-center justify-center p-6 text-center text-xs text-rose-400">
                              <FileText className="h-8 w-8 mb-2" />
                              <div>{pdfError}</div>
                              <button
                                onClick={() => void refreshPdf()}
                                className="mt-4 px-3 py-1.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 text-xs font-medium transition"
                              >
                                <RefreshCw className="h-3 w-3 inline mr-1" /> Retry
                              </button>
                            </div>
                          ) : pdfUrl ? (
                            <iframe
                              title="PDF preview"
                              className="h-full w-full"
                              src={`${pdfUrl}#toolbar=0&view=FitH&scrollbar=0&statusbar=0&messages=0&navpanes=0`}
                              sandbox="allow-same-origin allow-scripts allow-popups"
                            />
                          ) : (
                            <div className="flex h-full items-center justify-center text-xs text-zinc-500">
                              <FileText className="h-8 w-8 mb-2" />
                              <div>Open the PDF tab to render the attachment.</div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    <p className="mt-2 text-[11px] text-zinc-500">
                      The PDF attachment is generated from this same edited body, so both stay in sync.
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3 border-t border-zinc-800/80 bg-zinc-900/70 px-6 py-4 light:border-zinc-200 light:bg-zinc-50">
                <p className="mr-auto text-[11px] text-zinc-500" aria-live="polite">
                  {editing.status === 'REVIEW_REQUIRED'
                    ? 'Review the message before approving delivery.'
                    : editing.status === 'QUEUED'
                      ? 'Edits are saved to the queued notification.'
                      : 'The updated message will be sent as a new delivery.'}
                </p>
                <button
                  type="button"
                  className="ui-secondary focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-500"
                  disabled={editBusy}
                  onClick={() => setEditing(null)}
                >
                  Cancel
                </button>
                {editing.status === 'REVIEW_REQUIRED' ? (
                  <button
                    type="button"
                    className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-amber-400/30 bg-amber-500 px-4 text-xs font-semibold text-zinc-950 shadow-sm transition hover:bg-amber-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={editBusy}
                    onClick={sendUpdated}
                  >
                    <Send className="h-3.5 w-3.5" />
                    {editBusy ? 'Sending…' : 'Approve & send'}
                  </button>
                ) : editing.status === 'QUEUED' ? (
                  <button
                    type="button"
                    className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={editBusy}
                    onClick={saveEdit}
                  >
                    <Edit3 className="h-3.5 w-3.5" />
                    {editBusy ? 'Saving…' : 'Save edits'}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={
                      editBusy ||
                      (recipientMode === 'SINGLE_EMAIL' &&
                        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customEmail.trim()))
                    }
                    onClick={sendUpdated}
                  >
                    <Send className="h-3.5 w-3.5" />
                    {editBusy ? 'Sending…' : 'Update & send'}
                  </button>
                )}
              </div>
            </section>
          </div>
        )}
        {resending && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget && !resendBusy) setResending(null);
            }}
          >
            <section
              role="dialog"
              aria-modal="true"
              aria-labelledby="resend-email-title"
              className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
            >
              <div className="flex items-start justify-between gap-4 p-5 pb-3">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-sky-300 light:text-sky-700">
                    Resend delivered email
                  </p>
                  <h2 id="resend-email-title" className="mt-1 text-base font-semibold">
                    Resend to{' '}
                    {resending.mode === 'SINGLE_EMAIL'
                      ? resending.email
                      : resending.mode === 'SECURITY_TEAM'
                        ? 'Security team'
                        : 'Everyone'}
                  </h2>
                  <p className="mt-1 text-xs text-zinc-500">
                    Advisory {resending.advisoryId} · queues a new PENDING delivery
                  </p>
                </div>
                <button
                  type="button"
                  aria-label="Close resend"
                  className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800"
                  disabled={resendBusy}
                  onClick={() => {
                    if (!resendBusy) setResending(null);
                  }}
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-5 pt-3">
                <div className="space-y-4">
                  <div>
                    <label
                      htmlFor="resend-mode"
                      className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                    >
                      Send to
                    </label>
                    <select
                      id="resend-mode"
                      value={resending.mode}
                      onChange={(e) =>
                        setResending((prev) =>
                          prev
                            ? {
                                ...prev,
                                mode: e.target.value as 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE',
                              }
                            : null,
                        )
                      }
                      className="mt-1 w-full text-xs"
                    >
                      <option value="SINGLE_EMAIL">Single recipient</option>
                      <option value="SECURITY_TEAM">Security team</option>
                      <option value="EVERYONE">Everyone</option>
                    </select>
                    {resending.mode === 'SINGLE_EMAIL' && (
                      <input
                        type="email"
                        placeholder="Recipient email address"
                        value={resending.email}
                        onChange={(e) =>
                          setResending((prev) => (prev ? { ...prev, email: e.target.value } : null))
                        }
                        className="mt-2 w-full text-xs"
                      />
                    )}
                  </div>

                  <div>
                    <label
                      htmlFor="resend-reason"
                      className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                    >
                      Reason (audit note)
                    </label>
                    <textarea
                      id="resend-reason"
                      rows={3}
                      placeholder="Why this advisory is being resent..."
                      value={resending.reason}
                      onChange={(e) =>
                        setResending((prev) => (prev ? { ...prev, reason: e.target.value } : null))
                      }
                      className="mt-1 w-full resize-y font-mono text-xs"
                    />
                  </div>

                  <div className="text-xs text-zinc-500">
                    A new delivery job is queued for the selected group. Use the edit action on the new job to
                    adjust the audience or content before it ships.
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      if (!resending) return;
                      setResending(null);
                      setConfirmSend({ id: resending.id, action: 'resend', label: `resend to ${resending.mode === 'SINGLE_EMAIL' ? resending.email : resending.mode}` });
                    }}
                    disabled={resendBusy || (resending.mode === 'SINGLE_EMAIL' && !resending.email)}
                    className="ui-secondary w-full"
                  >
                    {resendBusy ? 'Queueing…' : 'Queue resend'}
                  </button>
                </div>
              </div>

              <div className="flex justify-end border-t border-zinc-800/80 p-4 light:border-zinc-200">
                <button
                  type="button"
                  className="ui-secondary"
                  disabled={resendBusy}
                  onClick={() => setResending(null)}
                >
                  Cancel
                </button>
              </div>
            </section>
          </div>
        )}
        {/* Confirmation modal for manual email sends */}
        {confirmSend && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) setConfirmSend(null);
            }}
          >
            <section
              role="dialog"
              aria-modal="true"
              aria-labelledby="confirm-send-title"
              className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
            >
              <h2 id="confirm-send-title" className="text-sm font-semibold">
                Send email?
              </h2>
              <p className="mt-2 text-xs leading-relaxed text-zinc-400">
                This will{' '}
                {confirmSend.action === 'cancel'
                  ? 'cancel'
                  : confirmSend.action === 'retry'
                  ? 'retry delivery of'
                  : confirmSend.action === 'resend'
                  ? 'resend'
                  : confirmSend.action === 'approve'
                  ? 'approve and send'
                  : 'send an updated copy of'}
                {' '}
                <span className="font-medium text-zinc-200 light:text-zinc-800">{confirmSend.label}</span>.{' '}
                {confirmSend.id === 'bulk'
                  ? 'This cannot be undone.'
                  : 'A delivery audit record will be created.'}
              </p>
              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  className="ui-secondary"
                  disabled={actionBusyId === confirmSend.id}
                  onClick={() => setConfirmSend(null)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-60"
                  disabled={actionBusyId === confirmSend.id}
                  onClick={() => void handleConfirmedSend()}
                >
                  {actionBusyId === confirmSend.id ? 'Sending…' : 'Confirm send'}
                </button>
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
};