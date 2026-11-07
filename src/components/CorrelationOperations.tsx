import {
  ClipboardCheck,
  Database,
  Flame,
  Inbox,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  AlertTriangle,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useApp } from '../context/AppContext';
import type { CorrelationPolicy, CorrelationWorkflows } from '../../shared/correlation';
import { formatDateTime as fmtDateTime } from '../utils/dateTime';
import { useDialogFocus } from '../hooks/useDialogFocus';
interface InventoryRow {
  id: string;
  vendor: string;
  product: string;
  version: string | null;
  recordId: string | null;
  assetTag: string | null;
}
const field = 'ui-field cr-operation-field';
const button = 'ui-secondary';
export function CorrelationOperations() {
  const { session, csrfToken, settings } = useApp();
  const [state, setState] = useState<CorrelationWorkflows | null>(null);
  const [policy, setPolicy] = useState<CorrelationPolicy | null>(null);
  const [notice, setNotice] = useState('');
  const [noticeError, setNoticeError] = useState(false);
  const [refreshError, setRefreshError] = useState('');
  const [hasSearched, setHasSearched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState('');
  const [assetId, setAssetId] = useState('');
  const [note, setNote] = useState('');
  const [correction, setCorrection] = useState('');
  const [assets, setAssets] = useState<InventoryRow[]>([]);
  const [query, setQuery] = useState('');
  const [assetCursor, setAssetCursor] = useState<string | null>(null);
  const decisionRef = useRef<HTMLDivElement>(null);
  const [confirmSavePolicy, setConfirmSavePolicy] = useState<{ action: string; label: string } | null>(null);
  const [confirmRetentionRun, setConfirmRetentionRun] = useState<{ action: string; label: string } | null>(null);
  const [confirmArmGate, setConfirmArmGate] = useState<{ action: 'arm' | 'disarm'; armed: boolean } | null>(null);
  const [confirmApproveReview, setConfirmApproveReview] = useState<{ id: string; assetId: string; note: string } | null>(null);
  const [confirmDismissReview, setConfirmDismissReview] = useState<{ id: string; note: string } | null>(null);
  const [confirmReplayDeadLetter, setConfirmReplayDeadLetter] = useState<{ id: string; note: string; correction: string } | null>(null);
  const [confirmDismissDeadLetter, setConfirmDismissDeadLetter] = useState<{ id: string; note: string } | null>(null);
  const isConfirming =
    confirmSavePolicy !== null ||
    confirmRetentionRun !== null ||
    confirmArmGate !== null ||
    confirmApproveReview !== null ||
    confirmDismissReview !== null ||
    confirmReplayDeadLetter !== null ||
    confirmDismissDeadLetter !== null;
  const confirmationDialogRef = useDialogFocus(() => {
    if (busy) return;
    setConfirmSavePolicy(null);
    setConfirmRetentionRun(null);
    setConfirmArmGate(null);
    setConfirmApproveReview(null);
    setConfirmDismissReview(null);
    setConfirmReplayDeadLetter(null);
    setConfirmDismissDeadLetter(null);
  }, isConfirming);
  useEffect(() => {
    if (selected) decisionRef.current?.focus();
  }, [selected]);
  const admin = session?.role === 'ADMIN';
  const operator = admin || session?.role === 'OPERATOR';
  const refresh = useCallback(async (signal?: AbortSignal) => {
    const response = await fetch('/api/correlation/workflows', { credentials: 'same-origin', signal });
    if (!response.ok) throw new Error(`Workflow unavailable (HTTP ${response.status})`);
    const data = (await response.json()) as CorrelationWorkflows;
    if (!signal?.aborted) {
      setState(data);
      setRefreshError('');
      setPolicy((current) => current || data.policy);
    }
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        await refresh(AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]));
      } catch {
        if (!controller.signal.aborted)
          setRefreshError('Workflow data could not be refreshed. Retrying automatically.');
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(() => void tick(), 5000);
      }
    };
    void tick();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [refresh]);
  const mutate = async (path: string, body: unknown, method = 'POST') => {
    if (busy) return;
    setBusy(true);
    setNotice('');
    setNoticeError(false);
    try {
      const response = await fetch('/api/correlation/' + path, {
        method,
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) {
        const error = (await response.json()) as { error?: string };
        throw new Error(error.error || `Action failed (HTTP ${response.status})`);
      }
      const data = (await response.json()) as { removed?: number };
      setNotice(
        data.removed === undefined ? 'Decision saved' : `${data.removed} resolved or expired records removed`,
      );
      setSelected('');
      setNote('');
      setCorrection('');
      await refresh();
    } catch (reason) {
      setNoticeError(true);
      setNotice(reason instanceof Error ? reason.message : 'Action failed');
    } finally {
      setBusy(false);
    }
  };
  const armGate = useCallback(() => {
    if (!state) return;
    const next = !state.faultSimulationArmed;
    setConfirmArmGate({ action: next ? 'arm' : 'disarm', armed: next });
  }, [state]);

  const executeArmGate = async () => {
    const confirmation = confirmArmGate;
    if (!confirmation || !state) return;
    setBusy(true);
    setNotice('');
    setNoticeError(false);
    try {
      const response = await fetch('/api/correlation/fault/arming', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify({ armed: confirmation.armed }),
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) {
        const error = (await response.json()) as { error?: string };
        throw new Error(error.error || `Arming failed (HTTP ${response.status})`);
      }
      const data = (await response.json()) as { faultSimulationArmed: boolean };
      setState((current) =>
        current ? { ...current, faultSimulationArmed: data.faultSimulationArmed } : current,
      );
      setNotice(`Fault simulation gate ${data.faultSimulationArmed ? 'armed' : 'disarmed'}`);
    } catch (reason) {
      setNoticeError(true);
      setNotice(reason instanceof Error ? reason.message : 'Fault simulation arming failed');
    } finally {
      setBusy(false);
      setConfirmArmGate(null);
    }
  };

  const executeSavePolicy = async () => {
    if (!confirmSavePolicy || !policy) return;
    await mutate('policy', policy, 'PATCH');
    setConfirmSavePolicy(null);
  };

  const executeRetentionRun = async () => {
    if (!confirmRetentionRun) return;
    await mutate('retention/run', {});
    setConfirmRetentionRun(null);
  };

  const executeApproveReview = async () => {
    const confirmation = confirmApproveReview;
    if (!confirmation) return;
    await mutate(`reviews/${confirmation.id}/decision`, {
      decision: 'APPROVED',
      assetId: confirmation.assetId,
      note: confirmation.note,
    });
    setConfirmApproveReview(null);
  };

  const executeDismissReview = async () => {
    const confirmation = confirmDismissReview;
    if (!confirmation) return;
    await mutate(`reviews/${confirmation.id}/decision`, { decision: 'DISMISSED', note: confirmation.note });
    setConfirmDismissReview(null);
  };

  const executeReplayDeadLetter = async () => {
    const confirmation = confirmReplayDeadLetter;
    if (!confirmation) return;
    let payload: unknown;
    if (confirmation.correction.trim()) {
      try {
        payload = JSON.parse(confirmation.correction);
      } catch {
        setNoticeError(true);
        setNotice('Corrected advisory must be valid JSON');
        return;
      }
    }
    await mutate(`dead-letters/${confirmation.id}/decision`, {
      action: 'REPLAYED',
      note: confirmation.note,
      ...(payload ? { payload } : {}),
    });
    setConfirmReplayDeadLetter(null);
  };

  const executeDismissDeadLetter = async () => {
    const confirmation = confirmDismissDeadLetter;
    if (!confirmation) return;
    await mutate(`dead-letters/${confirmation.id}/decision`, { action: 'DISMISSED', note: confirmation.note });
    setConfirmDismissDeadLetter(null);
  };

  const searchAssets = async (after?: string) => {
    setBusy(true);
    try {
      const params = new URLSearchParams({ q: query });
      if (after) params.set('after', after);
      const response = await fetch('/api/correlation/assets?' + params, {
        credentials: 'same-origin',
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error('Inventory search failed');
      const data = (await response.json()) as { assets: InventoryRow[]; nextCursor: string | null };
      setAssets(data.assets);
      setHasSearched(true);
      setAssetCursor(data.nextCursor);
    } catch (reason) {
      setNoticeError(true);
      setNotice(reason instanceof Error ? reason.message : 'Inventory search failed');
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="cr-workflows cr-view-content" aria-labelledby="correlation-review-title">
      <div className="ui-panel cr-control-card">
        <div className="cr-section-title">
          <span className="ui-section-icon">
            <ClipboardCheck size={18} />
          </span>
          <div>
            <h2 id="correlation-review-title">Review & delivery workspace</h2>
            <p>Resolve uncertain evidence and manage what happens after a match.</p>
          </div>
        </div>
        <div className="cr-queue-summary">
          <div>
            <span>Pending processing</span>
            <strong>{state?.counts.pending ?? '—'}</strong>
          </div>
          <div>
            <span>Open reviews</span>
            <strong>{state?.counts.reviews ?? '—'}</strong>
          </div>
          <div>
            <span>Unresolved dead letters</span>
            <strong>{state?.counts.deadLetters ?? '—'}</strong>
          </div>
        </div>
      </div>
      {refreshError && (
        <div className="cr-notice cr-notice-warning" role="alert">
          <AlertTriangle size={16} />
          <p>{refreshError}</p>
        </div>
      )}
      {policy && (
        <form
          className="ui-panel cr-control-card cr-policy-form"
          onSubmit={(event) => {
            event.preventDefault();
            setConfirmSavePolicy({ action: 'save', label: 'Save policy' });
          }}
        >
          <div className="cr-section-title">
            <span className="ui-section-icon">
              <SlidersHorizontal size={18} />
            </span>
            <div>
              <h3>Delivery & retention policy</h3>
              <p>Configure native notifications and resolved-data retention.</p>
            </div>
          </div>
          <div className="cr-policy-controls">
            <label className="ui-check-row">
              <input
                type="checkbox"
                disabled={!admin || busy}
                checked={policy.notificationsEnabled}
                onChange={(event) => setPolicy({ ...policy, notificationsEnabled: event.target.checked })}
              />
              Enable native notifications
            </label>
            <label className="ui-check-row">
              <input
                type="checkbox"
                disabled={!admin || busy}
                checked={policy.retentionEnabled}
                onChange={(event) => setPolicy({ ...policy, retentionEnabled: event.target.checked })}
              />
              Retain resolved data for
            </label>
            <label className="text-sm">
              <input
                aria-label="Correlation retention hours"
                className={field + ' w-24'}
                type="number"
                min={24}
                max={87600}
                disabled={!admin || busy}
                value={policy.retentionHours}
                onChange={(event) => setPolicy({ ...policy, retentionHours: Number(event.target.value) })}
              />{' '}
              hours
            </label>
            <button
              className={button}
              disabled={
                !admin ||
                busy ||
                isConfirming ||
                !Number.isInteger(policy.retentionHours) ||
                policy.retentionHours < 24 ||
                policy.retentionHours > 87600
              }
            >
              Save policy
            </button>
            <button
              type="button"
              className={button}
              disabled={!admin || busy || isConfirming}
              onClick={() => setConfirmRetentionRun({ action: 'run', label: 'Run retention batch' })}
            >
              Run retention batch
            </button>
          </div>
        </form>
      )}
      {admin && (
        <form
          className="ui-panel cr-control-card"
          onSubmit={(event) => {
            event.preventDefault();
            void armGate();
          }}
        >
          <div className="cr-section-title">
            <span className="ui-section-icon">
              <Flame size={17} />
            </span>
            <div>
              <h3>Fault simulation gate</h3>
              <p>
                The fleet-wide gate required by /api/correlation/fault. The per-replica
                FAULT_SIMULATION_ENABLED flag must also be set. Admin-only; every change is audited.
              </p>
            </div>
          </div>
          <div className="cr-policy-controls">
            <label className="ui-check-row">
              <input
                type="checkbox"
                disabled={busy || !state}
                checked={!!state?.faultSimulationArmed}
                onChange={() => void armGate()}
              />
              Fleet-wide simulation gate armed
            </label>
            <button type="submit" className={button} disabled={busy || !state}>
              {state?.faultSimulationArmed ? 'Disarm' : 'Arm'} gate
            </button>
          </div>
        </form>
      )}
      <p className="cr-caption cr-policy-explanation">
        Enabling notifications starts with new matches. HIGH evidence follows configured subscriptions; MEDIUM
        email requires approval in Email Queue. LOW evidence stays in review. Retention preserves open work
        and owner-managed tables.
      </p>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <div className="ui-panel cr-control-card">
          <div className="cr-section-title">
            <span className="ui-section-icon">
              <ClipboardCheck size={17} />
            </span>
            <div>
              <h3>Low-confidence review</h3>
              <p>Validate applicability before taking action.</p>
            </div>
          </div>
          <div className="max-h-64 overflow-auto space-y-2">
            {state?.reviews.map((review) => (
              <button
                key={review.id}
                disabled={!operator || busy}
                className="cr-work-item"
                aria-pressed={selected === review.id}
                onClick={() => {
                  setSelected(review.id);
                  setAssetId(review.assetId || '');
                  setNote('');
                  setCorrection('');
                }}
              >
                <span className="block">{review.title}</span>
                <span className="block text-xs text-zinc-500">{review.reason}</span>
              </button>
            ))}
            {state?.reviews.length === 0 && (
              <div className="cr-empty cr-empty-compact">
                <ShieldCheck size={23} />
                <h3>Review queue clear</h3>
                <p>New evidence requiring review will appear here.</p>
              </div>
            )}
            {!state && <p className="cr-caption">Loading review queue…</p>}
          </div>
        </div>
        <div className="ui-panel cr-control-card">
          <div className="cr-section-title">
            <span className="ui-section-icon">
              <Inbox size={17} />
            </span>
            <div>
              <h3>Encrypted dead letters</h3>
              <p>Investigate records that could not be processed.</p>
            </div>
          </div>
          <div className="max-h-64 overflow-auto space-y-2">
            {state?.deadLetters.map((letter) => (
              <button
                key={letter.id}
                disabled={!admin || busy}
                className="cr-work-item"
                aria-pressed={selected === letter.id}
                onClick={() => {
                  setSelected(letter.id);
                  setNote('');
                  setCorrection('');
                }}
              >
                <span className="block font-mono text-xs">{letter.id}</span>
                <span className="text-xs text-zinc-500">
                  {letter.errorCode} · {fmtDateTime(letter.createdAt, settings.timezone)}
                </span>
              </button>
            ))}
            {state?.deadLetters.length === 0 && (
              <div className="cr-empty cr-empty-compact">
                <Inbox size={23} />
                <h3>No unresolved dead letters</h3>
                <p>Failed records will appear here for replay or dismissal.</p>
              </div>
            )}
            {!state && <p className="cr-caption">Loading dead letters…</p>}
          </div>
        </div>
      </div>
      {selected && (
        <div
          ref={decisionRef}
          tabIndex={-1}
          role="region"
          aria-label="Record decision"
          className="ui-panel cr-control-card space-y-3"
        >
          <div className="cr-selection-header">
            <div>
              <h3>Record decision</h3>
              <p className="cr-caption font-mono break-all">{selected}</p>
            </div>
            <button type="button" className="ui-secondary" onClick={() => setSelected('')}>
              Close decision
            </button>
          </div>
          {state?.reviews
            .filter((review) => review.id === selected)
            .map((review) => (
              <details key={review.id} className="text-sm">
                <summary>Article context and source</summary>
                <p className="text-xs text-zinc-500 break-all mt-2">{review.url}</p>
                <p className="whitespace-pre-wrap mt-2">{review.content}</p>
              </details>
            ))}
          <label className="block text-sm">
            Decision note
            <input
              className={field + ' block w-full mt-1'}
              value={note}
              maxLength={1000}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Explain the decision (at least 5 characters)"
            />
          </label>
          {state?.reviews.some((review) => review.id === selected) ? (
            <>
              <label className="block text-sm">
                Target asset UUID
                <input
                  className={field + ' block w-full mt-1'}
                  value={assetId}
                  onChange={(event) => setAssetId(event.target.value)}
                  placeholder="Select a target using inventory search below"
                />
              </label>
              <button
                className={button}
                disabled={busy || note.trim().length < 5 || !assetId || isConfirming}
                onClick={() => setConfirmApproveReview({ id: selected, assetId, note })}
              >
                Approve applicability
              </button>{' '}
              <button
                className={button}
                disabled={busy || note.trim().length < 5 || isConfirming}
                onClick={() => setConfirmDismissReview({ id: selected, note })}
              >
                Dismiss review
              </button>
            </>
          ) : (
            <>
              <label className="block text-sm">
                Corrected advisory JSON (optional)
                <textarea
                  id="correlation-correction"
                  className={field + ' block w-full mt-1 min-h-24 font-mono'}
                  maxLength={262144}
                  value={correction}
                  onChange={(event) => setCorrection(event.target.value)}
                  placeholder="Leave empty to validate and replay the encrypted original"
                />
              </label>
              <button
                className={button}
                disabled={busy || note.trim().length < 5 || isConfirming}
                onClick={() => setConfirmReplayDeadLetter({ id: selected, note, correction })}
              >
                Validate and replay
              </button>{' '}
              <button
                className={button}
                disabled={busy || note.trim().length < 5 || isConfirming}
                onClick={() => setConfirmDismissDeadLetter({ id: selected, note })}
              >
                Dismiss dead letter
              </button>
            </>
          )}
        </div>
      )}
      <div className="ui-panel cr-control-card">
        <div className="cr-section-title">
          <span className="ui-section-icon">
            <Database size={17} />
          </span>
          <div>
            <h3>Connected inventory</h3>
            <p>Find a native or monitored asset to associate with a review.</p>
          </div>
        </div>
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            void searchAssets();
          }}
        >
          <input
            aria-label="Search connected inventory"
            className={field}
            maxLength={200}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Vendor or product"
          />
          <button className={button} disabled={busy}>
            <Search size={14} />
            {busy ? 'Searching…' : 'Search inventory'}
          </button>
          {assetCursor && (
            <button
              type="button"
              className={button}
              disabled={busy}
              onClick={() => void searchAssets(assetCursor)}
            >
              Next page
            </button>
          )}
        </form>
        <div className="max-h-52 overflow-auto mt-3">
          {assets.map((asset) => (
            <button
              key={asset.id}
              className="cr-work-item"
              aria-pressed={assetId === asset.id}
              disabled={!operator}
              onClick={() => setAssetId(asset.id)}
            >
              <span className="font-medium">
                {asset.assetTag && `${asset.assetTag} · `}
                {asset.vendor} / {asset.product} {asset.version || 'version unspecified'}
              </span>
              <span className="block text-zinc-500 font-mono">
                {asset.id} · {asset.recordId ? 'Monitored Products' : 'Native inventory'}
              </span>
            </button>
          ))}
          {assets.length === 0 && (
            <p className="cr-caption">
              {hasSearched
                ? 'No inventory matches. Try another vendor or product.'
                : 'Search inventory to find a target asset.'}
            </p>
          )}
        </div>
      </div>
      {notice && (
        <div
          role={noticeError ? 'alert' : 'status'}
          className={`cr-notice ${noticeError ? 'cr-notice-warning' : ''}`}
        >
          <p>{notice}</p>
        </div>
      )}
      {confirmSavePolicy && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmSavePolicy(null);
          }}
        >
          <section
            ref={confirmationDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-save-policy-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-save-policy-title" className="text-sm font-semibold text-zinc-100">
              Save delivery &amp; retention policy?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              Confirm to send PATCH /api/correlation/policy.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className={button} onClick={() => setConfirmSavePolicy(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="ui-primary"
                disabled={busy}
                onClick={() => void executeSavePolicy()}
              >
                Confirm
              </button>
            </div>
          </section>
        </div>
      )}
      {confirmRetentionRun && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmRetentionRun(null);
          }}
        >
          <section
            ref={confirmationDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-retention-run-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-retention-run-title" className="text-sm font-semibold text-zinc-100">
              Run retention batch?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              Confirm to send POST /api/correlation/retention/run.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className={button} onClick={() => setConfirmRetentionRun(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="ui-primary"
                disabled={busy}
                onClick={() => void executeRetentionRun()}
              >
                Confirm
              </button>
            </div>
          </section>
        </div>
      )}
      {confirmArmGate && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmArmGate(null);
          }}
        >
          <section
            ref={confirmationDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-arm-gate-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-arm-gate-title" className="text-sm font-semibold text-zinc-100">
              {confirmArmGate.action === 'arm' ? 'Arm fault simulation gate?' : 'Disarm fault simulation gate?'}
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              Confirm to send POST /api/correlation/fault/arming.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className={button} onClick={() => setConfirmArmGate(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="ui-primary"
                disabled={busy}
                onClick={() => void executeArmGate()}
              >
                Confirm
              </button>
            </div>
          </section>
        </div>
      )}
      {confirmApproveReview && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmApproveReview(null);
          }}
        >
          <section
            ref={confirmationDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-approve-review-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-approve-review-title" className="text-sm font-semibold text-zinc-100">
              Approve applicability?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              Confirm to send POST /api/correlation/reviews/{'{'}id{'}'}/decision with APPROVED.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className={button} onClick={() => setConfirmApproveReview(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="ui-primary"
                disabled={busy}
                onClick={() => void executeApproveReview()}
              >
                Confirm
              </button>
            </div>
          </section>
        </div>
      )}
      {confirmDismissReview && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmDismissReview(null);
          }}
        >
          <section
            ref={confirmationDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-dismiss-review-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-dismiss-review-title" className="text-sm font-semibold text-zinc-100">
              Dismiss review?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              Confirm to send POST /api/correlation/reviews/{'{'}id{'}'}/decision with DISMISSED.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className={button} onClick={() => setConfirmDismissReview(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="ui-primary"
                disabled={busy}
                onClick={() => void executeDismissReview()}
              >
                Confirm
              </button>
            </div>
          </section>
        </div>
      )}
      {confirmReplayDeadLetter && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmReplayDeadLetter(null);
          }}
        >
          <section
            ref={confirmationDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-replay-dead-letter-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-replay-dead-letter-title" className="text-sm font-semibold text-zinc-100">
              Validate and replay dead letter?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              Confirm to send POST /api/correlation/dead-letters/{'{'}id{'}'}/decision with REPLAYED.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className={button} onClick={() => setConfirmReplayDeadLetter(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="ui-primary"
                disabled={busy}
                onClick={() => void executeReplayDeadLetter()}
              >
                Confirm
              </button>
            </div>
          </section>
        </div>
      )}
      {confirmDismissDeadLetter && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmDismissDeadLetter(null);
          }}
        >
          <section
            ref={confirmationDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-dismiss-dead-letter-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-dismiss-dead-letter-title" className="text-sm font-semibold text-zinc-100">
              Dismiss dead letter?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              Confirm to send POST /api/correlation/dead-letters/{'{'}id{'}'}/decision with DISMISSED.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className={button} onClick={() => setConfirmDismissDeadLetter(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="ui-primary"
                disabled={busy}
                onClick={() => void executeDismissDeadLetter()}
              >
                Confirm
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
