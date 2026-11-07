import { PageHeading } from './PageHeading';
import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  HardDrive,
  Info,
  LockKeyhole,
  Newspaper,
  Play,
  RefreshCw,
  RotateCcw,
  Settings2,
  Save,
  LoaderCircle,
  ListFilter,
  ShieldAlert,
  ShieldCheck,
  Webhook,
  X,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { AuditLog, RetentionConfig, RetentionKind, RetentionPreview } from '../types';
import './archive.css';
import { formatDateTime as fmtDateTime } from '../utils/dateTime';

const FALLBACK: RetentionConfig = {
  enabled: false,
  retentionHours: 24,
  cleanupIntervalMinutes: 60,
  maxArchivedRecords: 10000,
  autoCleanup: true,
  retentionMode: 'rolling',
};

const MODES = [
  {
    id: 'strict',
    label: 'Strict',
    description: 'Delete every record whose timestamp is older than the window.',
  },
  {
    id: 'rolling',
    label: 'Rolling',
    description: 'Delete expired records, then trim the oldest until the archive ceiling is met.',
  },
  {
    id: 'checkpoints',
    label: 'Checkpoints',
    description: 'Delete expired records but keep the newest record from each UTC day.',
  },
] as const;

const panel = 'ar-panel';
const muted = 'text-zinc-400 light:text-zinc-600';
const badge = 'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium';

const stamp = (value: string | null | undefined) => (value ? fmtDateTime(value) : '—');

const hours = (value: number) => {
  if (value >= 24 && value % 24 === 0) {
    const days = value / 24;
    return `${days} day${days === 1 ? '' : 's'}`;
  }
  return `${value} hour${value === 1 ? '' : 's'}`;
};

const toConfig = (value?: Partial<RetentionConfig> | null): RetentionConfig => ({
  enabled: value?.enabled ?? FALLBACK.enabled,
  retentionHours: value?.retentionHours ?? FALLBACK.retentionHours,
  cleanupIntervalMinutes: value?.cleanupIntervalMinutes ?? FALLBACK.cleanupIntervalMinutes,
  maxArchivedRecords: value?.maxArchivedRecords ?? FALLBACK.maxArchivedRecords,
  autoCleanup: value?.autoCleanup ?? FALLBACK.autoCleanup,
  retentionMode: value?.retentionMode ?? FALLBACK.retentionMode,
});

function SectionHeading({
  icon: Icon,
  title,
  description,
  id,
}: {
  icon: typeof Settings2;
  title: string;
  description: string;
  id?: string;
}) {
  return (
    <div className="ar-section-heading flex items-start gap-3.5">
      <span className="ui-section-icon">
        <Icon className="h-4 w-4" aria-hidden="true" />
      </span>
      <div>
        <h2 id={id} className="ui-card-title">
          {title}
        </h2>
        <p className="ui-description mt-1">{description}</p>
      </div>
    </div>
  );
}

interface FootprintRow {
  label: string;
  tab: string;
  icon: typeof Database;
  total: number;
  /** Present only for kinds the retention policy may delete. */
  past?: number;
  eligible?: boolean;
}

function RecordRow({ row, onOpen }: { row: FootprintRow; onOpen: (tab: string) => void }) {
  return (
    <li>
      <button
        type="button"
        onClick={() => onOpen(row.tab)}
        className="ar-record-row group flex w-full items-center gap-3 py-2.5 text-left text-xs transition"
      >
        <row.icon className={`h-3.5 w-3.5 shrink-0 ${muted}`} aria-hidden="true" />
        <span className="flex-1 font-medium text-zinc-300 light:text-zinc-700">{row.label}</span>
        {!row.eligible ? (
          <LockKeyhole className="h-3 w-3 shrink-0 text-zinc-600" aria-label="Never removed by retention" />
        ) : (
          (row.past ?? 0) > 0 && (
            <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium tabular-nums text-amber-400 light:text-amber-700">
              {row.past?.toLocaleString()} past
            </span>
          )
        )}
        <span className="tabular-nums text-zinc-200 light:text-zinc-800">{(row.total ?? 0).toLocaleString()}</span>
        <ChevronRight
          className={`h-3.5 w-3.5 shrink-0 text-zinc-600 transition group-hover:translate-x-0.5 ${muted}`}
          aria-hidden="true"
        />
      </button>
    </li>
  );
}

export const ArchiveRetentionView: React.FC = () => {
  const {
    settings,
    updateSettings,
    session,
    counts,
    setActiveTab,
    runRetentionCleanup,
    previewRetention,
    fetchCollection,
    refreshVersion,
  } = useApp();
  const admin = session?.role === 'ADMIN';
  const [view, setView] = useState('policy');

  const saved = useMemo(() => toConfig(settings?.retentionConfig), [settings?.retentionConfig]);
  const [form, setForm] = useState<RetentionConfig>(saved);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const [running, setRunning] = useState(false);
  const [confirmCleanup, setConfirmCleanup] = useState<{ action: string; label: string } | null>(null);
  const [confirmSavePolicy, setConfirmSavePolicy] = useState<{ action: string; label: string } | null>(null);
  const [runNotice, setRunNotice] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  // Exact footprint counts come from the server. The snapshot only carries
  // capped recent slices, so computing totals from it would under-report.
  const [preview, setPreview] = useState<RetentionPreview | null>(null);
  const [previewVersion, setPreviewVersion] = useState(0);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState('');
  const dirty = JSON.stringify(form) !== JSON.stringify(saved);

  useEffect(() => {
    if (!dirty) setForm(saved);
    // Only re-sync when the persisted policy changes; an in-progress edit must survive it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(saved)]);

  // A policy edit or disabling the policy invalidates an armed manual cleanup.
  useEffect(() => {
    if (dirty || !form.enabled) setConfirmCleanup(null);
  }, [dirty, form.enabled]);
  useEffect(() => {
    setConfirmCleanup(null);
  }, [view]);

  // Refresh the server-side footprint as the operator edits the policy. The
  // context callback is intentionally omitted from the dependency list: the
  // provider recreates it on every clock tick, which would otherwise refetch
  // this preview once per second.
  useEffect(() => {
    if (!admin) return;
    let active = true;
    setPreviewLoading(true);
    setPreviewError('');
    const timer = setTimeout(() => {
      void previewRetention({
        enabled: form.enabled,
        retentionHours: form.retentionHours,
        maxArchivedRecords: form.maxArchivedRecords,
        retentionMode: form.retentionMode,
      }).then((value) => {
        if (!active) return;
        if (value) setPreview(value);
        else setPreviewError('The footprint preview could not be loaded. Try refreshing it.');
        setPreviewLoading(false);
      });
    }, 200);
    return () => {
      active = false;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [admin, form.enabled, form.retentionHours, form.maxArchivedRecords, form.retentionMode, previewVersion]);

  const patch = (update: Partial<RetentionConfig>) => {
    setForm((current) => ({ ...current, ...update }));
    setNotice(null);
  };

  const numberChange =
    (key: 'retentionHours' | 'cleanupIntervalMinutes' | 'maxArchivedRecords', min: number, max: number) =>
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const value = Number(event.target.value);
      patch({ [key]: Number.isFinite(value) ? Math.min(max, Math.max(min, Math.trunc(value))) : min });
    };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!admin || saving || !dirty) return;
    setConfirmSavePolicy({ action: 'save', label: 'Retention policy' });
  };

  const executeSavePolicy = async () => {
    if (!confirmSavePolicy) return;
    setSaving(true);
    setNotice(null);
    try {
      const ok = await updateSettings({ retentionConfig: form });
      setNotice(
        ok
          ? { tone: 'success', text: 'Retention policy saved.' }
          : { tone: 'error', text: 'Retention policy was not saved. See the error banner for details.' },
      );
    } finally {
      setSaving(false);
      setConfirmSavePolicy(null);
    }
  };

  // The snapshot's audit slice is capped, so look up the latest cleanup through
  // the paginated audit endpoint instead of scanning recent entries only.
  const [lastCleanup, setLastCleanup] = useState<AuditLog | null>(null);
  useEffect(() => {
    if (!admin) return;
    let active = true;
    void fetchCollection<AuditLog>('auditLogs', {
      page: 1,
      pageSize: 20,
      search: 'Retention cleanup',
    })
      .then((page) => {
        if (active) setLastCleanup(page.items.find((entry) => entry.event === 'Retention cleanup') ?? null);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [admin, refreshVersion]);

  const cutoff = preview?.cutoff ?? new Date(Date.now() - form.retentionHours * 3_600_000).toISOString();
  const footprint = (kind: RetentionKind): { total: number; past?: number } => {
    const record = preview?.records?.[kind];
    if (record && typeof record.total === 'number') {
      return { total: record.total, past: record.past };
    }
    if (kind === 'events') {
      return { total: 0, past: undefined };
    }
    return { total: (counts as Record<string, number>)?.[kind] ?? 0, past: undefined };
  };

  // Only these kinds are eligible for deletion; each timestamp matches the
  // field the corresponding table shows to operators.
  const removable: FootprintRow[] = [
    {
      label: 'Threat cache',
      tab: 'threat-data',
      icon: Database,
      total: footprint('cveData').total,
      eligible: true,
      past: footprint('cveData').past,
    },
    {
      label: 'News cache',
      tab: 'threat-data',
      icon: Newspaper,
      total: footprint('intelligenceArticles').total,
      eligible: true,
      past: footprint('intelligenceArticles').past,
    },
    {
      label: 'Delivery log',
      tab: 'emails',
      icon: Clock3,
      total: footprint('emailLogs').total,
      eligible: true,
      past: footprint('emailLogs').past,
    },
    {
      label: 'Webhook log',
      tab: 'recipients',
      icon: Webhook,
      total: footprint('webhookLogs').total,
      eligible: true,
      past: footprint('webhookLogs').past,
    },
    {
      label: 'Executions',
      tab: 'pipeline',
      icon: Settings2,
      total: footprint('executions').total,
      eligible: true,
      past: footprint('executions').past,
    },
    {
      label: 'News evidence matches',
      tab: 'news',
      icon: Newspaper,
      total: footprint('intelligenceMatches').total,
      eligible: true,
      past: footprint('intelligenceMatches').past,
    },
    {
      label: 'Zero-day digests',
      tab: 'news',
      icon: ShieldAlert,
      total: footprint('zeroDayDigests').total,
      eligible: true,
      past: footprint('zeroDayDigests').past,
    },
    {
      label: 'System & operational logs',
      tab: 'logs',
      icon: Clock3,
      total: footprint('events').total,
      eligible: true,
      past: footprint('events').past,
    },
  ];
  const retained: FootprintRow[] = [
    {
      label: 'Findings',
      tab: 'findings',
      icon: ShieldCheck,
      total: preview?.protected.findings ?? counts?.findings ?? 0,
    },
    {
      label: 'Advisories',
      tab: 'advisories',
      icon: Archive,
      total: preview?.protected.advisories ?? counts?.advisories ?? 0,
    },
    {
      label: 'Audit history',
      tab: 'logs',
      icon: HardDrive,
      total: (counts as Record<string, number>)?.auditLogs ?? 0,
    },
  ];
  const totalRecords = [...removable, ...retained].reduce((sum, row) => sum + (row.total ?? 0), 0);
  const removableRecords = removable.reduce((sum, row) => sum + (row.total ?? 0), 0);
  const expiredRecords = removable.reduce((sum, row) => sum + (row.past ?? 0), 0);
  const projectedRemoval = preview
    ? Object.values(preview.records).reduce((sum, record) => sum + record.deletable, 0)
    : null;
  const mode = MODES.find((item) => item.id === form.retentionMode) ?? MODES[1];

  const runCleanup = () => {
    if (!admin || running || !form.enabled || dirty || previewLoading || !preview || previewError) return;
    setConfirmCleanup({ action: 'cleanup', label: 'Manual retention cleanup' });
    setRunNotice(null);
  };

  const executeCleanup = async () => {
    if (!confirmCleanup) return;
    setConfirmCleanup(null);
    setRunning(true);
    setRunNotice(null);
    try {
      const result = await runRetentionCleanup();
      setRunNotice(
        result
          ? {
              tone: 'success',
              text: result.deleted
                ? `Removed ${result.deleted.toLocaleString()} record${result.deleted === 1 ? '' : 's'} using ${result.mode} mode.`
                : 'Cleanup completed. Nothing was outside the policy.',
            }
          : { tone: 'error', text: 'Cleanup did not run. See the error banner for the reason.' },
      );
    } finally {
      setRunning(false);
      // Cleanup removed rows; refresh the exact server footprint.
      setPreviewVersion((value) => value + 1);
    }
  };

  return (
    <div className="archive-page space-y-6 text-zinc-100 light:text-zinc-900">
      <header className="ui-page-header">
        <PageHeading page="archive">
          Set how long correlated records stay available and review what currently sits outside that window.
        </PageHeading>
        <span
          className={`${badge} shrink-0 self-start sm:self-auto ${
            saved.enabled
              ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400 light:text-emerald-700'
              : 'border-zinc-500/20 bg-zinc-500/10 text-zinc-400 light:text-zinc-600'
          }`}
        >
          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-current" />
          {saved.enabled ? 'Policy enabled' : 'Policy disabled'}
        </span>
      </header>

      <div className="ar-metrics">
        {[
          {
            label: 'Stored records',
            value: totalRecords.toLocaleString(),
            detail: 'Across tracked collections',
            icon: Database,
          },
          {
            label: 'Managed by policy',
            value: removableRecords.toLocaleString(),
            detail: 'Cache, delivery & execution records',
            icon: Archive,
          },
          {
            label: 'Beyond the window',
            value: preview && !previewLoading && !previewError ? expiredRecords.toLocaleString() : '—',
            detail: previewLoading
              ? 'Updating footprint preview…'
              : previewError
                ? 'Preview unavailable'
                : preview
                  ? 'Before the selected cutoff'
                  : 'Administrator preview required',
            icon: Clock3,
          },
          {
            label: 'Always retained',
            value: retained.reduce((sum, row) => sum + (row.total ?? 0), 0).toLocaleString(),
            detail: 'Findings, advisories & audit history',
            icon: ShieldCheck,
          },
        ].map(({ label, value, detail, icon: Icon }) => (
          <div key={label} className="ar-stat ar-panel">
            <div>
              <span>{label}</span>
              <Icon size={16} aria-hidden="true" />
            </div>
            <strong>{value}</strong>
            <p>{detail}</p>
          </div>
        ))}
      </div>

      <div className="ar-viewbar">
        <div className="ui-segmented ar-view-switch" role="group" aria-label="Archive views">
          {[
            { id: 'policy', label: 'Policy & schedule', icon: Settings2 },
            { id: 'inventory', label: 'Stored records', icon: Database },
            { id: 'cleanup', label: 'Manual cleanup', icon: Archive },
          ].map(({ id, label, icon: Icon }) => (
            <button
              type="button"
              key={id}
              aria-pressed={view === id}
              aria-controls={`archive-${id}`}
              onClick={() => setView(id)}
            >
              <Icon size={14} aria-hidden="true" />
              {label}
            </button>
          ))}
        </div>
        {admin && (
          <button
            type="button"
            className="ar-refresh"
            disabled={previewLoading}
            onClick={() => setPreviewVersion((value) => value + 1)}
          >
            <RefreshCw size={13} className={previewLoading ? 'animate-spin' : ''} />
            {previewLoading ? 'Refreshing…' : 'Refresh preview'}
          </button>
        )}
      </div>
      {previewError && (
        <div className="ar-feedback" role="alert">
          <AlertTriangle size={15} />
          <p>
            {previewError} {preview ? 'Previously received counts remain visible.' : ''}
          </p>
        </div>
      )}

      <div id="archive-policy" hidden={view !== 'policy'}>
        <div className="ar-policy-layout">
          <form className="ui-card space-y-6" aria-labelledby="retention-policy-title" onSubmit={submit}>
            <SectionHeading
              icon={ShieldCheck}
              id="retention-policy-title"
              title="Retention policy"
              description="Choose how long data stays available and how expired records are removed."
            />

            <div className="grid gap-3 sm:grid-cols-2">
              <label className="ar-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  disabled={!admin}
                  onChange={(event) => patch({ enabled: event.target.checked })}
                />
                <span>
                  <span className="block font-medium text-zinc-200 light:text-zinc-800">
                    Enforce retention
                  </span>
                  <span className="ui-description mt-0.5 block">
                    Treat the window below as the active data-retention policy.
                  </span>
                </span>
              </label>
              <label className="ar-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                <input
                  type="checkbox"
                  checked={form.autoCleanup}
                  disabled={!admin || !form.enabled}
                  onChange={(event) => patch({ autoCleanup: event.target.checked })}
                />
                <span>
                  <span className="block font-medium text-zinc-200 light:text-zinc-800">
                    Automatic cleanup
                  </span>
                  <span className="ui-description mt-0.5 block">
                    Run the policy on a schedule instead of waiting for a manual review.
                  </span>
                </span>
              </label>
            </div>

            <div className="grid gap-x-5 gap-y-4 sm:grid-cols-2">
              <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                Retention window
                <span className="ml-1 font-normal text-zinc-500">(hours)</span>
                <input
                  type="number"
                  min={1}
                  max={8760}
                  required
                  inputMode="numeric"
                  disabled={!admin}
                  className="ui-field"
                  value={form.retentionHours}
                  onChange={numberChange('retentionHours', 1, 8760)}
                />
                <span className="ui-description mt-1.5 block">
                  {hours(form.retentionHours)} — anything older is outside the policy.
                </span>
              </label>
              <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                Archive ceiling
                <span className="ml-1 font-normal text-zinc-500">(records)</span>
                <input
                  type="number"
                  min={1000}
                  max={1000000}
                  required
                  inputMode="numeric"
                  disabled={!admin}
                  className="ui-field"
                  value={form.maxArchivedRecords}
                  onChange={numberChange('maxArchivedRecords', 1000, 1000000)}
                />
                <span className="ui-description mt-1.5 block">
                  Upper bound used by rolling mode before the oldest records are dropped.
                </span>
              </label>
              <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700 sm:col-span-2">
                Cleanup interval
                <span className="ml-1 font-normal text-zinc-500">(minutes)</span>
                <input
                  type="number"
                  min={1}
                  max={1440}
                  required
                  inputMode="numeric"
                  disabled={!admin || !form.enabled || !form.autoCleanup}
                  className="ui-field"
                  value={form.cleanupIntervalMinutes}
                  onChange={numberChange('cleanupIntervalMinutes', 1, 1440)}
                />
                <span className="ui-description mt-1.5 block">
                  {form.enabled && form.autoCleanup
                    ? `A cleanup pass would run every ${form.cleanupIntervalMinutes} minute${
                        form.cleanupIntervalMinutes === 1 ? '' : 's'
                      }.`
                    : 'Enable automatic cleanup to schedule passes.'}
                </span>
              </label>
            </div>

            <fieldset className="space-y-3">
              <legend className="text-xs font-medium text-zinc-300 light:text-zinc-700">
                Retention mode
              </legend>
              <div className="ar-mode-options">
                {MODES.map((item) => {
                  const selected = form.retentionMode === item.id;
                  return (
                    <label
                      key={item.id}
                      className={`ar-mode-card flex cursor-pointer items-start gap-2.5 rounded-xl border p-3 text-xs leading-relaxed transition ${
                        selected
                          ? 'border-blue-500/50 bg-blue-500/5 light:border-blue-400 light:bg-blue-50'
                          : 'border-zinc-800/80 bg-zinc-950/30 hover:border-zinc-700 light:border-zinc-200 light:bg-zinc-50 light:hover:border-zinc-300'
                      }`}
                    >
                      <input
                        type="radio"
                        name="retention-mode"
                        value={item.id}
                        checked={selected}
                        disabled={!admin}
                        onChange={() => patch({ retentionMode: item.id })}
                        className="mt-0.5"
                      />
                      <span>
                        <span className="block font-semibold text-zinc-200 light:text-zinc-800">
                          {item.label}
                        </span>
                        <span className="ui-description mt-0.5 block">{item.description}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </fieldset>

            <div className="ui-actions justify-between">
              <div aria-live="polite" className="min-h-5">
                {notice ? (
                  <p
                    role={notice.tone === 'error' ? 'alert' : undefined}
                    className={`inline-flex items-center gap-2 text-xs font-medium ${
                      notice.tone === 'success'
                        ? 'text-emerald-400 light:text-emerald-700'
                        : 'text-rose-400 light:text-rose-700'
                    }`}
                  >
                    {notice.tone === 'success' ? (
                      <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                    ) : (
                      <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                    )}
                    {notice.text}
                  </p>
                ) : (
                  <span className={`text-xs ${muted}`}>
                    {!admin
                      ? 'Administrator role required to change the retention policy.'
                      : dirty
                        ? 'Unsaved policy changes.'
                        : 'Policy matches the saved workspace settings.'}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2.5">
                <button
                  type="button"
                  className="ui-secondary"
                  disabled={!admin || saving || !dirty || !!confirmSavePolicy || !!confirmCleanup}
                  onClick={() => {
                    setForm(saved);
                    setNotice(null);
                  }}
                >
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                  Reset
                </button>
                <button type="submit" className="ui-primary" disabled={!admin || saving || !dirty || !!confirmSavePolicy || !!confirmCleanup}>
                  {saving ? (
                    <>
                      <LoaderCircle size={14} className="animate-spin" />
                      Saving…
                    </>
                  ) : (
                    <>
                      <Save className="h-3.5 w-3.5" aria-hidden="true" />
                      Save policy
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>

          <div className="space-y-6">
            <section className={`${panel} ar-summary p-5`} aria-labelledby="policy-summary-title">
              <div className="flex items-center justify-between gap-3">
                <h2 id="policy-summary-title" className="ui-card-title">
                  {dirty ? 'Draft policy preview' : 'Policy summary'}
                </h2>
                <Info className="h-4 w-4 text-zinc-500" aria-hidden="true" />
              </div>
              <dl className="mt-4 space-y-3 text-xs">
                <div className="flex items-baseline justify-between gap-3">
                  <dt className={muted}>Window</dt>
                  <dd className="font-medium tabular-nums">{hours(form.retentionHours)}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <dt className={muted}>Cutoff</dt>
                  <dd className="text-right font-medium tabular-nums">
                    {previewLoading ? 'Updating…' : stamp(cutoff)}
                  </dd>
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <dt className={muted}>Mode</dt>
                  <dd className="font-medium">{mode.label}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <dt className={muted}>Schedule</dt>
                  <dd className="font-medium">
                    {form.enabled && form.autoCleanup ? `Every ${form.cleanupIntervalMinutes} min` : 'Paused'}
                  </dd>
                </div>
                <div className="flex items-baseline justify-between gap-3 border-t border-zinc-800/70 pt-3 light:border-zinc-200">
                  <dt className={muted}>Eligible records</dt>
                  <dd className="font-medium tabular-nums">{removableRecords.toLocaleString()}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <dt className={muted}>Past window</dt>
                  <dd
                    className={`font-medium tabular-nums ${
                      expiredRecords > 0
                        ? 'text-amber-400 light:text-amber-700'
                        : 'text-emerald-400 light:text-emerald-700'
                    }`}
                  >
                    {preview && !previewLoading && !previewError
                      ? `${expiredRecords.toLocaleString()} record${expiredRecords === 1 ? '' : 's'}`
                      : '—'}
                  </dd>
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <dt className={muted}>Projected removal</dt>
                  <dd className="font-medium tabular-nums">
                    {projectedRemoval !== null && !previewLoading && !previewError
                      ? projectedRemoval.toLocaleString()
                      : '—'}
                  </dd>
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <dt className={muted}>Last removal</dt>
                  <dd className="text-right font-medium tabular-nums">{stamp(lastCleanup?.timestamp)}</dd>
                </div>
              </dl>
            </section>
          </div>
        </div>
      </div>
      <div id="archive-inventory" hidden={view !== 'inventory'}>
        <div className="ar-inventory-grid">
          <section className="ui-card" aria-labelledby="managed-records-title">
            <SectionHeading
              icon={Database}
              id="managed-records-title"
              title="Managed collections"
              description="These records are eligible for removal under the saved retention policy."
            />
            <div className="ar-record-labels">
              <span>Collection</span>
              <span>Records</span>
            </div>
            <ul>
              {removable.map((row) => (
                <RecordRow key={row.label} row={row} onOpen={setActiveTab} />
              ))}
            </ul>
            <p className="ar-caption">
              Past-window counts come from the footprint preview. The selected mode determines which records
              are removed.
            </p>
          </section>
          <section className="ui-card" aria-labelledby="protected-records-title">
            <SectionHeading
              icon={LockKeyhole}
              id="protected-records-title"
              title="Protected records"
              description="These collections are preserved by this retention policy."
            />
            <div className="ar-record-labels">
              <span>Collection</span>
              <span>Records</span>
            </div>
            <ul>
              {retained.map((row) => (
                <RecordRow key={row.label} row={row} onOpen={setActiveTab} />
              ))}
            </ul>
            <div className="ar-protected-note">
              <ShieldCheck size={16} />
              <p>
                Feed checkpoints, source snapshots, monitored products, recipients, and settings are also
                preserved.
              </p>
            </div>
          </section>
        </div>
      </div>
      <div id="archive-cleanup" hidden={view !== 'cleanup'}>
        <div className="ar-cleanup-context">
          <div>
            <Clock3 size={16} />
            <span>
              Saved window<strong>{hours(saved.retentionHours)}</strong>
            </span>
          </div>
          <div>
            <ListFilter size={16} />
            <span>
              Saved mode<strong>{MODES.find((item) => item.id === saved.retentionMode)?.label}</strong>
            </span>
          </div>
          <div>
            <RefreshCw size={16} />
            <span>
              Last cleanup<strong>{stamp(lastCleanup?.timestamp)}</strong>
            </span>
          </div>
        </div>
        <section className={`${panel} ar-maintenance p-5`} aria-labelledby="maintenance-title">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex items-start gap-3.5">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 light:text-emerald-700">
                <ShieldCheck className="h-4 w-4" aria-hidden="true" />
              </span>
              <div className="min-w-0">
                <h2 id="maintenance-title" className="ui-card-title">
                  Manual cleanup
                </h2>
                <p className={`mt-1 max-w-2xl text-xs leading-relaxed ${muted}`}>
                  Run one cleanup pass using the saved policy. Review its projected removal count before
                  confirming. Save any pending policy edits before starting a pass.
                </p>
              </div>
            </div>
            <div className="flex shrink-0 flex-col items-stretch gap-2 sm:items-end">
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="ui-primary"
                  disabled={
                    !admin ||
                    running ||
                    !form.enabled ||
                    dirty ||
                    previewLoading ||
                    !preview ||
                    !!previewError ||
                    !!confirmSavePolicy ||
                    !!confirmCleanup
                  }
                  onClick={runCleanup}
                >
                  {running ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  ) : (
                    <Play className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  {running ? 'Running…' : 'Run cleanup now'}
                </button>
              </div>
              <span aria-live="polite" className={`text-right text-[11px] ${muted}`}>
                {!admin
                  ? 'Administrator role required.'
                  : !form.enabled
                    ? 'Enable the policy to run cleanup.'
                    : dirty
                      ? 'Save the policy before running cleanup.'
                      : previewLoading
                        ? 'Updating the footprint preview…'
                        : !preview || previewError
                          ? 'Load a current footprint preview before cleanup.'
                          : confirmCleanup
                            ? `This pass would remove ${projectedRemoval?.toLocaleString() ?? '—'} record${projectedRemoval === 1 ? '' : 's'} using ${mode.label.toLowerCase()} mode. Confirm to proceed.`
                            : 'Applies the saved policy immediately.'}
              </span>
            </div>
          </div>

          {runNotice && (
            <p
              role={runNotice.tone === 'error' ? 'alert' : 'status'}
              className={`mt-4 inline-flex items-center gap-2 text-xs font-medium ${
                runNotice.tone === 'success'
                  ? 'text-emerald-400 light:text-emerald-700'
                  : 'text-rose-400 light:text-rose-700'
              }`}
            >
              {runNotice.tone === 'success' ? (
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
              ) : (
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
              )}
              {runNotice.text}
            </p>
          )}

          <div
            className={`mt-5 grid gap-5 border-t border-zinc-800/70 pt-4 text-xs light:border-zinc-200 sm:grid-cols-2`}
          >
            <div>
              <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                Collections managed by policy
              </h3>
              <ul className={`mt-2 space-y-1.5 ${muted}`}>
                <li>Threat cache</li>
                <li>News cache</li>
                <li>Delivery log</li>
                <li>Webhook log</li>
                <li>Pipeline executions</li>
                <li>News evidence matches</li>
                <li>Zero-day digests</li>
                <li>System & operational logs</li>
              </ul>
            </div>
            <div>
              <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                Never removed by this policy
              </h3>
              <ul className={`mt-2 space-y-1.5 ${muted}`}>
                <li>Findings and advisories</li>
                <li>Audit history</li>
                <li>Feed checkpoints and source snapshots</li>
                <li>Monitored products, recipients and settings</li>
              </ul>
            </div>
          </div>

            <p className={`mt-4 text-[11px] leading-relaxed ${muted}`}>
              The separate housekeeping loop still expires sessions, clears old login attempts and prunes settled
              outbox jobs after 30 days. That housekeeping is fixed and independent of this policy.
            </p>
        </section>
      </div>

      {/* Save Policy Confirmation Modal */}
      {confirmSavePolicy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4" onMouseDown={(event) => {
          if (event.target === event.currentTarget) setConfirmSavePolicy(null);
        }}>
          <section role="dialog" aria-modal="true" aria-labelledby="confirm-save-policy-title" className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5">
            <h2 id="confirm-save-policy-title" className="text-sm font-semibold text-zinc-100">Save retention policy?</h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This will <span className="font-medium text-zinc-200 light:text-zinc-800">{confirmSavePolicy.label}</span> changes to the workspace retention settings.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className="ui-secondary" onClick={() => setConfirmSavePolicy(null)}>
                Cancel
              </button>
              <button type="button" className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500" onClick={() => void executeSavePolicy()}>
                Confirm save
              </button>
            </div>
          </section>
        </div>
      )}

      {/* Cleanup Confirmation Modal */}
      {confirmCleanup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4" onMouseDown={(event) => {
          if (event.target === event.currentTarget) setConfirmCleanup(null);
        }}>
          <section role="dialog" aria-modal="true" aria-labelledby="confirm-cleanup-title" className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5">
            <h2 id="confirm-cleanup-title" className="text-sm font-semibold text-zinc-100">Run retention cleanup?</h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This will <span className="font-medium text-zinc-200 light:text-zinc-800">{confirmCleanup.label}</span> using the saved policy. Expired records will be permanently removed.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className="ui-secondary" onClick={() => setConfirmCleanup(null)}>
                Cancel
              </button>
              <button type="button" className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-red-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-red-500" onClick={() => void executeCleanup()}>
                Confirm cleanup
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
};
