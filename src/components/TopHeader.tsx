import { pages, type PageId } from '../design/pages';
import { formatDateTime } from '../utils/dateTime';
import { DEFAULT_INGESTION_WINDOW_HOURS, formatScopeLabel } from '../utils/scopePresets';
import React, { useEffect, useRef, useState } from 'react';
import { useApp } from '../context/AppContext';
import { RotateCw, Play, Clock, Cpu, Sun, Moon, Menu, KeyRound } from 'lucide-react';
import { useDialogFocus } from '../hooks/useDialogFocus';

export const TopHeader: React.FC = () => {
  const {
    activeTab,
    isPipelineRunning,
    currentPipelinePhase,
    triggerPipelineRun,
    feeds,
    session,
    theme,
    toggleTheme,
    settings,
    mobileNavOpen,
    setMobileNavOpen,
    sessionTimeRemainingSec,
    resetSessionTimeout,
    systemUptime,
    health,
  } = useApp();
  const scopeHours = settings.scopeHours ?? DEFAULT_INGESTION_WINDOW_HOURS;
  const scopeLabel = formatScopeLabel(scopeHours);

  const [nextScheduledRun, setNextScheduledRun] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const result = await health();
        if (active) setNextScheduledRun(result?.nextScheduledRun ?? null);
      } catch {
        // ignore
      }
    };
    void load();
    const timer = setInterval(load, 30000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const [confirmingAction, setConfirmingAction] = useState<{ type: 'pipeline' | 'session'; label: string } | null>(null);
  const [confirmActionBusy, setConfirmActionBusy] = useState(false);
  const confirmActionInProgress = useRef(false);
  const confirmationDialogRef = useDialogFocus(() => {
    if (!confirmActionInProgress.current) setConfirmingAction(null);
  }, !!confirmingAction);

  const handleRunPipeline = () => {
    setConfirmingAction({ type: 'pipeline', label: `Run Pipeline (${scopeLabel})` });
  };

  const executeRunPipeline = async () => {
    if (confirmActionInProgress.current) return;
    confirmActionInProgress.current = true;
    setConfirmActionBusy(true);
    try {
      await triggerPipelineRun(scopeHours);
    } finally {
      confirmActionInProgress.current = false;
      setConfirmActionBusy(false);
      setConfirmingAction(null);
    }
  };

  const handleSessionRenewal = () => {
    setConfirmingAction({ type: 'session', label: 'Session Renewal' });
  };

  const executeSessionRenewal = async () => {
    if (confirmActionInProgress.current) return;
    confirmActionInProgress.current = true;
    setConfirmActionBusy(true);
    try {
      await resetSessionTimeout();
    } finally {
      confirmActionInProgress.current = false;
      setConfirmActionBusy(false);
      setConfirmingAction(null);
    }
  };

  const meta = pages[activeTab as PageId] || { section: 'OPERATIONS', title: 'Vulnerability Intelligence' };

  const sessionMins = Math.floor(sessionTimeRemainingSec / 60);
  const sessionSecs = sessionTimeRemainingSec % 60;
  const sessionWarning = sessionTimeRemainingSec <= 120 && sessionTimeRemainingSec > 0;
  const schedulerText = settings.schedulerEnabled
    ? `Scheduler enabled • next ${nextScheduledRun ? formatDateTime(nextScheduledRun, settings.timezone) : 'every ' + settings.schedulerIntervalMinutes + ' min'}`
    : 'Scheduler disabled';

  return (
    <>
      <header className="ui-topbar border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-white/80 backdrop-blur-md sticky top-0 z-20 transition-colors duration-200">
        <div className="px-3 sm:px-6 py-2.5 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <button
              type="button"
              onClick={() => setMobileNavOpen(!mobileNavOpen)}
              className="md:hidden shrink-0 p-2 rounded-lg text-zinc-300 dark:text-zinc-300 light:text-zinc-700 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-zinc-400"
              aria-label={mobileNavOpen ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={mobileNavOpen}
              aria-controls="primary-navigation"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="min-w-0">
              <div
                className="text-sm sm:text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 tracking-tight truncate"
                aria-hidden="true"
              >
                {meta.title}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            <div className="hidden min-[1360px]:flex items-center space-x-2 text-xs">
              <div className="flex items-center space-x-1.5 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-2.5 py-1 rounded-full text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                <span className={`w-1.5 h-1.5 rounded-full ${feeds.some((feed) => feed.enabled) ? 'bg-emerald-500' : 'bg-zinc-500'}`} />
                <span className="text-[11px] font-mono">
                  {feeds.length}/{feeds.filter((f) => f.enabled).length} Feeds Enabled
                </span>
              </div>

              <div className="flex items-center space-x-1.5 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-2.5 py-1 rounded-full text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                <Cpu className="w-3 h-3" />
                <span className="text-[11px]">{schedulerText}</span>
              </div>

              <div className="flex items-center space-x-1.5 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-2.5 py-1 rounded-full text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                <Clock className="w-3 h-3" />
                <span className="font-mono text-[11px]">{session?.role}</span>
              </div>

              <div className="flex items-center space-x-1.5 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-2.5 py-1 rounded-full text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                <div className={`w-3 h-3 rounded-full ${systemUptime.uptime === 'unknown' ? 'bg-zinc-500' : 'bg-emerald-500'}`} />
                <span className="font-mono text-[11px]" title="Current API process uptime; resets when the API restarts">
                  {systemUptime.uptime === 'unknown' ? 'Uptime unavailable' : `Online for ${systemUptime.uptime}`}
                </span>
              </div>
            </div>

            <button
              onClick={toggleTheme}
              className="ui-theme-toggle p-1.5 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/80 dark:bg-zinc-900/80 light:bg-zinc-100 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 hover:text-zinc-100 dark:hover:text-zinc-100 light:hover:text-zinc-900 transition"
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              aria-pressed={theme === 'light'}
            >
              {theme === 'dark' ? (
                <Sun className="w-4 h-4 text-amber-400" />
              ) : (
                <Moon className="w-4 h-4 text-zinc-600" />
              )}
            </button>

            <button
              onClick={handleRunPipeline}
              disabled={isPipelineRunning || confirmingAction !== null}
              aria-label={`Run pipeline for the past ${scopeLabel}`}
              title={`Ingestion window: ${scopeLabel}`}
              className={`ui-pipeline-action inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold transition shadow-sm border border-zinc-700/80 dark:border-zinc-700/80 light:border-zinc-300 ${
                isPipelineRunning || confirmingAction?.type === 'pipeline'
                  ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-400 cursor-not-allowed'
                  : 'bg-zinc-100 dark:bg-zinc-100 light:bg-zinc-900 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 hover:bg-zinc-200 dark:hover:bg-zinc-200 light:hover:bg-zinc-800'
              }`}
            >
              {isPipelineRunning || confirmingAction?.type === 'pipeline' ? (
                <>
                  <RotateCw className="w-3 h-3 animate-spin text-zinc-400" />
                  <span>Pipeline pending...</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 fill-current" />
                  <span className="hidden sm:inline">Run Pipeline ({scopeLabel})</span>
                  <span className="sm:hidden">Run</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleSessionRenewal}
              disabled={confirmingAction !== null}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-[11px] font-mono focus-visible:outline focus-visible:outline-2 focus-visible:outline-zinc-400 transition ${
                sessionWarning
                  ? 'text-amber-300 bg-amber-900/40 hover:text-amber-200 border border-amber-700/60'
                  : 'text-zinc-500 bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-zinc-100 hover:text-zinc-300'
              }`}
              title="Renew session"
              aria-label={`Renew session, ${sessionMins} minutes and ${sessionSecs} seconds remaining${sessionWarning ? '. Session expiring soon' : ''}`}
            >
              <KeyRound className={`w-3 h-3 ${sessionWarning ? 'text-amber-400' : 'text-zinc-500'}`} />
              <span className="hidden sm:inline">
                Session: {String(sessionMins).padStart(2, '0')}:{String(sessionSecs).padStart(2, '0')}
              </span>
            </button>
          </div>
        </div>

        {isPipelineRunning && (
          <div className="px-6 py-2 border-t border-zinc-800/60 dark:border-zinc-800/60 light:border-zinc-200 flex items-center justify-between text-xs bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
            <div className="flex items-center space-x-2">
              <RotateCw className="w-3.5 h-3.5 animate-spin text-zinc-400" />
              <span className="font-mono font-medium">{currentPipelinePhase}</span>
            </div>
            <span className="text-[11px] text-zinc-500 font-mono">Server-managed execution</span>
          </div>
        )}
      </header>

      {confirmingAction && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !confirmActionBusy) setConfirmingAction(null);
          }}
        >
          <section
            ref={confirmationDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-action-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-action-title" className="text-sm font-semibold">
              {confirmingAction.label}?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              {confirmingAction.type === 'pipeline'
                ? 'This will start a new ingestion pipeline run. It may overlap with scheduled runs.'
                : 'This will reset your server-side session timeout.'}
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                className="ui-secondary"
                disabled={confirmActionBusy}
                onClick={() => setConfirmingAction(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500"
                disabled={confirmActionBusy}
                onClick={() => {
                  if (confirmingAction.type === 'pipeline') {
                    void executeRunPipeline();
                  } else {
                    void executeSessionRenewal();
                  }
                }}
              >
                Confirm
              </button>
            </div>
          </section>
        </div>
      )}
    </>
  );
};
