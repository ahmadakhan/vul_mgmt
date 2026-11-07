import { pages, type PageId } from '../design/pages';
import { DashboardIcon } from '../design/icons';
import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { LogOut } from 'lucide-react';

export const Sidebar: React.FC = () => {
  const [isMobileView, setIsMobileView] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(max-width: 767px)').matches,
  );
  const {
    activeTab,
    setActiveTab,
    mobileNavOpen,
    setMobileNavOpen,
    counts,
    watchlist,
    feeds,
    logout,
  } = useApp();
  const [confirmingLogout, setConfirmingLogout] = useState(false);

  const handleLogout = async () => {
    setConfirmingLogout(true);
  };

  const executeLogout = async () => {
    setConfirmingLogout(false);
    await logout();
  };

  useEffect(() => {
    const media = window.matchMedia('(max-width: 767px)');
    const update = () => setIsMobileView(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMobileNavOpen(false);
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [mobileNavOpen, setMobileNavOpen]);

  const navSections = [
    {
      title: 'Overview',
      items: [{ id: 'dashboard' }],
    },
    {
      title: 'Assets & Findings',
      items: [
        { id: 'watchlist', count: watchlist.length },
        { id: 'findings', count: counts.findings },
      ],
    },
    {
      title: 'Threat Intelligence',
      items: [
        { id: 'threat-data' },
        { id: 'threat-intelligence-search' },
        { id: 'vulnerability-search' },
        { id: 'threat-analytics' },
        { id: 'cpe-matcher' },
        { id: 'advisories' },
        { id: 'feeds', count: feeds.length },
      ],
    },
    {
      title: 'Pipeline',
      items: [
        { id: 'correlation' },
        { id: 'pipeline' },
      ],
    },
    {
      title: 'Email & Notifications',
      items: [
        { id: 'alerted-cves' },
        { id: 'recipients' },
        { id: 'template' },
        { id: 'daily-digest' },
        { id: 'emails' },
        { id: 'email-queue' },
        { id: 'action-center' },
      ],
    },
    {
      title: 'Data Management',
      items: [{ id: 'aliases' }, { id: 'archive' }],
    },
    {
      title: 'System & Audit',
      items: [{ id: 'logs' }, { id: 'health' }, { id: 'settings' }],
    },
  ];

  return (
    <aside
      id="primary-navigation"
      aria-hidden={isMobileView && !mobileNavOpen}
      inert={isMobileView && !mobileNavOpen}
      className={`ui-sidebar fixed inset-y-0 left-0 z-40 w-64 bg-zinc-950 dark:bg-zinc-950 light:bg-white border-r border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 flex flex-col shrink-0 select-none transition-transform duration-200 md:sticky md:top-0 md:h-screen md:translate-x-0 md:z-30 ${mobileNavOpen ? 'translate-x-0' : '-translate-x-full'}`}
    >
      {/* Brand Header */}
      <div className="p-4 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
        <button
          type="button"
          onClick={() => setActiveTab('dashboard')}
          className="flex items-center space-x-3 text-left cursor-pointer group"
          aria-label="BA Threat Intel dashboard"
        >
          <DashboardIcon className="w-5 h-5" />
          <div>
            <div className="flex items-center space-x-1.5">
              <span className="text-sm font-bold tracking-tight text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                BA Threat Intel
              </span>
              <span className="text-[10px] font-semibold bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-1.5 py-0.2 rounded">
                Auto
              </span>
            </div>
            <div className="text-[10px] text-zinc-500 font-mono tracking-tight">Vulnerability Operations</div>
          </div>
        </button>
      </div>

      {/* Nav List with Sections & SVG Icons */}
      <nav
        aria-label="Primary navigation"
        className="ui-navigation flex-1 min-h-0 overflow-y-auto px-3 py-4 space-y-6"
      >
        {navSections.map((section) => (
          <div key={section.title}>
            <div className="px-3 mb-2 text-[10px] font-bold tracking-wider text-zinc-500 font-mono uppercase">
              {section.title}
            </div>
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = pages[item.id as PageId].icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    aria-current={isActive ? 'page' : undefined}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition duration-150 ${
                      isActive
                        ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-zinc-200 light:text-zinc-900 font-semibold shadow-sm'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60 dark:hover:bg-zinc-900/60 light:text-zinc-600 light:hover:text-zinc-900 light:hover:bg-zinc-100'
                    }`}
                  >
                    <div className="flex items-center space-x-2.5">
                      <Icon
                        className={`w-4 h-4 shrink-0 ${
                          isActive
                            ? 'text-zinc-200 dark:text-zinc-200 light:text-zinc-900'
                            : 'text-zinc-500 light:text-zinc-400'
                        }`}
                      />
                      <span className="truncate">{pages[item.id as PageId].title}</span>
                    </div>

                    {item.count !== undefined && (
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                          isActive
                            ? 'bg-zinc-700 text-zinc-100 dark:bg-zinc-700 dark:text-zinc-100 light:bg-zinc-300 light:text-zinc-900 font-bold'
                            : 'bg-zinc-900 text-zinc-500 dark:bg-zinc-900 dark:text-zinc-500 light:bg-zinc-200 light:text-zinc-600'
                        }`}
                      >
                        {item.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Sign out, below the left nav */}
      <div className="border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 p-3">
        <button
          type="button"
          onClick={handleLogout}
          className="w-full flex items-center gap-2 rounded-xl px-3 py-2 text-xs font-medium text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60 dark:hover:bg-zinc-800/60 light:text-zinc-600 light:hover:text-zinc-900 light:hover:bg-zinc-100"
        >
          <LogOut className="h-3.5 w-3.5" />
          <span>Sign out</span>
        </button>
        {confirmingLogout && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
            <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
              <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
                Sign out?
              </h3>
              <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
                This will end your session and return you to the login screen.
              </p>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setConfirmingLogout(false)}
                  className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={executeLogout}
                  className="px-3.5 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold disabled:opacity-50 transition"
                >
                  Sign out
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};
