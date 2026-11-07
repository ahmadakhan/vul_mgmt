import { PageHeading } from './PageHeading';
import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { ThreatFeed, FeedType, FeedAuthType } from '../types';
import {
  Radio,
  Plus,
  CheckCircle2,
  Lock,
  Trash2,
  Edit2,
  Search,
  RotateCw,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react';
import { formatDateTime as fmtDateTime } from '../utils/dateTime';

export const ThreatFeedsView: React.FC = () => {
  const { feeds, toggleFeedEnabled, testFeedConnectivity, addFeed, updateFeed, deleteFeed, settings } =
    useApp();

  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'enabled' | 'disabled'>('all');
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testingAll, setTestingAll] = useState(false);
  const [testAllProgress, setTestAllProgress] = useState<{ completed: number; total: number } | null>(null);
  const [testMessage, setTestMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingFeed, setEditingFeed] = useState<ThreatFeed | null>(null);
  const [deletingFeed, setDeletingFeed] = useState<ThreatFeed | null>(null);
  const [deletePending, setDeletePending] = useState(false);
  const [disablePending, setDisablePending] = useState(false);
  const [disablingFeed, setDisablingFeed] = useState<ThreatFeed | null>(null);
  const [confirmFeed, setConfirmFeed] = useState<{ id: string; label: string; enable: boolean } | null>(null);
  const [confirmSave, setConfirmSave] = useState<{ isEdit: boolean; label: string; feed: unknown } | null>(null);
  const [togglePending, setTogglePending] = useState(false);
  const [savePending, setSavePending] = useState(false);

  const [formData, setFormData] = useState({
    name: '',
    type: 'JSON_SEARCH_API' as FeedType,
    url: '',
    authType: 'NONE' as FeedAuthType,
    authSecretKey: '',
    requestTimeoutSeconds: 60,
    recoveryDelayMinutes: 5,
    rateLimitPerMin: 60,
    enabled: true,
  });

  const [formError, setFormError] = useState<string | null>(null);

  const filteredFeeds = feeds.filter(
    (feed) =>
      (filterStatus === 'all' || (filterStatus === 'enabled' && feed.enabled) || (filterStatus === 'disabled' && !feed.enabled)) &&
      (feed.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        feed.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
        feed.url.toLowerCase().includes(searchTerm.toLowerCase())),
  );
  const activeFeedCount = feeds.filter((feed) => feed.enabled).length;

  const handleTest = async (feedId: string) => {
    const feed = feeds.find((f) => f.id === feedId);
    setTestingId(feedId);
    setTestMessage(null);
    const result = await testFeedConnectivity(feedId);
    setTestingId(null);
    if (result?.success) {
      setTestMessage({
        type: 'success',
        text: `${feed?.name || 'Feed'} connectivity OK (${result.latency}ms)`,
      });
    } else if (result?.error) {
      setTestMessage({
        type: 'error',
        text: `${feed?.name || 'Feed'} test failed: ${result.error}`,
      });
    } else {
      setTestMessage({
        type: 'error',
        text: `${feed?.name || 'Feed'} test failed. See error banner for details.`,
      });
    }
    setTimeout(() => setTestMessage(null), 8000);
  };

  const handleTestAll = async () => {
    if (testingAll || feeds.length === 0) return;

    // Test in small batches so one slow or unreachable vendor cannot serialize the whole run.
    const queue = [...feeds];
    setTestingAll(true);
    setTestMessage(null);
    setTestAllProgress({ completed: 0, total: queue.length });

    const results: { name: string; success: boolean; latency: number; error?: string }[] = [];
    const worker = async () => {
      for (;;) {
        const feed = queue.shift();
        if (!feed) return;
        const result = await testFeedConnectivity(feed.id);
        results.push({ name: feed.name, ...result });
        setTestAllProgress((prev) => (prev ? { ...prev, completed: prev.completed + 1 } : prev));
      }
    };

    await Promise.all(Array.from({ length: Math.min(3, queue.length) }, () => worker()));

    setTestingAll(false);
    setTestAllProgress(null);

    const failed = results.filter((result) => !result.success);
    if (failed.length === 0) {
      setTestMessage({
        type: 'success',
        text: `All ${results.length} feeds passed connectivity checks.`,
      });
    } else {
      const details = failed
        .slice(0, 3)
        .map((result) => `${result.name}${result.error ? ` (${result.error})` : ''}`)
        .join('; ');
      const remaining = failed.length > 3 ? `; +${failed.length - 3} more` : '';
      setTestMessage({
        type: 'error',
        text: `${failed.length} of ${results.length} feeds failed: ${details}${remaining}`,
      });
    }
    setTimeout(() => setTestMessage(null), 12000);
  };

  const handleOpenAdd = () => {
    setFormData({
      name: '',
      type: 'JSON_SEARCH_API',
      url: 'https://',
      authType: 'NONE',
      authSecretKey: '',
      requestTimeoutSeconds: 60,
      recoveryDelayMinutes: 5,
      rateLimitPerMin: 60,
      enabled: true,
    });
    setEditingFeed(null);
    setFormError(null);
    setShowAddModal(true);
  };

  const handleOpenEdit = (feed: ThreatFeed) => {
    setFormData({
      name: feed.name,
      type: feed.type,
      url: feed.url,
      authType: feed.authType,
      authSecretKey: feed.authSecretKey || '',
      requestTimeoutSeconds: feed.requestTimeoutSeconds ?? 60,
      recoveryDelayMinutes: feed.recoveryDelayMinutes ?? 5,
      rateLimitPerMin: feed.rateLimitPerMin,
      enabled: feed.enabled,
    });
    setEditingFeed(feed);
    setFormError(null);
    setShowAddModal(true);
  };

  const handleSaveFeed = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    const feedData = {
      name: formData.name,
      type: formData.type,
      url: formData.url,
      authType: formData.authType,
      authSecretKey: formData.authSecretKey || undefined,
      requestTimeoutSeconds: formData.requestTimeoutSeconds,
      recoveryDelayMinutes: formData.recoveryDelayMinutes,
      rateLimitPerMin: formData.rateLimitPerMin,
      enabled: formData.enabled,
    };

    if (editingFeed) {
      setConfirmSave({
        isEdit: true,
        label: `Update "${editingFeed.name}"`,
        feed: { ...editingFeed, ...feedData },
      });
    } else {
      setConfirmSave({
        isEdit: false,
        label: `Add "${formData.name}"`,
        feed: { ...feedData, vendorSeed: false },
      });
    }
    setShowAddModal(false);
  };

  const handleDeleteFeed = async () => {
    if (!deletingFeed || deletePending) return;
    setDeletePending(true);
    const result = await deleteFeed(deletingFeed.id);
    setDeletePending(false);
    if (result) setDeletingFeed(null);
  };

  const handleConfirmedSave = async () => {
    if (!confirmSave) return;
    setSavePending(true);
    try {
      if (confirmSave.isEdit) {
        const ok = await updateFeed(confirmSave.feed as ThreatFeed);
        if (ok) {
          setConfirmSave(null);
        } else {
          setFormError('Failed to update feed. Please check the form values and try again.');
          setConfirmSave(null);
          setShowAddModal(true);
        }
      } else {
        const result = await addFeed(
          confirmSave.feed as Omit<ThreatFeed, 'id' | 'healthStatus' | 'lastSync' | 'latencyMs' | 'itemCountLastRun' | 'ssrfValidated'>,
        );
        if (result?.success) {
          setConfirmSave(null);
        } else {
          setFormError(result?.error || 'Failed to add feed. Check the URL, credentials, and server egress allowlist.');
          setConfirmSave(null);
          setShowAddModal(true);
        }
      }
    } finally {
      setSavePending(false);
    }
  };

  const handleConfirmedEnable = async () => {
    if (!confirmFeed) return;
    setTogglePending(true);
    try {
      await toggleFeedEnabled(confirmFeed.id);
    } finally {
      setTogglePending(false);
      setConfirmFeed(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="ui-page-header">
        <PageHeading page="feeds">
          Configure MITRE CVE, NVD, CISA KEV, FIRST EPSS, OpenCVE, VulnCheck KEV, or validated normalized JSON
          sources. The server scheduler polls enabled feeds when scheduling is enabled.
        </PageHeading>

        <div className="flex items-center gap-2">
          {/* Filter Toggle */}
          <div className="flex items-center gap-1 bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 rounded-xl p-0.5 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300">
            {(['all', 'enabled', 'disabled'] as const).map((status) => (
              <button
                key={status}
                onClick={() => setFilterStatus(status)}
                className={`text-[10px] font-mono px-2.5 py-1 rounded-lg transition ${
                  filterStatus === status
                    ? 'bg-zinc-100 dark:bg-zinc-100 light:bg-zinc-900 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 shadow-sm'
                    : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-800'
                }`}
                title={status === 'all' ? 'Show all feeds' : status === 'enabled' ? 'Show only enabled feeds' : 'Show only disabled feeds'}
              >
                {status === 'all' ? 'All' : status === 'enabled' ? 'Enabled' : 'Disabled'}
              </button>
            ))}
          </div>
          <button
            onClick={() => void handleTestAll()}
            disabled={testingAll || feeds.length === 0}
            className="text-xs px-3.5 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 font-semibold transition flex items-center space-x-1.5 shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
            title="Run a connectivity check against every configured feed"
          >
            {testingAll ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
            <span>
              {testingAll && testAllProgress
                ? `Testing ${testAllProgress.completed}/${testAllProgress.total}...`
                : 'Test All Feeds'}
            </span>
          </button>
          <button
            onClick={handleOpenAdd}
            className="text-xs px-3.5 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-semibold border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 transition flex items-center space-x-1.5 shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Threat Feed</span>
          </button>
        </div>
      </div>

      {/* Search & Stats Bar */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-sm transition-colors">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 absolute left-3 top-2.5" />
          <input
            type="text"
            aria-label="Search threat feeds"
            placeholder="Search feeds by vendor, protocol, or URL..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 dark:placeholder-zinc-500 light:placeholder-zinc-400 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>

        <div className="flex items-center space-x-4 text-xs font-mono">
          <div className="flex items-center space-x-1.5 text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              {feeds.length} Total Feeds / {activeFeedCount} Active Feeds
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>SSRF Guard: Enforced</span>
          </div>
        </div>
      </div>

      {testMessage && (
        <div
          role="status"
          aria-live="polite"
          className={`mb-4 px-4 py-2.5 rounded-xl text-xs font-mono flex items-center space-x-2 ${
            testMessage.type === 'success'
              ? 'bg-emerald-950/40 border border-emerald-800 text-emerald-300'
              : 'bg-red-950/40 border border-red-800 text-red-300'
          }`}
        >
          <Zap className="w-3.5 h-3.5 flex-shrink-0" />
          <span>{testMessage.text}</span>
        </div>
      )}

      {/* Threat Feeds Table */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
        <div>
          <table className="feeds-table w-full table-fixed text-left text-xs">
            <colgroup>
              <col style={{ width: '19%' }} />
              <col style={{ width: '12%' }} />
              <col style={{ width: '22%' }} />
              <col style={{ width: '12%' }} />
              <col style={{ width: '17%' }} />
              <col style={{ width: '6%' }} />
              <col style={{ width: '12%' }} />
            </colgroup>
            <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Feed Source / Vendor</th>
                <th className="py-3 px-4">Protocol &amp; Format</th>
                <th className="py-3 px-4">Endpoint URL</th>
                <th className="py-3 px-4">Auth &amp; Rate Limit</th>
                <th className="py-3 px-4">Health &amp; Latency</th>
                <th className="py-3 px-4">Active</th>
                <th className="feed-actions py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredFeeds.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-10 text-center text-sm text-zinc-500 dark:text-zinc-500 light:text-zinc-600"
                  >
                    {feeds.length
                      ? 'No feeds match your search.'
                      : 'No feeds configured yet. Add a source to start ingesting threat intelligence.'}
                  </td>
                </tr>
              )}
              {filteredFeeds.map((feed) => {
                const isTesting = testingId === feed.id;

                return (
                  <tr
                    key={feed.id}
                    className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition"
                  >
                    {/* Feed Name */}
                    <td className="py-3 px-4 font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                      <div className="flex items-center space-x-2">
                        <span>{feed.name}</span>
                        {feed.vendorSeed && (
                          <span className="text-[9px] bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 px-1.5 py-0.2 rounded font-mono">
                            Seed
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono mt-0.5">
                        Last Run Ingested: {feed.itemCountLastRun || 0} items
                      </div>
                    </td>

                    {/* Format */}
                    <td className="py-3 px-4 font-mono text-[11px] text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                      {feed.type}
                    </td>

                    {/* URL */}
                    <td
                      className="py-3 px-4 max-w-xs truncate font-mono text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600"
                      title={feed.url}
                    >
                      {feed.url}
                    </td>

                    {/* Auth */}
                    <td className="py-3 px-4 font-mono text-[11px]">
                      <div className="flex items-center space-x-1 text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                        {feed.authType !== 'NONE' && (
                          <Lock className="w-3 h-3 text-zinc-400 dark:text-zinc-400 light:text-zinc-600" />
                        )}
                        <span>{feed.authType}</span>
                      </div>
                      <div className="text-[10px] text-zinc-500">Max {feed.rateLimitPerMin} req/min</div>
                    </td>

                    {/* Health & Latency */}
                    <td className="py-3 px-4 font-mono">
                      <div className="flex items-center space-x-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            feed.healthStatus === 'HEALTHY' ? 'bg-emerald-500' : 'bg-zinc-500'
                          }`}
                        />
                        <span className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900 font-semibold text-[11px]">
                          {feed.healthStatus}
                        </span>
                        <span className="text-zinc-500 text-[10px]">({feed.latencyMs}ms)</span>
                      </div>
                      {feed.enabled && feed.healthStatus === 'DOWN' && feed.circuitOpenUntil && (
                        <div className="text-[10px] text-amber-400 mt-1">
                          Automatic retry after {fmtDateTime(feed.circuitOpenUntil, settings.timezone)}
                        </div>
                      )}
                      {feed.healthStatus !== 'HEALTHY' && feed.errorLog && (
                        <div
                          className="text-[10px] text-red-400 mt-0.5 max-w-xs truncate"
                          title={feed.errorLog}
                        >
                          {feed.errorLog}
                        </div>
                      )}
                    </td>

                    {/* Active toggle */}
                    <td className="py-3 px-4">
                      <button
                        onClick={() => {
                          if (feed.enabled) setDisablingFeed(feed);
                          else setConfirmFeed({ id: feed.id, label: feed.name, enable: true });
                        }}
                        disabled={confirmFeed !== null || disablingFeed !== null}
                        className={`w-8 h-4 flex items-center rounded-full p-0.5 transition ${
                          feed.enabled
                            ? 'bg-zinc-200 dark:bg-zinc-200 light:bg-zinc-900 justify-end'
                            : 'bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-300 justify-start'
                        }`}
                        title={feed.enabled ? 'Disable Feed' : 'Enable Feed'}
                      >
                        <span className="bg-zinc-950 dark:bg-zinc-950 light:bg-white w-3 h-3 rounded-full shadow-sm" />
                      </button>
                    </td>

                    {/* Actions */}
                    <td className="feed-actions py-3 px-4 text-right">
                      <div className="flex flex-wrap items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleTest(feed.id)}
                          disabled={isTesting || testingAll}
                          className="px-2.5 py-1 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 text-[11px] font-medium transition inline-flex items-center space-x-1"
                          title="Ping Endpoint & Test SSRF"
                        >
                          {isTesting ? (
                            <RotateCw className="w-3 h-3 animate-spin text-zinc-400" />
                          ) : (
                            <Zap className="w-3 h-3 text-zinc-400" />
                          )}
                          <span>{isTesting ? 'Testing...' : 'Test'}</span>
                        </button>
                        <button
                          onClick={() => handleOpenEdit(feed)}
                          className="p-1 text-zinc-400 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
                          title="Edit Feed"
                        >
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        {!feed.vendorSeed && feed.type !== 'NVD_API' && (
                          <button
                            onClick={() => setDeletingFeed(feed)}
                            className="p-1 text-zinc-400 hover:text-red-400 dark:text-zinc-400 dark:hover:text-red-400 light:text-zinc-600 light:hover:text-red-500 transition"
                            title="Delete Feed"
                            aria-label={`Delete ${feed.name}`}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add / Edit Custom Feed Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="feed-dialog-heading"
            className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative"
          >
            <button
              aria-label="Close feed dialog"
              onClick={() => setShowAddModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:text-zinc-500 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
            >
              <X className="w-5 h-5" />
            </button>

            <h2
              id="feed-dialog-heading"
              className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2"
            >
              <Radio className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-600" />
              {editingFeed ? 'Edit Threat Feed Source' : 'Register Custom Threat Feed'}
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Endpoints are protected against SSRF attacks. Secrets are encrypted with AES-256-GCM.
              Destination hosts must be allowed by the deployment administrator.
            </p>

            {formError && (
              <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs p-3 rounded-xl mb-4">
                {formError}
              </div>
            )}

            <form onSubmit={handleSaveFeed} className="space-y-4 text-xs">
              <div>
                <label
                  htmlFor="feed-name"
                  className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                >
                  Feed Name *
                </label>
                <input
                  id="feed-name"
                  type="text"
                  required
                  placeholder="e.g. Mandiant Threat Intel Stream"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label
                    htmlFor="feed-format"
                    className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                  >
                    Protocol / Format *
                  </label>
                  <select
                    id="feed-format"
                    value={formData.type}
                    onChange={(e) => {
                      const type = e.target.value as FeedType;
                      setFormData({
                        ...formData,
                        type,
                        ...(type === 'MITRE_CVE'
                          ? {
                              url: 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json',
                              authType: 'NONE' as FeedAuthType,
                              rateLimitPerMin: 120,
                            }
                          : {}),
                        ...(type === 'OPENCVE_API' || type === 'VULNCHECK_KEV'
                          ? { authType: 'BEARER' as FeedAuthType }
                          : {}),
                        ...(type === 'OTX_API'
                          ? {
                              url: 'https://otx.alienvault.com/api/v1/pulses/subscribed/',
                              authType: 'API_KEY' as FeedAuthType,
                              rateLimitPerMin: 60,
                            }
                          : {}),
                      });
                    }}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono focus:border-zinc-600 focus:outline-none"
                  >
                    <option value="JSON_SEARCH_API">Normalized CVE JSON array</option>
                    <option value="NVD_API">NVD CVE API 2.0</option>
                    <option value="MITRE_CVE">MITRE CVE (official CVE JSON 5 list)</option>
                    <option value="CISA_KEV">CISA KEV JSON catalog</option>
                    <option value="EPSS_API">FIRST EPSS API</option>
                    <option value="OPENCVE_API">OpenCVE API v2 (Bearer token)</option>
                    <option value="VULNCHECK_KEV">VulnCheck KEV (Bearer token)</option>
                    <option value="OTX_API">AlienVault OTX subscribed Pulses (API key)</option>
                    <option value="RSS_ATOM">RSS / Atom news and advisory evidence</option>
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="feed-rate"
                    className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                  >
                    Rate Limit (req/min)
                  </label>
                  <input
                    id="feed-rate"
                    type="number"
                    min={1}
                    max={600}
                    value={formData.rateLimitPerMin}
                    onChange={(e) => setFormData({ ...formData, rateLimitPerMin: Number(e.target.value) })}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label
                    htmlFor="feed-timeout"
                    className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                  >
                    Request timeout (seconds)
                  </label>
                  <input
                    id="feed-timeout"
                    type="number"
                    required
                    min={5}
                    max={120}
                    value={formData.requestTimeoutSeconds}
                    onChange={(e) =>
                      setFormData({ ...formData, requestTimeoutSeconds: Number(e.target.value) })
                    }
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100"
                  />
                </div>
                <div>
                  <label
                    htmlFor="feed-recovery"
                    className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                  >
                    Recovery delay (minutes)
                  </label>
                  <input
                    id="feed-recovery"
                    type="number"
                    required
                    min={1}
                    max={60}
                    value={formData.recoveryDelayMinutes}
                    onChange={(e) =>
                      setFormData({ ...formData, recoveryDelayMinutes: Number(e.target.value) })
                    }
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100"
                  />
                </div>
                <p className="col-span-2 text-xs text-zinc-500">
                  Failed sources retry automatically after this delay, doubling on repeated failures up to 60
                  minutes.
                </p>
              </div>

              <div>
                <label
                  htmlFor="feed-url"
                  className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                >
                  Endpoint URL *
                </label>
                <input
                  id="feed-url"
                  type="url"
                  required
                  placeholder="https://feed.provider.org/threats.json"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label
                    htmlFor="feed-auth-type"
                    className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                  >
                    Authentication Type
                  </label>
                  <select
                    id="feed-auth-type"
                    value={formData.authType}
                    onChange={(e) => setFormData({ ...formData, authType: e.target.value as FeedAuthType })}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono focus:border-zinc-600 focus:outline-none"
                  >
                    <option value="NONE">None (Public)</option>
                    <option value="API_KEY">API Key Header</option>
                    <option value="BEARER">Bearer Token</option>
                    <option value="BASIC">HTTP Basic Auth</option>
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="feed-token"
                    className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                  >
                    Secret Key / Token
                  </label>
                  <input
                    id="feed-token"
                    type="password"
                    placeholder={
                      formData.authType === 'NONE'
                        ? 'Not required'
                        : formData.authType === 'BASIC'
                          ? 'username:password'
                          : editingFeed
                            ? 'Leave blank to retain existing secret'
                            : 'Enter key...'
                    }
                    disabled={formData.authType === 'NONE'}
                    value={formData.authSecretKey}
                    onChange={(e) => setFormData({ ...formData, authSecretKey: e.target.value })}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none disabled:opacity-40"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold transition"
                >
                  {editingFeed ? 'Save Changes' : 'Save Feed'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Disable Feed Confirmation Modal */}
      {disablingFeed && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-amber-300 dark:text-amber-300 light:text-amber-700 mb-2">
              Disable Threat Feed Source?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to disable <strong>{disablingFeed.name}</strong>? Polling for this
              endpoint will pause immediately and stop ingesting new findings until re-enabled.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDisablingFeed(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  setDisablePending(true);
                  try {
                    await toggleFeedEnabled(disablingFeed.id);
                  } finally {
                    setDisablePending(false);
                    setDisablingFeed(null);
                  }
                }}
                disabled={disablePending}
                className="px-3.5 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {disablePending ? 'Disabling…' : 'Disable Feed'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Enable Feed Confirmation Modal */}
      {confirmFeed && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-emerald-300 dark:text-emerald-300 light:text-emerald-700 mb-2">
              Enable Threat Feed Source?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to enable <strong>{confirmFeed.label}</strong>? Polling for this
              endpoint will resume immediately and begin ingesting new findings.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmFeed(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleConfirmedEnable()}
                disabled={togglePending}
                className="px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {togglePending ? 'Enabling…' : 'Enable Feed'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Feed Confirmation Modal */}
      {deletingFeed && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              Delete Threat Feed Source?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to remove <strong>{deletingFeed.name}</strong>? Automated polling for this
              endpoint will terminate immediately.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeletingFeed(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleDeleteFeed()}
                disabled={deletePending}
                className="px-3.5 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {deletePending ? 'Deleting…' : 'Delete Feed'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Save Feed Confirmation Modal */}
      {confirmSave && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              Save Threat Feed Changes?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to <strong>{confirmSave.isEdit ? 'update' : 'add'}</strong>
              <span className="font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
                {confirmSave.label}
              </span>
              ? This will change the feed configuration and may affect polling.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmSave(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleConfirmedSave()}
                disabled={savePending}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 text-xs font-semibold disabled:opacity-50 transition"
              >
                {savePending ? 'Saving…' : 'Confirm Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
