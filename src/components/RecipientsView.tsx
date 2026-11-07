import { PageHeading } from './PageHeading';
import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { EmailRecipient, WebhookEndpoint } from '../types';
import { Plus, Trash2, Mail, AlertCircle, X, Search, Webhook, Send, CheckCircle2, Edit2 } from 'lucide-react';

export const RecipientsView: React.FC = () => {
  const {
    recipients,
    addRecipient,
    updateRecipient,
    toggleRecipientEnabled,
    deleteRecipient,
    webhooks,
    addWebhook,
    updateWebhook,
    toggleWebhookEnabled,
    deleteWebhook,
    testWebhook,
  } = useApp();

  const [activeTab, setActiveTab] = useState<'email' | 'webhooks'>('email');
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddEmailModal, setShowAddEmailModal] = useState(false);
  const [showAddWebhookModal, setShowAddWebhookModal] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [deletingRecipientId, setDeletingRecipientId] = useState<string | null>(null);
  const [deletingWebhookId, setDeletingWebhookId] = useState<string | null>(null);

  const [editingRecipient, setEditingRecipient] = useState<EmailRecipient | null>(null);
  const [editingWebhook, setEditingWebhook] = useState<WebhookEndpoint | null>(null);
  const [confirmToggleRecipient, setConfirmToggleRecipient] = useState<{ id: string; enabled: boolean } | null>(null);
  const [confirmToggleWebhook, setConfirmToggleWebhook] = useState<{ id: string; enabled: boolean } | null>(null);
  const [confirmToggleDigest, setConfirmToggleDigest] = useState<{ id: string; dailyDigest: boolean } | null>(null);
  const [confirmTestWebhook, setConfirmTestWebhook] = useState<{ id: string; name: string } | null>(null);
  const [confirmingEmailSave, setConfirmingEmailSave] = useState(false);
  const [confirmingWebhookSave, setConfirmingWebhookSave] = useState(false);

  // Email form state
  const [emailForm, setEmailForm] = useState({
    name: '',
    email: '',
    role: '',
    deliveryGroup: 'SECURITY_TEAM' as NonNullable<EmailRecipient['deliveryGroup']>,
    subscriptionTier: 'CRITICAL_HIGH_ONLY' as EmailRecipient['subscriptionTier'],
    enabled: true,
    dailyDigest: false,
  });

  // Webhook form state
  const [webhookForm, setWebhookForm] = useState({
    name: '',
    url: '',
    provider: 'SLACK' as WebhookEndpoint['provider'],
    secretToken: '',
    events: ['CRITICAL', 'CISA_KEV'] as ('CRITICAL' | 'CISA_KEV' | 'ALL')[],
    enabled: true,
  });

  // Webhook test modal state
  const [testResult, setTestResult] = useState<{
    endpointName: string;
    statusCode: number;
    signature: string;
  } | null>(null);

  const filteredRecipients = recipients.filter(
    (r) =>
      r.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.role.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  const filteredWebhooks = webhooks.filter(
    (w) =>
      w.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      w.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
      w.provider.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  const handleOpenEmailEdit = (r: EmailRecipient) => {
    setEditingRecipient(r);
    setEmailForm({
      name: r.name,
      email: r.email,
      role: r.role,
      deliveryGroup: r.deliveryGroup ?? 'SECURITY_TEAM',
      subscriptionTier: r.subscriptionTier,
      enabled: r.enabled,
      dailyDigest: !!r.dailyDigest,
    });
    setShowAddEmailModal(true);
  };

  const handleAddEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (confirmingEmailSave) return;
    setErrorMsg(null);
    setConfirmingEmailSave(true);
  };

  const handleOpenWebhookEdit = (w: WebhookEndpoint) => {
    setEditingWebhook(w);
    setWebhookForm({
      name: w.name,
      url: w.url,
      provider: w.provider,
      secretToken: '',
      events: w.events,
      enabled: w.enabled,
    });
    setShowAddWebhookModal(true);
  };

  const handleAddWebhookSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (confirmingWebhookSave) return;
    setErrorMsg(null);
    if (!webhookForm.name.trim() || !webhookForm.url.trim()) {
      setErrorMsg('Please provide a name and webhook URL.');
      return;
    }
    setConfirmingWebhookSave(true);
  };

  const handleRunWebhookTest = async (endpoint: WebhookEndpoint) => {
    setErrorMsg(null);
    const res = await testWebhook(endpoint.id);
    if (res.success) {
      setTestResult({
        endpointName: endpoint.name,
        statusCode: res.statusCode,
        signature: res.signature,
      });
    } else {
      setErrorMsg(
        `Webhook test for ${endpoint.name} failed${res.statusCode ? ` (HTTP ${res.statusCode})` : ''}.`,
      );
    }
  };

  const executeToggleRecipient = async () => {
    if (!confirmToggleRecipient) return;
    const { id, enabled } = confirmToggleRecipient;
    try {
      await toggleRecipientEnabled(id);
    } finally {
      setConfirmToggleRecipient(null);
    }
  };

  const executeToggleWebhook = async () => {
    if (!confirmToggleWebhook) return;
    const { id, enabled } = confirmToggleWebhook;
    try {
      await toggleWebhookEnabled(id);
    } finally {
      setConfirmToggleWebhook(null);
    }
  };

  const executeToggleDigest = async () => {
    if (!confirmToggleDigest) return;
    const { id, dailyDigest } = confirmToggleDigest;
    const r = recipients.find((x) => x.id === id);
    if (!r) {
      setConfirmToggleDigest(null);
      return;
    }
    try {
      await updateRecipient({ ...r, dailyDigest });
    } finally {
      setConfirmToggleDigest(null);
    }
  };

  const executeTestWebhook = async () => {
    if (!confirmTestWebhook) return;
    const { id, name } = confirmTestWebhook;
    setErrorMsg(null);
    const res = await testWebhook(id);
    if (res.success) {
      setTestResult({
        endpointName: name,
        statusCode: res.statusCode,
        signature: res.signature,
      });
    } else {
      setErrorMsg(
        `Webhook test for ${name} failed${res.statusCode ? ` (HTTP ${res.statusCode})` : ''}.`,
      );
    }
    setConfirmTestWebhook(null);
  };

  const executeConfirmedEmailSave = async () => {
    setConfirmingEmailSave(false);
    const payload = {
      name: emailForm.name.trim(),
      email: emailForm.email.trim(),
      role: emailForm.role.trim() || 'Security Engineer',
      deliveryGroup: emailForm.deliveryGroup,
      subscriptionTier: emailForm.subscriptionTier,
      enabled: emailForm.enabled,
      dailyDigest: emailForm.dailyDigest,
    };
    const ok = editingRecipient
      ? await updateRecipient({
          ...payload,
          id: editingRecipient.id,
          deliverySuccessRate: editingRecipient.deliverySuccessRate,
        })
      : await addRecipient(payload);
    if (ok) {
      setShowAddEmailModal(false);
      setEditingRecipient(null);
      setEmailForm({
        name: '',
        email: '',
        role: '',
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'CRITICAL_HIGH_ONLY',
        enabled: true,
        dailyDigest: false,
      });
    } else {
      setErrorMsg('Invalid email format. Please check and try again.');
    }
  };

  const executeConfirmedWebhookSave = async () => {
    setConfirmingWebhookSave(false);
    const payload = {
      name: webhookForm.name.trim(),
      url: webhookForm.url.trim(),
      provider: webhookForm.provider,
      secretToken: webhookForm.secretToken.trim(),
      events: webhookForm.events,
      enabled: webhookForm.enabled,
    };
    let ok: boolean;
    if (editingWebhook) {
      ok = await updateWebhook({
        ...payload,
        id: editingWebhook.id,
        deliveryCount: editingWebhook.deliveryCount,
      });
    } else {
      ok = await addWebhook(payload);
    }
    if (!ok) return;
    setShowAddWebhookModal(false);
    setEditingWebhook(null);
    setWebhookForm({
      name: '',
      url: '',
      provider: 'SLACK',
      secretToken: '',
      events: ['CRITICAL', 'CISA_KEV'],
      enabled: true,
    });
  };

  return (
    <div className="space-y-6">
      {/* Header & Sub-Tab Navigation */}
      <div className="ui-page-header">
        <PageHeading page="recipients">
          Enterprise distribution lists and webhook pipelines receiving automated alerts with zero human
          intervention.
        </PageHeading>

        <div className="flex items-center space-x-2">
          {activeTab === 'email' ? (
            <button
              onClick={() => {
                setErrorMsg(null);
                setEditingRecipient(null);
                setEmailForm({
                  name: '',
                  email: '',
                  role: '',
                  deliveryGroup: 'SECURITY_TEAM',
                  subscriptionTier: 'CRITICAL_HIGH_ONLY',
                  enabled: true,
                  dailyDigest: false,
                });
                setShowAddEmailModal(true);
              }}
              className="text-xs px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold transition flex items-center space-x-1.5 shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Email Recipient</span>
            </button>
          ) : (
            <button
              onClick={() => {
                setErrorMsg(null);
                setEditingWebhook(null);
                setWebhookForm({
                  name: '',
                  url: '',
                  provider: 'SLACK',
                  secretToken: '',
                  events: ['CRITICAL', 'CISA_KEV'],
                  enabled: true,
                });
                setShowAddWebhookModal(true);
              }}
              className="text-xs px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold transition flex items-center space-x-1.5 shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register Webhook</span>
            </button>
          )}
        </div>
      </div>

      {/* Channel Switcher Tabs (NextUI Style) */}
      <div className="flex items-center justify-between border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-200 pb-3">
        <div className="ui-segmented flex items-center space-x-1.5 bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl">
          <button
            onClick={() => setActiveTab('email')}
            aria-pressed={activeTab === 'email'}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition flex items-center space-x-1.5 ${
              activeTab === 'email'
                ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900'
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Email recipients ({recipients.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('webhooks')}
            aria-pressed={activeTab === 'webhooks'}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition flex items-center space-x-1.5 ${
              activeTab === 'webhooks'
                ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900'
            }`}
          >
            <Webhook className="w-3.5 h-3.5" />
            <span>Webhooks ({webhooks.length})</span>
          </button>
        </div>

        <div className="relative w-72 hidden md:block">
          <Search className="w-3.5 h-3.5 text-zinc-500 dark:text-zinc-500 light:text-zinc-600 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder={activeTab === 'email' ? 'Search recipients...' : 'Search webhooks...'}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-8 pr-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 dark:placeholder-zinc-500 light:placeholder-zinc-400 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>
      </div>

      {/* TAB 1: Email Recipients */}
      {activeTab === 'email' && (
        <div className="space-y-4">
          <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Recipient Name</th>
                    <th className="py-3 px-4">Email Address</th>
                    <th className="py-3 px-4">Role / Team</th>
                    <th className="py-3 px-4">Delivery / filter</th>
                    <th className="py-3 px-4">Success Rate</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Daily digest</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRecipients.length === 0 ? (
                    <tr>
                      <td
                        colSpan={8}
                        className="py-8 text-center text-zinc-500 dark:text-zinc-500 light:text-zinc-600"
                      >
                        No recipients match the filter.
                      </td>
                    </tr>
                  ) : (
                    filteredRecipients.map((r) => (
                      <tr
                        key={r.id}
                        className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition"
                      >
                        <td className="py-3 px-4 font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 flex items-center space-x-2">
                          <div className="w-6 h-6 rounded-full bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 border border-zinc-700/60 dark:border-zinc-700/60 light:border-zinc-300 flex items-center justify-center text-[10px] text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                            {r.name.slice(0, 1)}
                          </div>
                          <span>{r.name}</span>
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                          {r.email}
                        </td>
                        <td className="py-3 px-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                          {r.role}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`mb-1 inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold ${
                              r.deliveryGroup === 'EVERYONE'
                                ? 'border-amber-500/30 bg-amber-500/10 text-amber-300 light:text-amber-700'
                                : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 light:text-emerald-700'
                            }`}
                          >
                            {r.deliveryGroup === 'EVERYONE' ? 'SECURITY REVIEW' : 'AUTO · SECURITY TEAM'}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                              r.subscriptionTier === 'ALL_SEVERITIES'
                                ? 'bg-zinc-800 text-zinc-200 dark:bg-zinc-800 dark:text-zinc-200 light:bg-zinc-200 light:text-zinc-800 border-zinc-600 dark:border-zinc-600 light:border-zinc-400'
                                : r.subscriptionTier === 'CISA_KEV_ONLY'
                                  ? 'bg-zinc-800/80 dark:bg-zinc-800/80 light:bg-zinc-300 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 border-zinc-500 dark:border-zinc-500 light:border-zinc-400 font-bold'
                                  : 'bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-100 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 border-zinc-700 dark:border-zinc-700 light:border-zinc-300'
                            }`}
                          >
                            {r.subscriptionTier.replace(/_/g, ' ')}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                          {r.deliverySuccessRate.toFixed(1)}%
                        </td>
                        <td className="py-3 px-4">
                          <button
                            onClick={() => setConfirmToggleRecipient({ id: r.id, enabled: !r.enabled })}
                            disabled={confirmToggleRecipient !== null}
                            className={`px-2 py-0.5 rounded-full text-[10px] font-mono border transition ${
                              r.enabled
                                ? 'bg-emerald-950/40 text-emerald-300 light:text-emerald-700 border-emerald-800/60'
                                : 'bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-100 text-zinc-500 dark:text-zinc-500 light:text-zinc-600 border-zinc-800 dark:border-zinc-800 light:border-zinc-300'
                            }`}
                          >
                            {r.enabled ? 'ACTIVE' : 'MUTED'}
                          </button>
                        </td>
                        <td className="py-3 px-4">
                          <button
                            type="button"
                            onClick={() => setConfirmToggleDigest({ id: r.id, dailyDigest: !r.dailyDigest })}
                            disabled={confirmToggleDigest !== null}
                            className={`inline-flex items-center justify-center w-5 h-5 rounded border transition ${
                              r.dailyDigest
                                ? 'bg-amber-500 border-amber-500 text-white'
                                : 'bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-100 border-zinc-700 dark:border-zinc-700 light:border-zinc-300 text-zinc-500 dark:text-zinc-500 light:text-zinc-600'
                            }`}
                            title={r.dailyDigest ? 'Opted out of daily digest' : 'Opt in to daily digest'}
                          >
                            <Send className="w-3 h-3" />
                          </button>
                        </td>
                        <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end space-x-1">
                              <button
                                onClick={() => handleOpenEmailEdit(r)}
                                disabled={confirmToggleRecipient !== null || confirmToggleDigest !== null || confirmingEmailSave}
                                className="p-1 rounded hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
                                title="Edit"
                              >
                                <Edit2 className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => setDeletingRecipientId(r.id)}
                                disabled={confirmToggleRecipient !== null || confirmToggleDigest !== null || deletingRecipientId === r.id}
                                className="p-1 rounded hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
                                title="Delete"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Autonomous Webhooks */}
      {activeTab === 'webhooks' && (
        <div className="space-y-4">
          <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Endpoint Name</th>
                    <th className="py-3 px-4">Provider</th>
                    <th className="py-3 px-4">Webhook Target URL</th>
                    <th className="py-3 px-4">Events</th>
                    <th className="py-3 px-4">Deliveries</th>
                    <th className="py-3 px-4">State</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredWebhooks.length === 0 ? (
                    <tr>
                      <td
                        colSpan={7}
                        className="py-8 text-center text-zinc-500 dark:text-zinc-500 light:text-zinc-600"
                      >
                        No webhooks configured. Register a Slack, Teams, or SIEM webhook above.
                      </td>
                    </tr>
                  ) : (
                    filteredWebhooks.map((w) => (
                      <tr
                        key={w.id}
                        className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition"
                      >
                        <td className="py-3 px-4 font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 flex items-center space-x-2">
                          <Webhook className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-400 light:text-zinc-500" />
                          <span>{w.name}</span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="font-mono text-[11px] bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 px-2 py-0.5 rounded border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                            {w.provider}
                          </span>
                        </td>
                        <td
                          className="py-3 px-4 font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 max-w-xs truncate"
                          title={w.url}
                        >
                          {w.url}
                        </td>
                        <td className="py-3 px-4 font-mono text-[10px] text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                          {w.events.join(', ')}
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                          {w.deliveryCount} sent
                        </td>
                        <td className="py-3 px-4">
                          <button
                            onClick={() => setConfirmToggleWebhook({ id: w.id, enabled: !w.enabled })}
                            disabled={confirmToggleWebhook !== null}
                            className={`px-2 py-0.5 rounded-full text-[10px] font-mono border transition ${
                              w.enabled
                                ? 'bg-emerald-950/40 text-emerald-300 light:text-emerald-700 border-emerald-800/60'
                                : 'bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-100 text-zinc-500 dark:text-zinc-500 light:text-zinc-600 border-zinc-800 dark:border-zinc-800 light:border-zinc-300'
                            }`}
                          >
                            {w.enabled ? 'ENABLED' : 'PAUSED'}
                          </button>
                        </td>
                        <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end space-x-1">
                              <button
                                onClick={() => handleOpenWebhookEdit(w)}
                                disabled={confirmToggleWebhook !== null || confirmingWebhookSave}
                                className="p-1 rounded hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
                                title="Edit"
                              >
                                <Edit2 className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => setConfirmTestWebhook({ id: w.id, name: w.name })}
                                disabled={confirmTestWebhook !== null || confirmToggleWebhook !== null}
                                className="px-2.5 py-1 rounded-lg bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 text-[11px] font-medium transition flex items-center space-x-1"
                                title="Send Test Ping"
                              >
                                <Send className="w-3 h-3" />
                                <span>Test</span>
                              </button>
                              <button
                                onClick={() => setDeletingWebhookId(w.id)}
                                disabled={confirmToggleWebhook !== null || deletingWebhookId === w.id}
                                className="p-1 rounded hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 text-zinc-400 dark:text-zinc-400 light:text-zinc-500 hover:text-red-400 transition"
                                title="Delete"
                              >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Webhook Test Result Modal */}
      {testResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setTestResult(null)}
              className="absolute top-4 right-4 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 text-emerald-400 mb-2">
              <CheckCircle2 className="w-5 h-5" />
              <h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                Webhook Test Queued
              </h2>
            </div>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              A test notification was queued for{' '}
              <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
                {testResult.endpointName}
              </strong>
              .
            </p>

            <div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-3 font-mono text-[11px] space-y-2 text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              <div className="flex justify-between">
                <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600">HTTP Status:</span>
                <span className="text-emerald-400 font-bold">{testResult.statusCode} Queued</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600">Delivery:</span>
                <span className="text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
                  Pending worker acceptance
                </span>
              </div>
              <div>
                <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 block mb-1">
                  Signature:
                </span>
                <span className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[10px] break-all bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 p-1.5 rounded block">
                  {testResult.signature || 'Generated when the worker sends the request'}
                </span>
              </div>
            </div>

            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setTestResult(null)}
                className="px-4 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-100 dark:text-zinc-100 light:text-zinc-800 font-semibold text-xs transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Email Recipient Modal */}
      {showAddEmailModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowAddEmailModal(false)}
              className="absolute top-4 right-4 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2">
              <Mail className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-600" />
              {editingRecipient ? 'Edit Email Recipient' : 'Add Email Recipient'}
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Security team recipients are sent alerts automatically. Everyone recipients are held for
              security-team review before delivery.
            </p>

            {errorMsg && (
              <div className="mb-3 p-2.5 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-rose-800/60 dark:border-rose-800/60 light:border-rose-200/60 rounded-xl text-xs text-rose-300 flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleAddEmailSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Recipient Name *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Lead DevSecOps"
                  value={emailForm.name}
                  onChange={(e) => setEmailForm({ ...emailForm, name: e.target.value })}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Email Address *
                </label>
                <input
                  type="email"
                  required
                  placeholder="e.g. secops-team@enterprise.org"
                  value={emailForm.email}
                  onChange={(e) => setEmailForm({ ...emailForm, email: e.target.value })}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Role / Designation
                </label>
                <input
                  type="text"
                  placeholder="e.g. SOC Tier 3 Responder"
                  value={emailForm.role}
                  onChange={(e) => setEmailForm({ ...emailForm, role: e.target.value })}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Notification group
                </label>
                <select
                  value={emailForm.deliveryGroup}
                  onChange={(e) =>
                    setEmailForm({
                      ...emailForm,
                      deliveryGroup: e.target.value as NonNullable<EmailRecipient['deliveryGroup']>,
                    })
                  }
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                >
                  <option value="SECURITY_TEAM">Security team · send automatically</option>
                  <option value="EVERYONE">Everyone · require security review</option>
                </select>
                <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-500 light:text-zinc-600">
                  Review-required alerts stay queued until an authorized operator approves them.
                </p>
              </div>

              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Subscription Filter Tier
                </label>
                <select
                  value={emailForm.subscriptionTier}
                  onChange={(e) =>
                    setEmailForm({
                      ...emailForm,
                      subscriptionTier: e.target.value as EmailRecipient['subscriptionTier'],
                    })
                  }
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                >
                  <option value="CRITICAL_HIGH_ONLY">Critical &amp; High Only (Standard)</option>
                  <option value="CISA_KEV_ONLY">CISA KEV Actively Exploited Only</option>
                  <option value="ALL_SEVERITIES">All Severities (Includes Low / Medium)</option>
                </select>
              </div>

              <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    checked={emailForm.dailyDigest}
                    onChange={(e) => setEmailForm({ ...emailForm, dailyDigest: e.target.checked })}
                    className="h-4 w-4 rounded border-zinc-600 bg-zinc-800 text-amber-500 focus:ring-amber-500 light:bg-white"
                  />
                  <span>
                    <span className="block font-medium text-zinc-200 light:text-zinc-800">
                      Subscribe to daily digest
                    </span>
                    <span className="ui-description mt-0.5 block">
                      Receive a daily summary of findings plus an operational health-check report at the time
                      configured in Settings.
                    </span>
                  </span>
                </div>
              </label>

              <div className="flex justify-end gap-2 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
                <button
                  type="button"
                  onClick={() => setShowAddEmailModal(false)}
                  className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
                >
                  Save Recipient
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Webhook Modal */}
      {showAddWebhookModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowAddWebhookModal(false)}
              className="absolute top-4 right-4 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2">
              <Webhook className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-600" />
              {editingWebhook ? 'Edit Webhook Endpoint' : 'Register Autonomous Webhook Channel'}
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Dispatches JSON payloads with HMAC-SHA256 signature immediately upon vulnerability correlation.
            </p>

            {errorMsg && (
              <div className="mb-3 p-2.5 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-rose-800/60 dark:border-rose-800/60 light:border-rose-200/60 rounded-xl text-xs text-rose-300 flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleAddWebhookSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Channel Name *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. SecOps Alerts (Slack)"
                  value={webhookForm.name}
                  onChange={(e) => setWebhookForm({ ...webhookForm, name: e.target.value })}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Provider Format
                </label>
                <select
                  value={webhookForm.provider}
                  onChange={(e) =>
                    setWebhookForm({
                      ...webhookForm,
                      provider: e.target.value as WebhookEndpoint['provider'],
                    })
                  }
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                >
                  <option value="SLACK">Slack Incoming Webhook</option>
                  <option value="TEAMS">Microsoft Teams Connector</option>
                  <option value="GENERIC_HMAC">Enterprise SIEM / SOAR (HMAC-SHA256)</option>
                </select>
              </div>

              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Webhook URL *
                </label>
                <input
                  type="url"
                  required
                  placeholder="https://hooks.slack.com/services/..."
                  value={webhookForm.url}
                  onChange={(e) => setWebhookForm({ ...webhookForm, url: e.target.value })}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  HMAC shared secret (32+ characters for Generic HMAC)
                </label>
                <input
                  type="password"
                  placeholder="Required for Generic HMAC receivers"
                  value={webhookForm.secretToken}
                  onChange={(e) => setWebhookForm({ ...webhookForm, secretToken: e.target.value })}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
                <button
                  type="button"
                  onClick={() => setShowAddWebhookModal(false)}
                  className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
                >
                  {editingWebhook ? 'Save Webhook' : 'Register Webhook'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Recipient Confirmation */}
      {deletingRecipientId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              Remove Recipient?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              This recipient will stop receiving automated vulnerability notifications.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeletingRecipientId(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  if (await deleteRecipient(deletingRecipientId)) setDeletingRecipientId(null);
                }}
                className="px-3.5 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                Remove
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Webhook Confirmation */}
      {deletingWebhookId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              Remove Webhook Endpoint?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Automated payload delivery to this endpoint will be terminated.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeletingWebhookId(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  if (await deleteWebhook(deletingWebhookId)) setDeletingWebhookId(null);
                }}
                className="px-3.5 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                Remove
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toggle Recipient Confirmation */}
      {confirmToggleRecipient && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {confirmToggleRecipient.enabled ? 'Mute Recipient?' : 'Activate Recipient?'}
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              {confirmToggleRecipient.enabled
                ? 'This recipient will stop receiving automated vulnerability notifications.'
                : 'This recipient will start receiving automated vulnerability notifications.'}
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmToggleRecipient(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={() => void executeToggleRecipient()}
                className="px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs transition"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toggle Webhook Confirmation */}
      {confirmToggleWebhook && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {confirmToggleWebhook.enabled ? 'Pause Webhook?' : 'Enable Webhook?'}
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              {confirmToggleWebhook.enabled
                ? 'Automated payload delivery to this endpoint will be paused.'
                : 'Automated payload delivery to this endpoint will be enabled.'}
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmToggleWebhook(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={() => void executeToggleWebhook()}
                className="px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs transition"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toggle Daily Digest Confirmation */}
      {confirmToggleDigest && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {confirmToggleDigest.dailyDigest ? 'Opt Out of Daily Digest?' : 'Opt In to Daily Digest?'}
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              {confirmToggleDigest.dailyDigest
                ? 'This recipient will no longer receive the daily summary.'
                : 'This recipient will receive a daily summary of findings.'}
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmToggleDigest(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={() => void executeToggleDigest()}
                className="px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs transition"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Test Webhook Confirmation */}
      {confirmTestWebhook && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              Send Test Ping?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              A test notification will be sent to <strong>{confirmTestWebhook.name}</strong>.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmTestWebhook(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={() => void executeTestWebhook()}
                className="px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs transition"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Save Email Recipient Confirmation */}
      {confirmingEmailSave && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {editingRecipient ? 'Save Recipient Changes?' : 'Add Email Recipient?'}
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              {editingRecipient
                ? `This will update the recipient ${emailForm.name}.`
                : `This will add ${emailForm.name} as a new email recipient.`}
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmingEmailSave(false)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={() => void executeConfirmedEmailSave()}
                className="px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs transition"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Save Webhook Confirmation */}
      {confirmingWebhookSave && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {editingWebhook ? 'Save Webhook Changes?' : 'Register Webhook?'}
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              {editingWebhook
                ? `This will update the webhook ${webhookForm.name}.`
                : `This will register ${webhookForm.name} as a new webhook endpoint.`}
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmingWebhookSave(false)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={() => void executeConfirmedWebhookSave()}
                className="px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs transition"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
