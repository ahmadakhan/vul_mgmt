import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import {
  emptyState,
  type AppState,
  type SessionInfo,
  type CollectionKind,
  type CollectionPage,
} from '../../shared/state';
import type {
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  EmailRecipient,
  WebhookEndpoint,
  TemplateCustomization,
  AppSettings,
  PipelineExecution,
  AuditLog,
  EmailConfiguration,
  SystemHealth,
  EmailQueueItem,
  AliasEntry,
  RetentionRunResult,
  RetentionPreview,
  CorrelationSimulation,
  NvdCpeSearchResponse,
  ThreatSearchResponse,
  ThreatAnalytics,
  CpeMatchSimulation,
  ReviewEdits,
  VulnerabilitySearchParams,
  VulnerabilitySearchResponse,
} from '../types';
import {
  compileCustomizedTemplate,
  compileDailyDigestTemplate,
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
} from '../utils/templateCompiler';

const SESSION_RENEW_THRESHOLD_SEC = 60;

function useApplication() {
  const [snapshot, setSnapshot] = useState<AppState>(emptyState);
  const [session, setSession] = useState<SessionInfo | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('dashboard'),
    [mobileNavOpen, setMobileNavOpen] = useState(false),
    [selectedFinding, setSelectedFinding] = useState<Finding | null>(null),
    [selectedAdvisory, setSelectedAdvisory] = useState<Advisory | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      return localStorage.getItem('vulnstream_theme') === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });
  const [clock, setClock] = useState(Date.now()),
    [draft, setDraft] = useState<TemplateCustomization | null>(null),
    [dailyDigestDraft, setDailyDigestDraft] = useState<TemplateCustomization | null>(null),
    [dailyDigestCustomTemplate, setDailyDigestCustomTemplate] = useState(() => {
      try {
        return localStorage.getItem('vulnstream_dailyDigestCustomTemplate');
      } catch {
        return null;
      }
    }),
[refreshVersion, setRefreshVersion] = useState(0),
    [pending, setPending] = useState(0);
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const [sessionExpired, setSessionExpired] = useState(false);
  const sessionRenewingRef = useRef(false);
  // Monotonic id so an older snapshot response can never overwrite a newer one.
  const refreshId = useRef(0);
  const [activeExecutionId, setActiveExecutionId] = useState<string | null>(() =>
    snapshot.executions.find((e) => ['RUNNING', 'QUEUED'].includes(e.status))?.id ?? snapshot.executions[0]?.id ?? null,
  );
  const inFlightMutations = new Set<string>();
  const request = useCallback(
    async <T,>(url: string, body?: unknown, method = body === undefined ? 'GET' : 'POST'): Promise<T> => {
      // Debounce repeated mutations to the same endpoint to prevent rapid-fire
      // requests (e.g. double-clicking a button, accidental re-submission).
      if (method !== 'GET') {
        const key = `${method}:${url}`;
        if (inFlightMutations.has(key)) throw new Error('Request already in progress');
        inFlightMutations.add(key);
        try {
          return await executeRequest(url, body, method, undefined);
        } finally {
          inFlightMutations.delete(key);
        }
      }
      return executeRequest(url, body, method, undefined);
    },
    [],
  );

  /** Performs the actual HTTP fetch with retries for transient gateway errors. */
  async function executeRequest<T>(
    url: string,
    body: unknown,
    method: string,
    signal: AbortSignal | undefined,
  ): Promise<T> {
    let response: Response;
    for (let attempt = 0; ; attempt++) {
      response = await fetch(`/api${url}`, {
        method,
        credentials: 'same-origin',
        headers: {
          'content-type': 'application/json',
          ...(sessionRef.current ? { 'x-csrf-token': sessionRef.current.csrfToken } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: signal ?? AbortSignal.timeout(30000),
      });
      // Retry transient gateway errors only for idempotent state reads.
      if (method !== 'GET' || ![502, 503, 504].includes(response.status) || attempt >= 2) break;
      await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** attempt));
    }
    const data = await response
      .json()
      .catch(() => ({ error: `Server returned an empty or non-JSON response (HTTP ${response.status})` }));
    if (!response.ok) {
      if (response.status === 401) {
        setSessionExpired(true);
        setSession(null);
        setSnapshot(emptyState());
      }
      throw new Error(
        data.error === 'Validation failed'
          ? `${data.error}: ${(data.details || []).map((d: any) => d.path.join('.') + ': ' + d.message).join('; ')}`
          : data.error || 'Request failed',
      );
    }
    return data;
  }

  const [systemUptime, setSystemUptime] = useState<{ uptime: string }>({ uptime: 'unknown' });

  useEffect(() => {
    let active = true;
    const fetchSystemUptime = async () => {
      try {
        const { getSystemUptime } = await import('../utils/systemUptime');
        const uptime = await getSystemUptime();
        if (active) setSystemUptime(uptime);
      } catch (error) {
        if (active) {
          console.error('Failed to load application uptime', error);
          setSystemUptime({ uptime: 'unknown' });
        }
      }
    };
    fetchSystemUptime();
    const interval = setInterval(fetchSystemUptime, 60000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);
  const refresh = useCallback(async () => {
    const id = ++refreshId.current;
    let next: AppState;
    try {
      next = await request<AppState>('/state');
    } catch (error) {
      // A stale request that failed after a newer refresh succeeded must not
      // surface an error banner for state that is already current.
      if (refreshId.current !== id) return;
      throw error;
    }
    // Concurrent polls and post-mutation refreshes can resolve out of order.
    // Apply only the newest request so a slow response cannot roll state back.
    if (refreshId.current !== id) return;
    setSnapshot(next);
    // Signals bounded collection views to refetch their current page after a
    // mutation or poll, without duplicating heavy collections in the snapshot.
    setRefreshVersion((value) => value + 1);
  }, [request]);
  const fetchCollection = useCallback(
    <T,>(
      kind: CollectionKind,
      query: {
        page?: number;
        pageSize?: number;
        search?: string;
        sort?: string;
        order?: 'asc' | 'desc';
        filters?: Record<string, unknown>;
      } = {},
    ): Promise<CollectionPage<T>> => {
      const page = Math.max(1, Math.floor(query.page ?? 1));
      const pageSize = Math.max(1, Math.floor(query.pageSize ?? 50));
      const params = new URLSearchParams({
        limit: String(pageSize),
        offset: String((page - 1) * pageSize),
      });
      if (query.search) params.set('search', query.search);
      if (query.sort) params.set('sort', query.sort);
      if (query.order) params.set('order', query.order);
      for (const [key, value] of Object.entries(query.filters ?? {})) {
        if (value === undefined || value === null || value === '' || value === 'ALL') continue;
        if (Array.isArray(value)) {
          if (value.length) params.set(key, value.join(','));
        } else params.set(key, String(value));
      }
      return request<CollectionPage<T>>(`/collections/${encodeURIComponent(kind)}?${params}`);
    },
    [request],
  );
  const safely = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setPending((p) => p + 1);
    try {
      setError(null);
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operation failed');
      return undefined;
    } finally {
      setPending((p) => p - 1);
    }
  }, []);
  useEffect(() => {
    let mounted = true;
    request<SessionInfo>('/session')
      .then(async (value) => {
        if (mounted) {
          setSession(value);
          sessionRef.current = value;
          await refresh();
        }
      })
      .catch((e) => {
        if (mounted && e.message !== 'Authentication required' && e.message !== 'Session expired')
          setError(e.message);
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [request, refresh]);
  useEffect(() => {
    if (!session) return;
    const timer = setInterval(() => {
      setClock(Date.now());
      if (sessionRef.current && Date.now() >= new Date(sessionRef.current.expiresAt).getTime()) {
        setSessionExpired(true);
        setSession(null);
        setSnapshot(emptyState());
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [session]);
  useEffect(() => {
    if (!session || sessionRenewingRef.current) return;
    const now = Date.now();
    const expiresAt = new Date(session.expiresAt).getTime();
    const remaining = Math.max(0, Math.floor((expiresAt - now) / 1000));
    if (remaining > SESSION_RENEW_THRESHOLD_SEC || remaining <= 0) return;
    sessionRenewingRef.current = true;
    void request<{ expiresAt: string; csrfToken?: string }>('/session/renew', {})
      .then((result) => {
        setSession((s) => (s ? { ...s, expiresAt: result.expiresAt, csrfToken: result.csrfToken ?? s.csrfToken } : null));
      })
      .catch(() => {})
      .finally(() => {
        sessionRenewingRef.current = false;
      });
  }, [clock, session, request]);
  useEffect(() => {
    if (!session) return;
    let active = true;
    const poll = () => {
      // Idle background tabs do not need the full snapshot every ten seconds.
      // Refresh immediately when the tab becomes visible again.
      if (active && document.visibilityState !== 'hidden') void refresh().catch((e) => setError(e.message));
    };
    const timer = setInterval(poll, 10000);
    const onVisibility = () => {
      if (document.visibilityState === 'visible') poll();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      active = false;
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [!!session, refresh]);
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    document.documentElement.classList.toggle('light', theme === 'light');
    try {
      localStorage.setItem('vulnstream_theme', theme);
    } catch {}
  }, [theme]);
  const login = async (username: string, password: string) =>
    safely(async () => {
      const info = await request<SessionInfo>('/login', { username, password });
      sessionRef.current = info;
      setSession(info);
      setSessionExpired(false);
      await refresh();
      return true;
    });
  const logout = async () =>
    safely(async () => {
      await request('/logout', {});
      sessionRef.current = null;
      setSession(null);
      setSnapshot(emptyState());
      setDraft(null);
      setDailyDigestDraft(null);
      setDailyDigestCustomTemplate(null);
    });
  const requestPasswordReset = (username: string) =>
    safely(
      async () => await request<{ success: boolean; code?: string }>('/password-reset/request', { username }),
    );
  const verifyPasswordReset = (username: string, code: string) =>
    safely(async () => await request<{ success: boolean }>('/password-reset/verify', { username, code }));
  const completePasswordReset = (username: string, code: string, newPassword: string) =>
    safely(
      async () =>
        await request<{ success: boolean }>('/password-reset/complete', { username, code, newPassword }),
    );
  const command = async (action: string, data?: unknown, id?: string) =>
    safely(async () => {
      const result = await request<any>('/commands', { action, data, id });
      return result;
    });
  // A committed mutation is a success even if the follow-up snapshot refresh
  // fails. Surface the stale snapshot separately so destructive actions are not
  // retried blindly because of a transient GET failure.
  const refreshAfterMutation = async () => {
    try {
      await refresh();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'State refresh failed');
    }
  };
  const save = async (action: string, data: unknown, id?: string) => {
    const saved = !!(await command(action, data, id));
    if (saved) await refreshAfterMutation();
    return saved;
  };
  const call = async <T,>(url: string, body: unknown = {}, method = 'POST') =>
    safely(async () => {
      const result = await request<T>(url, body, method);
      await refreshAfterMutation();
      return result;
    });
  const activeExecution = snapshot.executions.find((e) => ['RUNNING', 'QUEUED'].includes(e.status));
  const customization = draft || snapshot.templateCustomization;
  const dailyDigestCustomization =
    dailyDigestDraft || snapshot.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION;
  const dailyDigestTemplate =
    dailyDigestCustomTemplate ||
    (dailyDigestDraft
      ? compileDailyDigestTemplate(dailyDigestDraft)
      : snapshot.dailyDigestTemplate);
  const setDailyDigestCustomTemplatePersisted = (template: string | null) => {
    setDailyDigestCustomTemplate(template);
    try {
      if (template) {
        localStorage.setItem('vulnstream_dailyDigestCustomTemplate', template);
      } else {
        localStorage.removeItem('vulnstream_dailyDigestCustomTemplate');
      }
    } catch {}
  };

  return {
    ...snapshot,
    activeTab,
    setActiveTab: (tab: string) => {
      setActiveTab(tab);
      setMobileNavOpen(false);
    },
    mobileNavOpen,
    setMobileNavOpen,
    theme,
    toggleTheme: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')),
    session,
    loading,
    error,
    sessionExpired,
    pending,
    activeExecutionId,
    setActiveExecutionId,
    clearError: () => setError(null),
    login,
    logout,
    requestPasswordReset,
    verifyPasswordReset,
    completePasswordReset,
    refresh,
    refreshVersion,
    fetchCollection,
    selectedFinding: snapshot.findings.find((f) => f.id === selectedFinding?.id) || selectedFinding,
    setSelectedFinding,
    selectedAdvisory,
    setSelectedAdvisory,
    csrfToken: session?.csrfToken || '',
    sessionTimeRemainingSec: session
      ? Math.max(0, Math.floor((new Date(session.expiresAt).getTime() - clock) / 1000))
      : 0,
    resetSessionTimeout: () =>
      safely(async () => {
        const result = await request<{ expiresAt: string; csrfToken?: string }>('/session/renew', {});
        setSession((s) => (s ? { ...s, expiresAt: result.expiresAt, csrfToken: result.csrfToken ?? s.csrfToken } : null));
      }),
    changePassword: (currentPassword: string, newPassword: string) =>
      safely(async () => {
        await request('/password', { currentPassword, newPassword });
        setSession(null);
        setSnapshot(emptyState());
        return true;
      }),
    listUsers: () => safely(() => request<any[]>('/users')),
    createUser: (data: { username: string; password: string; role: string; email: string }) =>
      safely(() => request('/users', data)),
    // Every field is optional on the server: the account form sends username-free
    // edits of role, email and disabled state independently.
    updateUser: (id: string, data: { role?: string; disabled?: boolean; email?: string | null }) =>
      safely(async () => {
        const result = await request(`/users/${encodeURIComponent(id)}`, data, 'PATCH');
        // An administrator editing their own account changes the cached session
        // (a new reset address must show without a re-login), and a self-role or
        // self-disable edit is refused by the server, so re-reading is harmless.
        if (data.email !== undefined || data.role !== undefined) {
          const current = await request<SessionInfo>('/session');
          setSession(current);
          sessionRef.current = current;
        }
        return result;
      }),
    deleteUser: (id: string) => safely(() => request(`/users/${encodeURIComponent(id)}`, {}, 'DELETE')),
    resetUserPassword: (id: string, password: string) =>
      safely(() => request(`/users/${encodeURIComponent(id)}/reset-password`, { password })),
    fetchEvents: (query: string) =>
      request<{ events: import('../types').OperationalEvent[]; nextCursor: string | null }>(
        `/events?${query}`,
      ),
    health: () => safely(() => request<SystemHealth>('/health')),
    ntpSyncStatus: { synchronized: false, driftMs: 0, lastChecked: '' },
    toggleFeedEnabled: async (id: string) => {
      const result = await command('feed.toggle', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    addFeed: async (
      feed: Omit<
        ThreatFeed,
        'id' | 'healthStatus' | 'lastSync' | 'latencyMs' | 'itemCountLastRun' | 'ssrfValidated'
      >,
    ) => {
      setPending((count) => count + 1);
      try {
        setError(null);
        await request('/commands', { action: 'feed.save', data: feed });
        await refreshAfterMutation();
        return { success: true as const };
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : 'Feed could not be added';
        setError(message);
        return { success: false as const, error: message };
      } finally {
        setPending((count) => count - 1);
      }
    },
    updateFeed: (feed: ThreatFeed) => save('feed.save', feed, feed.id),
    deleteFeed: async (id: string) => {
      const result = await command('feed.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    testFeedConnectivity: async (id: string) =>
      (await call<{ success: boolean; latency: number; error?: string }>(
        `/feeds/${encodeURIComponent(id)}/test`,
      )) || { success: false, latency: 0, error: 'Connectivity test failed' },
    runRetentionCleanup: () => call<RetentionRunResult>('/retention/run'),
    previewRetention: (policy: {
      enabled: boolean;
      retentionHours: number;
      maxArchivedRecords: number;
      retentionMode: 'strict' | 'rolling' | 'checkpoints';
    }) => safely(() => request<RetentionPreview>('/retention/preview', policy)),
    verifyAuditChainRemote: () => safely(() => request<{ verified: boolean; logCount: number; merkleRoot: string }>('/audit/verify')),
    simulateCorrelation: (asset: {
      vendor: string;
      product: string;
      version?: string;
      cpes: string[];
      purls?: string[];
      targetHw?: string;
      assetTag?: string;
    }) => safely(() => request<CorrelationSimulation>('/correlation/simulate', asset)),
    addWatchlistItem: (item: Omit<WatchListItem, 'id' | 'createdAt'>) => save('asset.save', item),
    updateWatchlistItem: (item: WatchListItem) => save('asset.save', item, item.id),
    searchNvdCpes: async (vendor: string, product: string, limit = 50) => {
      const params = new URLSearchParams({ vendor, product, limit: String(limit) });
      return request<NvdCpeSearchResponse>(`/cpes/search?${params}`);
    },
    verifyNvdCpe: async (cpe: string, cpeNameId?: string) => {
      const params = new URLSearchParams({ cpe, limit: '200' });
      if (cpeNameId) params.set('cpeNameId', cpeNameId);
      return request<NvdCpeSearchResponse>(`/cpes/search?${params}`);
    },
    saveRegisteredProducts: async (items: WatchListItem[]) => {
      const result = await command('watchlist.import', items);
      if (result?.success && !result.errors?.length) await refreshAfterMutation();
      return result || { success: false, imported: 0, errors: ['Could not save registered products.'] };
    },
    searchThreatIntelligence: async (vendor: string, product: string, limit = 50, startDate?: string) => {
      const params = new URLSearchParams({ vendor, product, limit: String(limit) });
      if (startDate) params.set('startDate', startDate);
      return request<ThreatSearchResponse>(`/threat/intelligence/search?${params}`);
    },
    searchVulnerabilities: async (params: VulnerabilitySearchParams) => {
      const search = new URLSearchParams();
      if (params.query?.trim()) search.set('query', params.query.trim());
      if (params.productName?.trim()) search.set('productName', params.productName.trim());
      if (params.ecosystem) search.set('ecosystem', params.ecosystem);
      if (params.packageName?.trim()) search.set('package', params.packageName.trim());
      if (params.version?.trim()) search.set('version', params.version.trim());
      if (params.cveId?.trim()) search.set('cveId', params.cveId.trim());
      if (params.limit) search.set('limit', String(params.limit));
      // Defaults to true on the server; only send the opt-out.
      if (params.includeOsint === false) search.set('includeOsint', 'false');
      if (params.watchlistIds?.length)
        search.set('watchlistIds', params.watchlistIds.join(','));
      if (params.fromDate) search.set('fromDate', params.fromDate);
      return request<VulnerabilitySearchResponse>(`/vulnerabilities/search?${search}`);
    },
    fetchThreatAnalytics: async (range: string, limit = 10) => {
      const params = new URLSearchParams({ range, limit: String(limit) });
      return request<ThreatAnalytics>(`/threat/analytics?${params}`);
    },
    simulateCpeMatch: async (payload: {
      assetCpe: string;
      vulnerabilityCpe: string;
      assetVendor: string;
      assetProduct: string;
      versionRange?: {
        versionStartIncluding?: string;
        versionStartExcluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
      };
      assetVersion?: string;
    }) => request<CpeMatchSimulation>('/threat/cpe-simulate', payload, 'POST'),
    toggleWatchlistItemActive: async (id: string) => {
      const updated = !!(await command('asset.toggle', undefined, id));
      if (updated) await refreshAfterMutation();
      return updated;
    },
    deleteWatchlistItem: async (id: string) => {
      const result = await command('asset.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    bulkImportWatchlist: async (items: unknown[]) => {
      const result = await command('asset.import', items);
      if (result && !result.errors?.length) await refreshAfterMutation();
      return result || { imported: 0, errors: ['Import failed. See the error banner.'] };
    },
    addCustomCve: (cve: NormalizedCVE) => save('cve.save', cve),
    updateFindingStatus: async (id: string, status: Finding['status'], note?: string) => {
      const result = await command('finding.status', { status, note }, id);
      if (result?.success) await refreshAfterMutation();
      return result;
    },
    deleteFinding: async (id: string) => {
      const result = await command('finding.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    addRecipient: (rec: Omit<EmailRecipient, 'id' | 'deliverySuccessRate'>) => save('recipient.save', rec),
    updateRecipient: (rec: EmailRecipient) => save('recipient.save', rec, rec.id),
    toggleRecipientEnabled: async (id: string) => {
      const updated = !!(await command('recipient.toggle', undefined, id));
      if (updated) await refreshAfterMutation();
      return updated;
    },
    deleteRecipient: async (id: string) => {
      const result = await command('recipient.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    addWebhook: (hook: Omit<WebhookEndpoint, 'id' | 'deliveryCount'>) => save('webhook.save', hook),
    updateWebhook: (hook: WebhookEndpoint) => save('webhook.save', hook, hook.id),
    toggleWebhookEnabled: async (id: string) => {
      const updated = !!(await command('webhook.toggle', undefined, id));
      if (updated) await refreshAfterMutation();
      return updated;
    },
    deleteWebhook: async (id: string) => {
      const result = await command('webhook.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    testWebhook: async (id: string) =>
      (await call<{ success: boolean; statusCode: number; signature: string }>(
        `/webhooks/${encodeURIComponent(id)}/test`,
      )) || { success: false, statusCode: 0, signature: '' },
    addAlias: (entry: Omit<AliasEntry, 'id' | 'createdAt'>) => save('alias.save', entry),
    updateAlias: (entry: AliasEntry) => save('alias.save', entry, entry.id),
    deleteAlias: async (id: string) => {
      const result = await command('alias.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    promoteAlias: async (id: string) => {
      const result = await command('alias.promote', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    revokeAlias: async (id: string) => {
      const result = await command('alias.revoke', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    resendNotification: (cveId: string, reason: string) => call('/resend', { cveId, reason }),
    sendBulkNotification: (
      findingIds: string[],
      reason: string,
      recipientMode: 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE',
      customEmail?: string,
    ) => call('/send-bulk-notification', { findingIds, reason, recipientMode, customEmail }),
    retryEmailDelivery: (id: string) => call(`/email/${encodeURIComponent(id)}/retry`),
    resendEmailDelivery: (
      id: string,
      data: { recipientMode: 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE'; customEmail?: string; reason?: string },
    ) =>
      call<{ success: boolean; advisoryId: string; queued: number }>(
        `/email/${encodeURIComponent(id)}/resend`,
        data,
      ),
     approveEmailDelivery: (id: string) => call(`/email/${encodeURIComponent(id)}/approve`),
    rejectEmailDelivery: (id: string) => call(`/email/${encodeURIComponent(id)}/reject`),
    editEmailReview: (id: string, edits: Partial<ReviewEdits>) =>
      call<{ success: boolean }>(`/email/${encodeURIComponent(id)}/edit`, edits),
    previewEmailReview: (id: string) =>
      safely(() =>
        request<{
          html: string;
          text: string;
          subject: string;
          edits: ReviewEdits;
          advisoryId: string;
        }>(`/email/${encodeURIComponent(id)}/preview`),
      ),
    previewEmailEdits: (id: string, edits: ReviewEdits) =>
      safely(() =>
        request<{ html: string; text: string; subject: string; edits: ReviewEdits }>(
          `/email/${encodeURIComponent(id)}/preview-edits`,
          edits,
          'POST',
        ),
      ),
    /**
     * Renders the edited email into the exact PDF that delivery would attach.
     * The request helper is JSON-only, so the binary response is fetched
     * directly while preserving the session cookie and CSRF header.
     */
    previewEmailPdf: (id: string, edits: ReviewEdits) =>
      safely(async () => {
        const response = await fetch(`/api/email/${encodeURIComponent(id)}/preview-pdf`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'content-type': 'application/json',
            ...(sessionRef.current ? { 'x-csrf-token': sessionRef.current.csrfToken } : {}),
          },
          body: JSON.stringify(edits),
          signal: AbortSignal.timeout(45000),
        });
        if (!response.ok) {
          const data = await response
            .json()
            .catch(() => ({ error: `PDF preview failed (HTTP ${response.status})` }));
          throw new Error(data.error || `PDF preview failed (HTTP ${response.status})`);
        }
        return response.blob();
      }),
    acknowledgeEmailDelivery: (id: string, reason?: string) =>
      call(`/email/${encodeURIComponent(id)}/acknowledge`, { reason }),
    updateAndSendEmail: (
      id: string,
      data: {
        subject?: string;
        audienceNotice?: string;
        reviewerComment?: string;
        reviewerName?: string;
        customBodyOverride?: string;
        recipientMode: 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE';
        customEmail?: string;
        reason?: string;
      },
    ) =>
      call<{ success: boolean; advisoryId: string; queued: number }>(
        `/email/${encodeURIComponent(id)}/follow-up`,
        data,
      ),
    listEmailQueue: () => safely(() => request<EmailQueueItem[]>('/email-queue')),
    deleteEmailQueueItem: (id: string) => call(`/email/${encodeURIComponent(id)}`, {}, 'DELETE'),
    clearEmailQueue: () => call<{ success: boolean; removed: number; inFlight: number }>('/email-queue', {}, 'DELETE'),
    isPipelineRunning: !!activeExecution,
    currentPipelinePhase: activeExecution ? `${activeExecution.status}: ${activeExecution.id}` : null,
    latestExecution: snapshot.executions[0] || null,
    stopPipelineRun: async (id: string) =>
      (await call<PipelineExecution>(`/pipeline/${encodeURIComponent(id)}/stop`)) || null,
    triggerPipelineRun: async (scopeHours?: number, incrementalFeeds = true) =>
      (await call<PipelineExecution>('/pipeline', { scopeHours, incrementalFeeds })) || null,
    templateCustomization: customization,
    customAdvisoryTemplate: snapshot.customAdvisoryTemplate,
    advisoryTemplate: draft ? compileCustomizedTemplate(draft) : snapshot.advisoryTemplate,
    updateTemplateCustomization: (update: Partial<TemplateCustomization>) =>
      setDraft((prev) => ({ ...snapshot.templateCustomization, ...prev, ...update })),
    saveTemplate: async (customAdvisoryTemplate?: string | null) => {
      const data: { templateCustomization: typeof customization; customAdvisoryTemplate?: string | null } = {
        templateCustomization: customization,
      };
      if (customAdvisoryTemplate !== undefined) data.customAdvisoryTemplate = customAdvisoryTemplate;
      const success = await save('template.save', data);
      if (success) setDraft(null);
      return success;
    },
    setAdvisoryTemplate: (advisoryTemplate: string) =>
      save('template.save', { templateCustomization: customization, customAdvisoryTemplate: advisoryTemplate }),
    dailyDigestCustomization,
    dailyDigestTemplate,
    setDailyDigestCustomTemplate: setDailyDigestCustomTemplatePersisted,
    updateDailyDigestCustomization: (update: Partial<TemplateCustomization>) =>
      setDailyDigestDraft((prev) => ({ ...dailyDigestCustomization, ...prev, ...update })),
    saveDailyDigestTemplate: async (customTemplate?: string | null) => {
      const success = await save('dailyDigestTemplate.save', {
        dailyDigestCustomization,
        dailyDigestCustomTemplate: customTemplate ?? null,
      });
      if (success) {
        setDailyDigestDraft(null);
        if (!customTemplate) setDailyDigestCustomTemplate(null);
      }
      return success;
    },
    sendTestEmail: async (email: string, forceReview = false, html?: string) =>
      (await call<{ success: boolean; message: string }>('/test-email', {
        email,
        forceReview,
        ...(html !== undefined ? { html } : {}),
      })) || {
        success: false,
        message: 'Test could not be queued; see the error banner.',
      },
    sendTestDailyDigestEmail: async (email: string) =>
      (await call<{ success: boolean; message: string }>('/test-daily-digest', { email })) || {
        success: false,
        message: 'Test could not be queued; see the error banner.',
      },
    testEmailConnectivity: async (input: {
      provider: string;
      smtpHost: string;
      smtpPort: number;
      smtpSecurity?: string;
    }) =>
      (await call<{ success: boolean; latency: number; error?: string }>('/test-email-connectivity', input)) || {
        success: false,
        latency: 0,
        error: 'Connectivity test could not be completed; see the error banner.',
      },
    updateSettings: (settings: Partial<AppSettings>) => save('settings.save', settings),
    configureEmailProvider: (configuration: EmailConfiguration) => save('email.configure', configuration),
    systemUptime,
    // Audit events are recorded by server operations, never accepted as client claims.
    addAuditLog: (
      _category: AuditLog['category'],
      _level: AuditLog['level'],
      _event: string,
      _details: string,
    ) => {},
  };
}
type AppContextType = ReturnType<typeof useApplication>;
const AppContext = createContext<AppContextType | undefined>(undefined);
export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AppContext.Provider value={useApplication()}>{children}</AppContext.Provider>
);
export function useApp() {
  const value = useContext(AppContext);
  if (!value) throw new Error('useApp requires AppProvider');
  return value;
}

if (import.meta && import.meta.hot) {
  import.meta.hot.accept(() => {
    window.location.reload();
  });
}
