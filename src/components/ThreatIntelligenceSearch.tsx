import { PageHeading } from './PageHeading';
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useApp } from '../context/AppContext';
import type { NormalizedCVE, ThreatSearchHit } from '../types';
import {
  ENTERPRISE_VENDOR_CATALOG,
  getCatalogProductsForVendor,
  type CatalogProduct,
  type CatalogVendor,
} from '../data/vendorCatalog';
import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Check,
  ChevronDown,
  ChevronRight,
  Clock3,
  Copy,
  Crosshair,
  Database,
  Download,
  ExternalLink,
  FileJson,
  Flame,
  Inbox,
  Key,
  Loader2,
  PackageSearch,
  RotateCcw,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  Tag,
  X,
  Calendar,
} from 'lucide-react';
import { copyText } from '../utils/clipboard';
import { CveLink } from './CveLink';
import { Pagination } from './Pagination';
import { useDialogFocus } from '../hooks/useDialogFocus';
import './threat-search.css';

type SeverityFilter = 'ALL' | NormalizedCVE['cvss']['severity'];
type SortKey = 'cve' | 'score' | 'published';
type SortOrder = 'asc' | 'desc';
type ProductMode = 'catalog' | 'custom';

interface ExecutedSearch {
  vendor: string;
  product: string;
  vendorName: string;
  productName: string;
  at: string;
  limit: number;
  startDate?: string;
}

const panel =
  'ui-panel rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white';
const inputClass =
  'w-full rounded-[10px] border border-zinc-800 bg-zinc-950 min-h-11 py-2.5 px-3 text-sm text-zinc-100 placeholder-zinc-500 transition focus:border-zinc-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/30 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-900';
const labelClass =
  'mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-zinc-400 light:text-zinc-600';
const smallButton =
  'inline-flex min-h-9 items-center justify-center gap-1.5 rounded-[10px] border px-3 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-50';
const smallButtonIdle =
  'border-zinc-800 bg-zinc-950 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200 light:border-zinc-300 light:bg-white light:text-zinc-600 light:hover:bg-zinc-100 light:hover:text-zinc-900';

import { formatDate as fmtDate, formatDateTime as fmtDateTime } from '../utils/dateTime';

const formatDate = (value: string, timezone?: string) => fmtDate(value, timezone);
const formatDateTime = (value: string, timezone?: string) => fmtDateTime(value, timezone);

const SEVERITY_RANK: Record<NormalizedCVE['cvss']['severity'], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

const severityTone = (severity: NormalizedCVE['cvss']['severity']) => {
  switch (severity) {
    case 'CRITICAL':
      return 'border-rose-500/30 bg-rose-500/10 text-rose-300 light:text-rose-800';
    case 'HIGH':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-300 light:text-orange-800';
    case 'MEDIUM':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300 light:text-amber-800';
    case 'LOW':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 light:text-emerald-800';
    default:
      return 'border-zinc-700/60 bg-zinc-800/60 text-zinc-400 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-600';
  }
};

const exploitTone = (status: NormalizedCVE['exploitStatus']) => {
  switch (status) {
    case 'Active Weaponized':
      return 'text-rose-300 light:text-rose-700';
    case 'Reported In Wild':
      return 'text-orange-300 light:text-orange-700';
    case 'POC Available':
      return 'text-amber-300 light:text-amber-700';
    default:
      return 'text-zinc-400 dark:text-zinc-500 light:text-zinc-600';
  }
};

const hasEpss = (epss: NormalizedCVE['epss'] | undefined) =>
  !!epss && (epss.score > 0 || epss.percentile > 0);
const formatEpss = (value: number) => `${(value * 100).toFixed(1)}%`;
const formatPercentile = (value: number) => {
  const percentile = value * 100;
  const rounded = Math.round(percentile);
  const shown = Math.abs(percentile - rounded) < 0.05 ? rounded : Math.round(percentile * 10) / 10;
  const suffix = (() => {
    const mod100 = shown % 100;
    if (mod100 >= 11 && mod100 <= 13) return 'th';
    switch (shown % 10) {
      case 1:
        return 'st';
      case 2:
        return 'nd';
      case 3:
        return 'rd';
      default:
        return 'th';
    }
  })();
  return `${shown}${suffix} pct`;
};

const productPartLabel: Record<CatalogProduct['part'], string> = {
  a: 'Applications',
  o: 'Operating systems',
  h: 'Hardware',
};

const slugify = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'search';

const csvCell = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;

function SeverityBadge({ severity }: { severity: NormalizedCVE['cvss']['severity'] }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${severityTone(severity)}`}
    >
      {severity}
    </span>
  );
}

function KevBadge() {
  return (
    <span
      className="inline-flex items-center gap-0.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] font-medium text-amber-300 light:text-amber-800"
      title="Listed in the CISA Known Exploited Vulnerabilities catalog"
    >
      <Flame className="h-3 w-3" aria-hidden="true" />
      KEV
    </span>
  );
}

function SourceBadge({ source }: { source: ThreatSearchHit['source'] }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-1.5 py-0.5 font-mono text-[10px] font-medium ${
        source === 'NVD_API'
          ? 'border-blue-500/30 bg-blue-500/10 text-blue-300 light:text-blue-800'
          : 'border-teal-500/30 bg-teal-500/10 text-teal-300 light:text-teal-800'
      }`}
    >
      {source === 'NVD_API' ? 'Exact CPE' : 'Keyword'}
    </span>
  );
}

function MetricCard({
  label,
  value,
  hint,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string;
  hint: string;
  icon: React.ComponentType<{ className?: string; 'aria-hidden'?: boolean }>;
  tone: string;
}) {
  return (
    <div className={`${panel} threat-metric p-4`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
            {label}
          </p>
          <p className="mt-1 text-xl font-semibold tabular-nums text-zinc-100 light:text-zinc-900">{value}</p>
          <p className="mt-0.5 truncate text-[11px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
            {hint}
          </p>
        </div>
        <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg ${tone}`}>
          <Icon className="h-4 w-4" aria-hidden={true} />
        </span>
      </div>
    </div>
  );
}

function ThreatDetailDialog({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
  const ref = useDialogFocus(onClose);
  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="true"
      aria-labelledby="threat-detail-title"
      tabIndex={-1}
      className="threat-detail-dialog flex max-h-[calc(100dvh-1.5rem)] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-900 shadow-2xl light:border-zinc-200 light:bg-white"
    >
      {children}
    </div>
  );
}

function ThreatApiKeyDialog({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
  const ref = useDialogFocus(onClose);
  return (
    <div
      className="threat-key-overlay fixed inset-0 z-50 grid place-items-center bg-black/60 p-4 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby="threat-key-title"
        aria-describedby="threat-key-description"
        tabIndex={-1}
        className="threat-key-dialog"
      >
        {children}
      </div>
    </div>
  );
}

export const ThreatIntelligenceSearch: React.FC = () => {
  const { searchThreatIntelligence, feeds, updateFeed } = useApp();

  // Search parameters
  const [vendorQuery, setVendorQuery] = useState('');
  const [vendorSelected, setVendorSelected] = useState('');
  const [vendorOpen, setVendorOpen] = useState(false);
  const [activeVendorIndex, setActiveVendorIndex] = useState(0);
  const vendorBoxRef = useRef<HTMLDivElement>(null);
  const vendorInputRef = useRef<HTMLInputElement>(null);

  const [productMode, setProductMode] = useState<ProductMode>('catalog');
  const [productSelected, setProductSelected] = useState('');
  const [customProduct, setCustomProduct] = useState('');
  const [resultLimit, setResultLimit] = useState(50);
  const [startDate, setStartDate] = useState('');

  // Search lifecycle
  const [results, setResults] = useState<ThreatSearchHit[] | null>(null);
  const [totalResults, setTotalResults] = useState(0);
  const [executedSearch, setExecutedSearch] = useState<ExecutedSearch | null>(null);
  const [loading, setLoading] = useState(false);
  const [searchExpanded, setSearchExpanded] = useState(true);
  const resultsHeadingRef = useRef<HTMLHeadingElement>(null);
  const [error, setError] = useState<string | null>(null);

  // Result controls
  const [resultQuery, setResultQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [kevOnly, setKevOnly] = useState(false);
  const [evidenceFilter, setEvidenceFilter] = useState<'ALL' | 'EXACT' | 'KEYWORD'>('ALL');
  const [sortKey, setSortKey] = useState<SortKey>('score');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Detail / clipboard state
  const [inspect, setInspect] = useState<ThreatSearchHit | null>(null);
  const [copiedIds, setCopiedIds] = useState(false);
  const [copiedDetail, setCopiedDetail] = useState(false);
  const searchSequence = useRef(0);

  // NVD API key dialog
  const [apiKeyDialogOpen, setApiKeyDialogOpen] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [apiKeyMessage, setApiKeyMessage] = useState('');
  const [apiKeySaving, setApiKeySaving] = useState(false);
  const [confirmingApiKey, setConfirmingApiKey] = useState(false);
  useEffect(
    () => () => {
      searchSequence.current++;
    },
    [],
  );

  const nvdFeed = feeds.find((f) => f.type === 'NVD_API' && f.enabled);
  const hasNvdApiKey = nvdFeed && nvdFeed.authType === 'API_KEY' && Boolean(nvdFeed.authSecretKey);

  const openApiKeyDialog = () => {
    setApiKeyInput('');
    setApiKeyMessage('');
    setApiKeyDialogOpen(true);
  };

  const handleSaveApiKey = async () => {
    if (apiKeySaving || !apiKeyInput.trim()) return;
    setConfirmingApiKey(true);
    setApiKeyDialogOpen(false);
  };

  const executeSaveApiKey = async () => {
    setConfirmingApiKey(false);
    setApiKeySaving(true);
    setApiKeyMessage('');
    if (!nvdFeed) {
      setApiKeyMessage('No NVD feed is configured. Add one under Feeds first.');
      setApiKeySaving(false);
      return;
    }
    try {
      const ok = await updateFeed({
        ...nvdFeed,
        authType: 'API_KEY',
        authSecretKey: apiKeyInput.trim(),
      });
      if (ok) {
        setApiKeyMessage('API key saved. Run a new search to pick it up.');
        setApiKeyInput('');
        setApiKeyDialogOpen(false);
      } else {
        setApiKeyMessage('Failed to save API key. Please try again.');
      }
    } catch {
      setApiKeyMessage('Failed to save API key. Please try again.');
    } finally {
      setApiKeySaving(false);
    }
  };

  const selectedVendor = useMemo(
    () => ENTERPRISE_VENDOR_CATALOG.find((vendor) => vendor.normalizedId === vendorSelected),
    [vendorSelected],
  );
  const selectedVendorName = selectedVendor?.name ?? vendorSelected;
  const catalogProducts = useMemo(
    () => (selectedVendor ? getCatalogProductsForVendor(selectedVendor.normalizedId) : []),
    [selectedVendor],
  );
  const isCustomVendor = Boolean(vendorSelected) && !selectedVendor;

  const vendorMatches = useMemo(() => {
    const query = vendorQuery.trim().toLowerCase();
    const matches = query
      ? ENTERPRISE_VENDOR_CATALOG.filter(
          (vendor) =>
            vendor.name.toLowerCase().includes(query) ||
            vendor.normalizedId.toLowerCase().includes(query) ||
            vendor.aliases.some((alias) => alias.toLowerCase().includes(query)),
        )
      : ENTERPRISE_VENDOR_CATALOG;
    return matches.slice(0, 50);
  }, [vendorQuery]);

  const trimmedVendorQuery = vendorQuery.trim();
  const exactVendorMatch = vendorMatches.some(
    (vendor) =>
      vendor.normalizedId === trimmedVendorQuery.toLowerCase() ||
      vendor.name.toLowerCase() === trimmedVendorQuery.toLowerCase(),
  );
  const showCustomVendor = trimmedVendorQuery.length > 0 && !exactVendorMatch;
  const vendorOptionCount = vendorMatches.length + (showCustomVendor ? 1 : 0);
  const activeVendorOption = vendorOptionCount > 0 ? Math.min(activeVendorIndex, vendorOptionCount - 1) : 0;

  const useCatalog = productMode === 'catalog' && catalogProducts.length > 0;
  const selectedCatalogProduct = useCatalog
    ? catalogProducts.find((product) => product.normalizedId === productSelected)
    : undefined;
  const effectiveProduct = useCatalog ? productSelected : customProduct.trim();
  const effectiveProductName = useCatalog ? (selectedCatalogProduct?.name ?? '') : customProduct.trim();
  const canSearch = Boolean(vendorSelected && effectiveProduct) && !loading;

  const draftChanged =
    !!executedSearch &&
    (executedSearch.vendor !== vendorSelected ||
      executedSearch.product !== effectiveProduct ||
      executedSearch.limit !== resultLimit ||
      (executedSearch.startDate || '') !== startDate);

  useEffect(() => {
    setActiveVendorIndex(0);
  }, [vendorQuery]);

  useEffect(() => {
    if (vendorOpen)
      document.getElementById(`vendor-option-${activeVendorOption}`)?.scrollIntoView({ block: 'nearest' });
  }, [vendorOpen, activeVendorOption]);

  useEffect(() => {
    if (!vendorOpen) return;
    const handlePointerDown = (event: MouseEvent) => {
      if (!vendorBoxRef.current?.contains(event.target as Node)) setVendorOpen(false);
    };
    document.addEventListener('mousedown', handlePointerDown);
    return () => document.removeEventListener('mousedown', handlePointerDown);
  }, [vendorOpen]);

  useEffect(() => {
    setPage(1);
  }, [resultQuery, severityFilter, kevOnly, evidenceFilter, sortKey, sortOrder]);

  useEffect(() => {
    if (loading || !results || searchExpanded) return;
    resultsHeadingRef.current?.focus({ preventScroll: true });
  }, [loading, results, searchExpanded]);

  const resetResultControls = () => {
    setResultQuery('');
    setSeverityFilter('ALL');
    setKevOnly(false);
    setEvidenceFilter('ALL');
    setSortKey('score');
    setSortOrder('desc');
    setPage(1);
  };

  const chooseCatalogVendor = (vendor: CatalogVendor) => {
    const products = getCatalogProductsForVendor(vendor.normalizedId);
    setVendorSelected(vendor.normalizedId);
    setVendorQuery('');
    setVendorOpen(false);
    setActiveVendorIndex(0);
    setProductSelected('');
    setCustomProduct('');
    setProductMode(products.length > 0 ? 'catalog' : 'custom');
    setError(null);
  };

  const chooseCustomVendor = (value: string) => {
    setVendorSelected(value);
    setVendorQuery('');
    setVendorOpen(false);
    setActiveVendorIndex(0);
    setProductSelected('');
    setCustomProduct('');
    setProductMode('custom');
    setError(null);
  };

  const chooseVendorOption = (index: number) => {
    if (index < vendorMatches.length) {
      chooseCatalogVendor(vendorMatches[index]);
    } else if (showCustomVendor) {
      chooseCustomVendor(trimmedVendorQuery);
    }
  };

  const clearVendor = () => {
    setVendorSelected('');
    setVendorQuery('');
    setVendorOpen(false);
    setProductSelected('');
    setCustomProduct('');
    setProductMode('catalog');
    requestAnimationFrame(() => vendorInputRef.current?.focus());
  };

  const handleVendorKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setVendorOpen(true);
      if (vendorOptionCount > 0)
        setActiveVendorIndex((index) => (vendorOpen ? (index + 1) % vendorOptionCount : 0));
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setVendorOpen(true);
      if (vendorOptionCount > 0)
        setActiveVendorIndex((index) =>
          vendorOpen ? (index - 1 + vendorOptionCount) % vendorOptionCount : vendorOptionCount - 1,
        );
      return;
    }
    if (event.key === 'Tab') setVendorOpen(false);
    if (event.key === 'Escape') {
      setVendorOpen(false);
      setActiveVendorIndex(0);
      return;
    }
    if (event.key === 'Enter') {
      if (vendorOpen && vendorOptionCount > 0) {
        event.preventDefault();
        chooseVendorOption(activeVendorOption);
      } else if (trimmedVendorQuery) {
        event.preventDefault();
        chooseCustomVendor(trimmedVendorQuery);
      }
      return;
    }
  };

  const handleSearch = async () => {
    if (!canSearch) return;
    const sequence = ++searchSequence.current;
    const vendor = vendorSelected;
    const product = effectiveProduct;
    const vendorName = selectedVendorName || vendor;
    const productName = effectiveProductName || product;

    setLoading(true);
    setSearchExpanded(true);
    setError(null);
    setResults(null);
    setExecutedSearch(null);
    setCopiedIds(false);
    resetResultControls();

    try {
      const response = await searchThreatIntelligence(vendor, product, resultLimit, startDate || undefined);
      if (sequence !== searchSequence.current) return;
      setResults(response.hits);
      setTotalResults(response.totalResults);
      setExecutedSearch({
        vendor,
        product,
        vendorName,
        productName,
        at: new Date().toISOString(),
        limit: resultLimit,
        startDate: startDate || undefined,
      });
      setSearchExpanded(Boolean(response.rateLimited));
      if (response.rateLimited) {
        setError(
          `NVD rate limit reached. NVD limits anonymous requests; wait before retrying${
            response.apiKeyUsed ? ' or lower the result count.' : ' or add an API key under Feeds.'
          }`,
        );
      }
    } catch (caught) {
      if (sequence !== searchSequence.current) return;
      const message = caught instanceof Error ? caught.message : 'Search failed.';
      if (/rate limit/i.test(message)) {
        const noApiKey = /no API key loaded/i.test(message);
        setError(
          `${message}. ${
            noApiKey
              ? 'The NVD API key was not loaded; verify it under Feeds or check server logs.'
              : 'Wait a few seconds before retrying.'
          }`,
        );
      } else if (/temporarily unavailable|failed/i.test(message)) {
        // NVD could not be reached or answered with an error. Say so plainly and
        // keep the query on screen: the previous behaviour collapsed this into
        // an empty result set, which read as "no such vulnerability exists".
        setError(
          `NVD could not be queried (${message.replace(/\.$/, '')}). ` +
            'This is an upstream problem, not a problem with your query. Retry shortly; if it persists, check the server log for nvd_cpe_search_error / nvd_keyword_fallback_error entries.',
        );
      } else {
        setError(message);
      }
    } finally {
      if (sequence === searchSequence.current) setLoading(false);
    }
  };

  const resetSearch = () => {
    searchSequence.current++;
    setLoading(false);
    setSearchExpanded(true);
    setInspect(null);
    setVendorSelected('');
    setVendorQuery('');
    setVendorOpen(false);
    setProductMode('catalog');
    setProductSelected('');
    setCustomProduct('');
    setResultLimit(50);
    setStartDate('');
    setResults(null);
    setTotalResults(0);
    setExecutedSearch(null);
    setError(null);
    setCopiedIds(false);
    resetResultControls();
  };

  const filteredResults = useMemo(() => {
    if (!results) return [];
    const query = resultQuery.trim().toLowerCase();
    const filtered = results.filter((hit) => {
      if (severityFilter !== 'ALL' && hit.cve.cvss.severity !== severityFilter) return false;
      if (kevOnly && !hit.cve.cisaKev?.isKev) return false;
      if (evidenceFilter === 'EXACT' && hit.source !== 'NVD_API') return false;
      if (evidenceFilter === 'KEYWORD' && hit.source === 'NVD_API') return false;
      if (!query) return true;
      return [
        hit.cve.cveId,
        hit.cve.title,
        hit.cve.description,
        hit.cve.cvss.severity,
        hit.source,
        ...hit.cve.cwe,
        ...hit.matchingCpes,
      ]
        .join(' ')
        .toLowerCase()
        .includes(query);
    });

    const direction = sortOrder === 'asc' ? 1 : -1;
    return filtered.sort((left, right) => {
      if (sortKey === 'cve') {
        return direction * left.cve.cveId.localeCompare(right.cve.cveId);
      }
      if (sortKey === 'published') {
        const leftDate = new Date(left.cve.publishedDate).getTime() || 0;
        const rightDate = new Date(right.cve.publishedDate).getTime() || 0;
        return direction * (leftDate - rightDate);
      }
      const severityDelta = SEVERITY_RANK[left.cve.cvss.severity] - SEVERITY_RANK[right.cve.cvss.severity];
      if (severityDelta !== 0) return direction * severityDelta;
      return direction * (left.cve.cvss.score - right.cve.cvss.score);
    });
  }, [results, resultQuery, severityFilter, kevOnly, evidenceFilter, sortKey, sortOrder]);

  const summary = useMemo(() => {
    if (!results) return null;
    let critical = 0;
    let high = 0;
    let kev = 0;
    let exact = 0;
    for (const hit of results) {
      if (hit.cve.cvss.severity === 'CRITICAL') critical++;
      if (hit.cve.cvss.severity === 'HIGH') high++;
      if (hit.cve.cisaKev?.isKev) kev++;
      if (hit.source === 'NVD_API') exact++;
    }
    return {
      critical,
      high,
      kev,
      exact,
      total: results.length,
      exactPct: results.length ? Math.round((exact / results.length) * 100) : 0,
    };
  }, [results]);

  const pageCount = Math.max(1, Math.ceil(filteredResults.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageResults = filteredResults.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const hasResultFilters =
    resultQuery.trim().length > 0 || severityFilter !== 'ALL' || kevOnly || evidenceFilter !== 'ALL';

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortOrder((order) => (order === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortKey(key);
      setSortOrder('desc');
    }
  };

  const sortIcon = (key: SortKey) => {
    if (sortKey !== key) return <ArrowUpDown className="h-3 w-3 opacity-50" aria-hidden="true" />;
    return sortOrder === 'asc' ? (
      <ArrowUp className="h-3 w-3" aria-hidden="true" />
    ) : (
      <ArrowDown className="h-3 w-3" aria-hidden="true" />
    );
  };
  const ariaSort = (key: SortKey) =>
    sortKey === key ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none';

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const exportBaseName = executedSearch
    ? `threat-intel-${slugify(executedSearch.vendorName)}-${slugify(executedSearch.productName)}`
    : 'threat-intel-search';

  const handleCopyIds = async () => {
    if (!filteredResults.length) return;
    const success = await copyText(filteredResults.map((hit) => hit.cve.cveId).join('\n'));
    if (success) {
      setCopiedIds(true);
      setTimeout(() => setCopiedIds(false), 2000);
    }
  };

  const handleExportJson = () => {
    if (!filteredResults.length) return;
    const payload = {
      query: executedSearch,
      exportedAt: new Date().toISOString(),
      totalResults,
      returned: results?.length ?? 0,
      exported: filteredResults.length,
      filters: {
        text: resultQuery.trim() || null,
        severity: severityFilter === 'ALL' ? null : severityFilter,
        evidence: evidenceFilter === 'ALL' ? null : evidenceFilter,
        kevOnly,
        sort: `${sortKey}:${sortOrder}`,
      },
      hits: filteredResults,
    };
    downloadFile(
      JSON.stringify(payload, null, 2),
      `${exportBaseName}-${new Date().toISOString().slice(0, 10)}.json`,
      'application/json',
    );
  };

  const handleExportCsv = () => {
    if (!filteredResults.length) return;
    const header = [
      'CVE ID',
      'Title',
      'Severity',
      'CVSS score',
      'CVSS version',
      'CVSS vector',
      'CISA KEV',
      'KEV date added',
      'EPSS score',
      'EPSS percentile',
      'Published',
      'Modified',
      'Source',
      'Matched CPEs',
      'CWE',
      'Description',
    ];
    const rows = filteredResults.map((hit) =>
      [
        hit.cve.cveId,
        hit.cve.title,
        hit.cve.cvss.severity,
        hit.cve.cvss.score,
        hit.cve.cvss.version,
        hit.cve.cvss.vector,
        hit.cve.cisaKev?.isKev ? 'Yes' : 'No',
        hit.cve.cisaKev?.dateAdded ?? '',
        hasEpss(hit.cve.epss) ? (hit.cve.epss?.score ?? 0) : '',
        hasEpss(hit.cve.epss) ? (hit.cve.epss?.percentile ?? 0) : '',
        hit.cve.publishedDate,
        hit.cve.modifiedDate,
        hit.source,
        hit.matchingCpes.join(' '),
        hit.cve.cwe.join(' '),
        hit.cve.description,
      ]
        .map(csvCell)
        .join(','),
    );
    downloadFile(
      [header.map(csvCell).join(','), ...rows].join('\r\n'),
      `${exportBaseName}-${new Date().toISOString().slice(0, 10)}.csv`,
      'text/csv;charset=utf-8',
    );
  };

  const handleCopyDetail = async () => {
    if (!inspect) return;
    const success = await copyText(JSON.stringify(inspect, null, 2));
    if (success) {
      setCopiedDetail(true);
      setTimeout(() => setCopiedDetail(false), 2000);
    }
  };

  const vendorOptionId = (index: number) => `vendor-option-${index}`;
  const activeOptionId = vendorOpen && vendorOptionCount > 0 ? vendorOptionId(activeVendorOption) : undefined;

  return (
    <div className="threat-search-page space-y-6">
      <PageHeading page="threat-intelligence-search">
        Investigate product vulnerabilities, assess exploit risk, and export the evidence for your team.
      </PageHeading>

      {/* Search parameters */}
      <section
        className={`${panel} threat-search-form ${searchExpanded ? 'is-expanded' : 'is-compact'} p-5 sm:p-6`}
        aria-labelledby="threat-search-heading"
      >
        <div className="threat-search-header">
          <div className="threat-section-title">
            <span className="threat-section-icon">
              <Search size={19} strokeWidth={1.7} aria-hidden="true" />
            </span>
            <div>
              <h2
                id="threat-search-heading"
                className="text-sm font-semibold text-zinc-100 light:text-zinc-900"
              >
                {searchExpanded ? 'Investigate a product' : 'Current investigation'}
              </h2>
              <p className="mt-0.5 text-[11px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                {searchExpanded
                  ? 'Search the National Vulnerability Database by vendor and product.'
                  : 'Review the search scope or edit the parameters to investigate another product.'}
              </p>
            </div>
          </div>
          <div className="threat-search-header-actions">
            <span className="threat-source-label">
              <Database className="h-3.5 w-3.5" aria-hidden="true" />
              NVD · On-demand search
            </span>
            {executedSearch && !loading && (
              <button
                type="button"
                className="ui-secondary threat-edit-search"
                aria-expanded={searchExpanded}
                aria-controls="threat-search-parameters"
                onClick={() => {
                  setSearchExpanded((value) => !value);
                  if (!searchExpanded)
                    requestAnimationFrame(() =>
                      document.getElementById('threat-product')?.focus({ preventScroll: true }),
                    );
                }}
              >
                <SlidersHorizontal size={14} aria-hidden="true" />
                {searchExpanded ? 'Hide parameters' : 'Edit search'}
                <ChevronDown size={14} className={searchExpanded ? 'is-open' : ''} aria-hidden="true" />
              </button>
            )}
          </div>
        </div>

        {executedSearch && !searchExpanded && (
          <div className="threat-query-summary">
            <div className="threat-query-product">
              <PackageSearch size={19} aria-hidden="true" />
              <div>
                <span>{executedSearch.vendorName}</span>
                <strong>{executedSearch.productName}</strong>
              </div>
            </div>
            <dl>
              <div>
                <dt>Result limit</dt>
                <dd>{executedSearch.limit}</dd>
              </div>
              <div>
                <dt>Published from</dt>
                <dd>{executedSearch.startDate ? formatDate(executedSearch.startDate) : 'Any date'}</dd>
              </div>
            </dl>
            {draftChanged && (
              <p className="threat-query-draft">
                <AlertCircle size={14} aria-hidden="true" />
                Parameters changed. Edit search to run the updated query.
              </p>
            )}
          </div>
        )}
        <form
          id="threat-search-parameters"
          hidden={!searchExpanded}
          role="search"
          aria-label="Search vulnerability intelligence"
          onSubmit={(event) => {
            event.preventDefault();
            void handleSearch();
          }}
        >
          <div className="threat-search-fields grid gap-5 lg:grid-cols-14">
            {/* Vendor */}
            <div className="threat-vendor-field">
              <label htmlFor="threat-vendor" className={labelClass}>
                <span className="threat-field-number" aria-hidden="true">
                  01
                </span>{' '}
                Vendor
              </label>
              {vendorSelected ? (
                <div className="threat-selected-vendor flex min-h-[42px] items-center justify-between gap-2 rounded-[10px] border border-zinc-800 bg-zinc-950 px-3 light:border-zinc-300 light:bg-zinc-50">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-zinc-100 light:text-zinc-900">
                      {selectedVendorName}
                    </p>
                    <p className="truncate font-mono text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                      {vendorSelected}
                      {isCustomVendor ? ' · custom vendor' : ' · catalog vendor'}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={clearVendor}
                    aria-label="Clear vendor"
                    className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-zinc-400 dark:text-zinc-500 light:text-zinc-600 transition hover:bg-zinc-800 hover:text-zinc-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/50 light:hover:bg-zinc-200 light:hover:text-zinc-900 light:focus-visible:ring-blue-500/30"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>
              ) : (
                <div ref={vendorBoxRef} className="relative">
                  <Search
                    className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400 dark:text-zinc-500 light:text-zinc-600"
                    aria-hidden="true"
                  />
                  <input
                    id="threat-vendor"
                    ref={vendorInputRef}
                    type="text"
                    role="combobox"
                    aria-expanded={vendorOpen}
                    aria-controls={vendorOpen ? 'vendor-listbox' : undefined}
                    aria-autocomplete="list"
                    aria-activedescendant={activeOptionId}
                    autoComplete="off"
                    value={vendorQuery}
                    onChange={(event) => {
                      setVendorQuery(event.target.value);
                      setVendorOpen(true);
                    }}
                    onFocus={() => setVendorOpen(true)}
                    onKeyDown={handleVendorKeyDown}
                    placeholder="Search the vendor catalog…"
                    className={`${inputClass} pl-9 pr-9`}
                  />
                  <ChevronDown
                    className={`pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400 dark:text-zinc-500 light:text-zinc-600 transition-transform ${vendorOpen ? 'rotate-180' : ''}`}
                    aria-hidden="true"
                  />
                  {vendorOpen && (
                    <div className="absolute left-0 right-0 top-full z-30 mt-2 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900 shadow-2xl light:border-zinc-200 light:bg-white">
                      {vendorOptionCount > 0 ? (
                        <div
                          id="vendor-listbox"
                          role="listbox"
                          aria-label="Vendor catalog"
                          className="max-h-72 overflow-y-auto py-1"
                        >
                          {vendorMatches.map((vendor, index) => (
                            <button
                              key={vendor.normalizedId}
                              id={vendorOptionId(index)}
                              type="button"
                              role="option"
                              tabIndex={-1}
                              aria-selected={index === activeVendorOption}
                              onMouseEnter={() => setActiveVendorIndex(index)}
                              onMouseDown={(event) => event.preventDefault()}
                              onClick={() => chooseCatalogVendor(vendor)}
                              className={`flex w-full items-start justify-between gap-3 px-3 py-2 text-left transition ${
                                index === activeVendorOption
                                  ? 'bg-blue-500/10 text-zinc-100 light:bg-blue-50 light:text-zinc-900'
                                  : 'text-zinc-300 hover:bg-zinc-800/70 light:text-zinc-700 light:hover:bg-zinc-100'
                              }`}
                            >
                              <span className="min-w-0">
                                <span className="block truncate text-sm font-medium">{vendor.name}</span>
                                <span className="mt-0.5 block truncate font-mono text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                                  {vendor.normalizedId}
                                  {vendor.aliases.length > 0 ? ` · ${vendor.aliases.join(', ')}` : ''}
                                </span>
                              </span>
                              <span className="shrink-0 text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                                {vendor.products.length} products
                              </span>
                            </button>
                          ))}
                          {showCustomVendor && (
                            <button
                              id={vendorOptionId(vendorMatches.length)}
                              type="button"
                              role="option"
                              tabIndex={-1}
                              aria-selected={activeVendorOption === vendorMatches.length}
                              onMouseEnter={() => setActiveVendorIndex(vendorMatches.length)}
                              onMouseDown={(event) => event.preventDefault()}
                              onClick={() => chooseCustomVendor(trimmedVendorQuery)}
                              className={`flex w-full flex-col items-start gap-0.5 border-t border-zinc-800/80 px-3 py-2 text-left transition light:border-zinc-200 ${
                                activeVendorOption === vendorMatches.length
                                  ? 'bg-blue-500/10 text-zinc-100 light:bg-blue-50 light:text-zinc-900'
                                  : 'text-zinc-300 hover:bg-zinc-800/70 light:text-zinc-700 light:hover:bg-zinc-100'
                              }`}
                            >
                              <span className="text-sm font-medium">
                                Use “{trimmedVendorQuery}” as a custom vendor
                              </span>
                              <span className="text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                                Query NVD with this free-text vendor name
                              </span>
                            </button>
                          )}
                        </div>
                      ) : (
                        <p
                          className="px-3 py-3 text-xs text-zinc-400 dark:text-zinc-500 light:text-zinc-600"
                          role="status"
                        >
                          No catalog vendor matches. Type a name and press Enter to search it as a custom
                          vendor.
                        </p>
                      )}
                      <div className="border-t border-zinc-800/80 px-3 py-2 text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600 light:border-zinc-200">
                        Use arrow keys to navigate · Enter to select
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Product */}
            <div className="threat-product-field">
              <div className="threat-product-heading flex flex-wrap items-center justify-between gap-2">
                <label htmlFor="threat-product" className={labelClass}>
                  <span className="threat-field-number" aria-hidden="true">
                    02
                  </span>{' '}
                  Product
                </label>
                {selectedVendor && catalogProducts.length > 0 && (
                  <div className="mb-1.5 inline-flex rounded-lg border border-zinc-800 bg-zinc-950 p-0.5 light:border-zinc-300 light:bg-zinc-100">
                    <button
                      type="button"
                      aria-pressed={productMode === 'catalog'}
                      onClick={() => setProductMode('catalog')}
                      className={`rounded-md px-2 py-0.5 text-[10px] font-medium transition ${
                        productMode === 'catalog'
                          ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-white light:text-zinc-900'
                          : 'text-zinc-400 dark:text-zinc-500 light:text-zinc-600 hover:text-zinc-300 light:hover:text-zinc-700'
                      }`}
                    >
                      Catalog
                    </button>
                    <button
                      type="button"
                      aria-pressed={productMode === 'custom'}
                      onClick={() => setProductMode('custom')}
                      className={`rounded-md px-2 py-0.5 text-[10px] font-medium transition ${
                        productMode === 'custom'
                          ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-white light:text-zinc-900'
                          : 'text-zinc-400 dark:text-zinc-500 light:text-zinc-600 hover:text-zinc-300 light:hover:text-zinc-700'
                      }`}
                    >
                      Custom
                    </button>
                  </div>
                )}
              </div>

              {!vendorSelected ? (
                <div className="threat-product-placeholder flex min-h-[42px] items-center rounded-[10px] border border-dashed border-zinc-800 px-3 text-xs text-zinc-400 dark:text-zinc-500 light:text-zinc-600 light:border-zinc-300">
                  Select a vendor first
                </div>
              ) : useCatalog ? (
                <>
                  <select
                    id="threat-product"
                    value={productSelected}
                    onChange={(event) => setProductSelected(event.target.value)}
                    className={`${inputClass} px-3`}
                  >
                    <option value="">Select a catalog product</option>
                    {(['a', 'o', 'h'] as const).map((part) => {
                      const group = catalogProducts.filter((product) => product.part === part);
                      if (group.length === 0) return null;
                      return (
                        <optgroup key={part} label={productPartLabel[part]}>
                          {group.map((product) => (
                            <option key={product.normalizedId} value={product.normalizedId}>
                              {product.name}
                            </option>
                          ))}
                        </optgroup>
                      );
                    })}
                  </select>
                  <p className="mt-1 truncate text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                    {selectedCatalogProduct?.description ||
                      'Choose the product that matches the affected asset.'}
                  </p>
                </>
              ) : (
                <>
                  <input
                    id="threat-product"
                    type="text"
                    value={customProduct}
                    onChange={(event) => setCustomProduct(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') {
                        event.preventDefault();
                        void handleSearch();
                      }
                    }}
                    placeholder="Enter a product name, e.g. Apache HTTP Server"
                    className={`${inputClass} px-3`}
                  />
                  <p className="mt-1 text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                    {isCustomVendor
                      ? 'Custom vendors have no catalog products; enter the NVD product name.'
                      : 'Use a custom product when it is not listed in the catalog.'}
                  </p>
                </>
              )}
            </div>

            <div className="threat-search-options">
              <div className="threat-scope-heading">
                <SlidersHorizontal size={16} aria-hidden="true" />
                <div>
                  <h3>Search scope</h3>
                  <p>Set a result limit and optional publication date.</p>
                </div>
              </div>
              {/* Limit */}
              <div className="threat-limit-field">
                <label htmlFor="threat-limit" className={labelClass}>
                  Max results
                </label>
                <select
                  id="threat-limit"
                  value={resultLimit}
                  onChange={(event) => setResultLimit(Number(event.target.value))}
                  className={`${inputClass} px-3`}
                >
                  {[25, 50, 100, 200].map((limit) => (
                    <option key={limit} value={limit}>
                      {limit}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                  Per search
                </p>
              </div>

              {/* Scan start date */}
              <div className="threat-date-field">
                <label htmlFor="threat-start-date" className={labelClass}>
                  Published from
                </label>
                <div className="relative">
                  <input
                    id="threat-start-date"
                    type="date"
                    value={startDate}
                    max={new Date().toISOString().slice(0, 10)}
                    onChange={(event) => setStartDate(event.target.value)}
                    placeholder="YYYY-MM-DD"
                    className={`${inputClass} px-3`}
                  />
                </div>
                <p className="mt-1 text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                  Only CVEs published on or after this date
                  {startDate && (
                    <button
                      type="button"
                      aria-label="Clear start date"
                      onClick={() => setStartDate('')}
                      className="ml-2 text-blue-400 light:text-blue-700 hover:underline"
                    >
                      Clear
                    </button>
                  )}
                </p>
              </div>
            </div>
          </div>
          <div className="threat-examples">
            <span>Common products</span>
            {[
              { vendor: 'microsoft', product: 'windows_server_2025', label: 'Windows Server 2025' },
              { vendor: 'fortinet', product: 'fortios', label: 'Fortinet FortiOS' },
              { vendor: 'apache', product: 'http_server', label: 'Apache HTTP Server' },
            ].map((example) => (
              <button
                type="button"
                key={example.product}
                aria-pressed={vendorSelected === example.vendor && effectiveProduct === example.product}
                disabled={loading}
                onClick={() => {
                  const vendor = ENTERPRISE_VENDOR_CATALOG.find(
                    (item) => item.normalizedId === example.vendor,
                  );
                  if (vendor) {
                    chooseCatalogVendor(vendor);
                    setProductSelected(example.product);
                  }
                }}
              >
                {example.label}
                <ChevronRight size={13} aria-hidden="true" />
              </button>
            ))}
          </div>
          <div className="threat-search-actions">
            <div className={`threat-search-context ${draftChanged ? 'is-changed' : ''}`} role="status">
              <Crosshair className="h-4 w-4 shrink-0" aria-hidden="true" />
              <p>
                {draftChanged
                  ? 'Selection changed. Run a new search to update your results.'
                  : !vendorSelected
                    ? 'Choose a vendor and product to begin your investigation.'
                    : !effectiveProduct
                      ? 'Choose a catalog product or enter a custom product name.'
                      : 'Your search is ready. Results include CPE and keyword match evidence.'}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              {(vendorSelected || results || error || loading) && (
                <button type="button" onClick={resetSearch} className={`${smallButton} ${smallButtonIdle}`}>
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" /> Reset
                </button>
              )}
              <button
                type="button"
                onClick={openApiKeyDialog}
                className={`${smallButton} ${smallButtonIdle} ${hasNvdApiKey ? 'border-emerald-700 bg-emerald-950/30 text-emerald-300 hover:border-emerald-600 light:border-emerald-300 light:bg-emerald-50 light:text-emerald-700' : ''}`}
                title={hasNvdApiKey ? 'NVD API key configured · click to change' : 'Add NVD API key'}
              >
                <Key className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{hasNvdApiKey ? 'API key' : 'Add API key'}</span>
              </button>
              <button type="submit" disabled={!canSearch} className="ui-primary threat-search-submit">
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                ) : (
                  <Search className="h-4 w-4" aria-hidden="true" />
                )}
                {loading ? 'Searching NVD…' : 'Search intelligence'}
              </button>
            </div>
          </div>
        </form>
      </section>

      {/* NVD API key configuration dialog */}
      {apiKeyDialogOpen && (
        <ThreatApiKeyDialog
          onClose={() => {
            if (!apiKeySaving) setApiKeyDialogOpen(false);
          }}
        >
          <form
            aria-busy={apiKeySaving}
            onSubmit={(event) => {
              event.preventDefault();
              void handleSaveApiKey();
            }}
          >
            <header className="threat-key-header">
              <span className="threat-section-icon">
                <Key size={19} aria-hidden="true" />
              </span>
              <div>
                <p className="threat-key-eyebrow">Search configuration</p>
                <h2 id="threat-key-title">NVD API key</h2>
              </div>
              <button
                type="button"
                aria-label="Close API key settings"
                disabled={apiKeySaving}
                onClick={() => setApiKeyDialogOpen(false)}
                className="threat-key-close"
              >
                <X size={18} aria-hidden="true" />
              </button>
            </header>
            <div className="threat-key-body">
              <p id="threat-key-description">
                {hasNvdApiKey
                  ? 'An API key is configured. Enter a new key to replace it for future searches.'
                  : 'Configure the API key for your NVD feed. You can also search without a key.'}
              </p>
              <label htmlFor="threat-api-key">{hasNvdApiKey ? 'Replacement API key' : 'API key'}</label>
              <input
                id="threat-api-key"
                type="password"
                autoComplete="off"
                value={apiKeyInput}
                disabled={apiKeySaving}
                onChange={(event) => setApiKeyInput(event.target.value)}
                placeholder="Enter your NVD API key"
                maxLength={256}
                className={inputClass}
              />
              <p className="threat-key-hint">This updates the enabled NVD feed in Threat feeds.</p>
              {apiKeyMessage && (
                <p
                  role={apiKeyMessage.includes('saved') ? 'status' : 'alert'}
                  className={`threat-key-feedback ${apiKeyMessage.includes('saved') ? 'is-success' : ''}`}
                >
                  {apiKeyMessage}
                </p>
              )}
            </div>
            <footer className="threat-key-footer">
              <button
                type="button"
                disabled={apiKeySaving}
                onClick={() => setApiKeyDialogOpen(false)}
                className="ui-secondary"
              >
                {apiKeyMessage.includes('saved') ? 'Done' : 'Cancel'}
              </button>
              <button type="button" disabled={apiKeySaving || !apiKeyInput.trim()} onClick={handleSaveApiKey} className="ui-primary">
                {apiKeySaving ? (
                  <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                ) : (
                  <Key size={14} aria-hidden="true" />
                )}
                {apiKeySaving ? 'Saving…' : 'Save key'}
              </button>
            </footer>
          </form>
        </ThreatApiKeyDialog>
      )}

      {/* Confirmation modal for saving API key */}
      {confirmingApiKey && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmingApiKey(false);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-api-key-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-api-key-title" className="text-sm font-semibold">
              Save NVD API key?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This will replace the configured API key for your NVD feed and persist it to the server.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                className="ui-secondary"
                onClick={() => setConfirmingApiKey(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500 disabled:opacity-60"
                disabled={apiKeySaving}
                onClick={() => void executeSaveApiKey()}
              >
                {apiKeySaving ? 'Saving…' : 'Confirm save'}
              </button>
            </div>
          </section>
        </div>
      )}

      {/* Results placeholder before the first search */}
      {!results && !loading && !error && (
        <section className="threat-search-placeholder" aria-label="Search results">
          <p>No search run yet</p>
          <span>Results will appear here.</span>
        </section>
      )}

      {/* Error */}
      {error && !loading && (
        <section role="alert" className={`${panel} threat-search-alert`} aria-live="assertive">
          <span className="threat-search-alert-icon">
            <AlertCircle size={20} strokeWidth={1.8} aria-hidden="true" />
          </span>
          <div className="threat-search-alert-copy">
            <span className="threat-search-alert-eyebrow">
              {results?.length ? 'Partial result' : 'Search not completed'}
            </span>
            <h2>{results?.length ? 'Some intelligence is unavailable' : 'Unable to complete the search'}</h2>
            <p>{error}</p>
          </div>
          <button
            type="button"
            onClick={() => void handleSearch()}
            disabled={!canSearch}
            className="ui-secondary threat-alert-action"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            Retry search
          </button>
        </section>
      )}

      {/* Loading */}
      {loading && (
        <section className={`${panel} threat-loading overflow-hidden`} aria-busy="true" aria-live="polite">
          <div className="threat-loading-heading flex items-center gap-2 border-b border-zinc-800/80 px-4 py-3 text-xs text-zinc-400 light:border-zinc-200">
            <Loader2 className="h-4 w-4 animate-spin text-blue-400" aria-hidden="true" />
            Querying the NVD CVE API…
            <span className="text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
              Exact CPE matching may fall back to keyword correlation.
            </span>
          </div>
          <div className="divide-y divide-zinc-800/60 light:divide-zinc-200">
            {Array.from({ length: 5 }).map((_, index) => (
              <div key={index} className="flex animate-pulse items-center gap-4 px-4 py-4">
                <div className="h-4 w-28 rounded bg-zinc-800 light:bg-zinc-200" />
                <div className="h-4 flex-1 rounded bg-zinc-800/70 light:bg-zinc-200/70" />
                <div className="h-5 w-16 rounded bg-zinc-800/70 light:bg-zinc-200/70" />
                <div className="h-4 w-20 rounded bg-zinc-800/70 light:bg-zinc-200/70" />
              </div>
            ))}
          </div>
        </section>
      )}

      {/* No matches */}
      {results && results.length === 0 && !loading && !error && (
        <section className={`${panel} threat-empty-state`} aria-labelledby="threat-empty-heading">
          <div className="threat-empty-symbol">
            <Inbox size={22} strokeWidth={1.7} aria-hidden="true" />
          </div>
          <span className="threat-empty-eyebrow">NVD search completed</span>
          <h2
            id="threat-empty-heading"
            ref={resultsHeadingRef}
            tabIndex={-1}
            className="threat-empty-title"
          >
            No vulnerabilities matched this query
          </h2>
          <p className="threat-empty-copy">
            The CPE and keyword matching paths returned no corroborated CVEs for{' '}
            <strong>{executedSearch?.vendorName || '—'} / {executedSearch?.productName || '—'}</strong>.
            This is a verified empty result, not an upstream search failure.
          </p>
          {executedSearch && (
            <dl className="threat-empty-meta" aria-label="Completed search scope">
              <div>
                <dt>Vendor</dt>
                <dd>{executedSearch.vendorName}</dd>
              </div>
              <div>
                <dt>Product</dt>
                <dd>{executedSearch.productName}</dd>
              </div>
              <div>
                <dt>Published from</dt>
                <dd>{executedSearch.startDate ? formatDate(executedSearch.startDate) : 'Any date'}</dd>
              </div>
              <div>
                <dt>Searched</dt>
                <dd>{formatDateTime(executedSearch.at)}</dd>
              </div>
            </dl>
          )}
          <div className="threat-empty-actions">
            <button
              type="button"
              className="ui-secondary"
              onClick={() => {
                setSearchExpanded(true);
                requestAnimationFrame(() => document.getElementById('threat-product')?.focus({ preventScroll: true }));
              }}
            >
              <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
              Refine search
            </button>
            <button
              type="button"
              className="ui-primary"
              onClick={() => void handleSearch()}
              disabled={!canSearch}
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              Search again
            </button>
          </div>
        </section>
      )}

      {/* Results */}
      {results && results.length > 0 && summary && !loading && (
        <section className="space-y-4" aria-label="Threat intelligence results">
          <div className="threat-overview-heading">
            <h2>Investigation overview</h2>
            <p>
              Based on {results.length} returned {results.length === 1 ? 'record' : 'records'}
            </p>
          </div>
          <div className="threat-metrics grid grid-cols-2 gap-3 lg:grid-cols-4">
            <MetricCard
              label="Matches"
              value={String(summary.total)}
              hint={totalResults > summary.total ? `${totalResults} reported by NVD` : 'Returned by NVD'}
              icon={Database}
              tone="bg-blue-500/10 text-blue-400 light:bg-blue-50 light:text-blue-700"
            />
            <MetricCard
              label="Critical & high"
              value={String(summary.critical + summary.high)}
              hint={`${summary.critical} critical · ${summary.high} high`}
              icon={ShieldAlert}
              tone="bg-rose-500/10 text-rose-400 light:bg-rose-50 light:text-rose-700"
            />
            <MetricCard
              label="Known exploited"
              value={String(summary.kev)}
              hint="CISA KEV catalog"
              icon={Flame}
              tone="bg-amber-500/10 text-amber-400 light:bg-amber-50 light:text-amber-700"
            />
            <MetricCard
              label="Exact match share"
              value={`${summary.exactPct}%`}
              hint={`${summary.exact} of ${summary.total} via CPE`}
              icon={Crosshair}
              tone="bg-emerald-500/10 text-emerald-400 light:bg-emerald-50 light:text-emerald-700"
            />
          </div>

          <div className={`${panel} threat-results-panel overflow-hidden`}>
            <div className="threat-results-toolbar border-b border-zinc-800/80 p-4 light:border-zinc-200">
              <div className="threat-results-heading flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="threat-results-title">
                    <h2
                      ref={resultsHeadingRef}
                      tabIndex={-1}
                      className="threat-results-focus text-sm font-semibold text-zinc-100 light:text-zinc-900"
                    >
                      Search results
                    </h2>
                    <span className="threat-results-count">{results.length} returned</span>
                  </div>
                  <p className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                    {executedSearch && (
                      <>
                        <span>
                          <span className="text-zinc-400 light:text-zinc-600">
                            {executedSearch.vendorName}
                          </span>{' '}
                          / {executedSearch.productName}
                        </span>
                        <span className="inline-flex items-center gap-1">
                          <Clock3 className="h-3 w-3" aria-hidden="true" />
                          {formatDateTime(executedSearch.at)}
                        </span>
                        {executedSearch.startDate && (
                          <span className="inline-flex items-center gap-1">
                            <Calendar className="h-3 w-3" aria-hidden="true" />
                            Published from {formatDate(executedSearch.startDate)}
                          </span>
                        )}
                      </>
                    )}
                    {totalResults > (results?.length ?? 0) && (
                      <span>
                        Showing first {results?.length ?? 0} of {totalResults} reported matches
                      </span>
                    )}
                  </p>
                </div>
                <div
                  className="threat-export-actions flex flex-wrap items-center gap-2"
                  role="group"
                  aria-label="Export filtered results"
                >
                  <button
                    type="button"
                    onClick={() => void handleCopyIds()}
                    disabled={filteredResults.length === 0}
                    title="Copy the CVE IDs in the current filtered view"
                    className={`${smallButton} ${smallButtonIdle}`}
                  >
                    {copiedIds ? (
                      <Check
                        className="h-3.5 w-3.5 text-emerald-400 light:text-emerald-700"
                        aria-hidden="true"
                      />
                    ) : (
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                    )}
                    {copiedIds ? 'Copied' : 'Copy IDs'}
                  </button>
                  <button
                    type="button"
                    onClick={handleExportCsv}
                    disabled={filteredResults.length === 0}
                    className={`${smallButton} ${smallButtonIdle}`}
                  >
                    <Download className="h-3.5 w-3.5" aria-hidden="true" />
                    CSV
                  </button>
                  <button
                    type="button"
                    onClick={handleExportJson}
                    disabled={filteredResults.length === 0}
                    className={`${smallButton} ${smallButtonIdle}`}
                  >
                    <FileJson className="h-3.5 w-3.5" aria-hidden="true" />
                    JSON
                  </button>
                </div>
              </div>

              <div className="threat-refine-label">
                <SlidersHorizontal size={14} aria-hidden="true" />
                Refine results
              </div>
              <div className="threat-result-controls">
                <div className="threat-result-query">
                  <label htmlFor="threat-result-query">Search within results</label>
                  <div className="relative">
                    <Search
                      className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400 light:text-zinc-600"
                      aria-hidden="true"
                    />
                    <input
                      id="threat-result-query"
                      type="search"
                      aria-label="Filter search results"
                      placeholder="CVE, title, CWE, or CPE…"
                      value={resultQuery}
                      onChange={(event) => setResultQuery(event.target.value)}
                      className={`${inputClass} pl-9 pr-9`}
                    />
                    {resultQuery && (
                      <button
                        type="button"
                        aria-label="Clear result filter"
                        onClick={() => setResultQuery('')}
                        className="threat-clear-query"
                      >
                        <X size={14} aria-hidden="true" />
                      </button>
                    )}
                  </div>
                </div>
                <div>
                  <label htmlFor="severity-filter">Severity</label>
                  <select
                    id="severity-filter"
                    value={severityFilter}
                    onChange={(event) => setSeverityFilter(event.target.value as SeverityFilter)}
                    className={inputClass}
                  >
                    <option value="ALL">All severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="UNKNOWN">Unknown</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="threat-evidence-filter">Match evidence</label>
                  <select
                    id="threat-evidence-filter"
                    aria-label="Filter by match evidence"
                    value={evidenceFilter}
                    onChange={(event) => setEvidenceFilter(event.target.value as typeof evidenceFilter)}
                    className={inputClass}
                  >
                    <option value="ALL">All evidence</option>
                    <option value="EXACT">Exact CPE matches</option>
                    <option value="KEYWORD">Keyword matches</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="threat-result-sort">Sort by</label>
                  <select
                    id="threat-result-sort"
                    aria-label="Sort search results"
                    className={inputClass}
                    value={`${sortKey}:${sortOrder}`}
                    onChange={(event) => {
                      const [key, order] = event.target.value.split(':');
                      setSortKey(key as SortKey);
                      setSortOrder(order as SortOrder);
                    }}
                  >
                    <option value="score:desc">Highest risk first</option>
                    <option value="score:asc">Lowest risk first</option>
                    <option value="published:desc">Newest published</option>
                    <option value="published:asc">Oldest published</option>
                    <option value="cve:asc">CVE ID: A–Z</option>
                    <option value="cve:desc">CVE ID: Z–A</option>
                  </select>
                </div>
                <div className="threat-kev-control">
                  <span className="threat-control-label" id="threat-kev-label">
                    Exploitation
                  </span>
                  <button
                    type="button"
                    aria-describedby="threat-kev-label"
                    aria-pressed={kevOnly}
                    onClick={() => setKevOnly((value) => !value)}
                    className={`${smallButton} ${kevOnly ? 'border-amber-500/40 bg-amber-500/10 text-amber-300 light:text-amber-800' : smallButtonIdle}`}
                  >
                    <Flame size={14} aria-hidden="true" />
                    CISA KEV only
                    {kevOnly && <Check size={13} aria-hidden="true" />}
                  </button>
                </div>
              </div>
              {hasResultFilters && (
                <div className="threat-active-filters" role="group" aria-label="Active result filters">
                  <span>Applied filters</span>
                  {[
                    ...(resultQuery.trim()
                      ? [{ label: `Text: ${resultQuery.trim()}`, clear: () => setResultQuery('') }]
                      : []),
                    ...(severityFilter !== 'ALL'
                      ? [
                          {
                            label: `Severity: ${severityFilter.toLowerCase()}`,
                            clear: () => setSeverityFilter('ALL'),
                          },
                        ]
                      : []),
                    ...(evidenceFilter !== 'ALL'
                      ? [
                          {
                            label: evidenceFilter === 'EXACT' ? 'Exact CPE matches' : 'Keyword matches',
                            clear: () => setEvidenceFilter('ALL'),
                          },
                        ]
                      : []),
                    ...(kevOnly ? [{ label: 'CISA KEV only', clear: () => setKevOnly(false) }] : []),
                  ].map(({ label, clear }) => (
                    <button key={label} type="button" onClick={clear} aria-label={`Remove filter ${label}`}>
                      <span>{label}</span>
                      <X size={12} aria-hidden="true" />
                    </button>
                  ))}
                </div>
              )}
              <div className="threat-view-status">
                <p role="status">
                  <strong>{filteredResults.length}</strong> of {results.length} returned results
                  <span>{hasResultFilters ? 'Filters active' : 'All results shown'}</span>
                </p>
                {hasResultFilters && (
                  <button type="button" onClick={resetResultControls} className="threat-clear-filters">
                    <RotateCcw size={13} aria-hidden="true" /> Clear filters
                  </button>
                )}
              </div>
              <p className="threat-evidence-note">
                <Crosshair size={14} aria-hidden="true" />
                <span>
                  Exact CPE matches reference product identifiers. Keyword matches need review for product
                  applicability.
                </span>
              </p>
            </div>

            <div className="threat-desktop-results overflow-x-auto">
              <table className="threat-results-table w-full min-w-[920px] text-left text-xs">
                <caption className="sr-only">NVD vulnerability search results</caption>
                <thead className="border-b border-zinc-800/80 bg-zinc-950/60 text-[10px] uppercase tracking-[0.06em] text-zinc-400 dark:text-zinc-500 light:text-zinc-600 light:border-zinc-200 light:bg-zinc-50">
                  <tr>
                    <th scope="col" aria-sort={ariaSort('cve')} className="min-w-[240px] px-4 py-3">
                      <button
                        type="button"
                        onClick={() => toggleSort('cve')}
                        className="-mx-1 flex items-center gap-1 rounded px-1 py-0.5 transition hover:text-zinc-200 light:hover:text-zinc-900"
                      >
                        Vulnerability
                        {sortIcon('cve')}
                      </button>
                    </th>
                    <th scope="col" aria-sort={ariaSort('score')} className="px-4 py-3">
                      <button
                        type="button"
                        onClick={() => toggleSort('score')}
                        className="-mx-1 flex items-center gap-1 rounded px-1 py-0.5 transition hover:text-zinc-200 light:hover:text-zinc-900"
                      >
                        Risk / CVSS
                        {sortIcon('score')}
                      </button>
                    </th>
                    <th scope="col" className="px-4 py-3">
                      Exploit intelligence
                    </th>
                    <th scope="col" className="px-4 py-3">
                      Match evidence
                    </th>
                    <th scope="col" aria-sort={ariaSort('published')} className="px-4 py-3">
                      <button
                        type="button"
                        onClick={() => toggleSort('published')}
                        className="-mx-1 flex items-center gap-1 rounded px-1 py-0.5 transition hover:text-zinc-200 light:hover:text-zinc-900"
                      >
                        Published
                        {sortIcon('published')}
                      </button>
                    </th>
                    <th scope="col" className="px-4 py-3 text-right">
                      Details
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {pageResults.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-14 text-center">
                        <div className="mx-auto flex max-w-sm flex-col items-center">
                          <span className="grid h-11 w-11 place-items-center rounded-xl border border-zinc-800 bg-zinc-950 text-zinc-400 dark:text-zinc-500 light:text-zinc-600 light:border-zinc-300 light:bg-zinc-100">
                            <Inbox className="h-5 w-5" aria-hidden="true" />
                          </span>
                          <p className="mt-3 text-sm font-semibold text-zinc-300 light:text-zinc-800">
                            No results match these filters
                          </p>
                          <p className="mt-1 text-xs text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                            Clear the text, severity, evidence, or KEV filters to restore the full result set.
                          </p>
                          <button
                            type="button"
                            onClick={resetResultControls}
                            className="ui-secondary mt-3 min-h-8 px-3 text-[11px]"
                          >
                            <RotateCcw className="h-3 w-3" aria-hidden="true" />
                            Clear filters
                          </button>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    pageResults.map((hit) => {
                      const cve = hit.cve;
                      const scored = cve.cvss.version !== 'UNKNOWN';
                      return (
                        <tr
                          key={cve.cveId}
                          className="align-top transition hover:bg-zinc-800/30 light:hover:bg-zinc-50"
                        >
                          <td className="max-w-sm px-4 py-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <CveLink cveId={cve.cveId} className="whitespace-nowrap" />
                              {cve.cisaKev?.isKev && <KevBadge />}
                            </div>
                            <p
                              className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-zinc-400 light:text-zinc-600"
                              title={cve.title}
                            >
                              {cve.title || 'No title provided'}
                            </p>
                            {cve.cwe.length > 0 && (
                              <p className="mt-1 truncate font-mono text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                                {cve.cwe.slice(0, 3).join(' · ')}
                                {cve.cwe.length > 3 ? ` +${cve.cwe.length - 3}` : ''}
                              </p>
                            )}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3">
                            <div className="mb-1.5">
                              <SeverityBadge severity={cve.cvss.severity} />
                            </div>
                            <span className="font-mono text-sm font-semibold tabular-nums text-zinc-200 light:text-zinc-800">
                              {scored ? cve.cvss.score.toFixed(1) : '—'}
                            </span>
                            <span className="ml-1.5 font-mono text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                              {scored ? `v${cve.cvss.version}` : 'Unscored'}
                            </span>
                            {scored && (
                              <span
                                className="threat-risk-meter"
                                data-severity={cve.cvss.severity}
                                aria-hidden="true"
                              >
                                <span
                                  style={{ width: `${Math.min(100, Math.max(0, cve.cvss.score * 10))}%` }}
                                />
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <div className="space-y-0.5">
                              <p className={`text-[11px] font-medium ${exploitTone(cve.exploitStatus)}`}>
                                {cve.exploitStatus === 'None' ? 'No known exploit' : cve.exploitStatus}
                              </p>
                              {cve.cisaKev?.isKev && cve.cisaKev.dateAdded && (
                                <p className="text-[10px] text-amber-300 light:text-amber-700">
                                  KEV added {formatDate(cve.cisaKev?.dateAdded)}
                                </p>
                              )}
                              {hasEpss(cve.epss) && (
                                <p className="font-mono text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                                  EPSS {formatEpss(cve.epss?.score ?? 0)} ·{' '}
                                  {formatPercentile(cve.epss?.percentile ?? 0)}
                                </p>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="mb-1.5">
                              <SourceBadge source={hit.source} />
                            </div>
                            {hit.matchingCpes.length > 0 ? (
                              <div className="space-y-0.5">
                                <code
                                  className="block max-w-[220px] truncate font-mono text-[10px] text-zinc-400 light:text-zinc-600"
                                  title={hit.matchingCpes[0]}
                                >
                                  {hit.matchingCpes[0]}
                                </code>
                                {hit.matchingCpes.length > 1 && (
                                  <span className="text-[10px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                                    +{hit.matchingCpes.length - 1} more
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="text-[11px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                                —
                              </span>
                            )}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3 text-[11px] text-zinc-400 light:text-zinc-600">
                            {formatDate(cve.publishedDate)}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              type="button"
                              onClick={() => {
                                setCopiedDetail(false);
                                setInspect(hit);
                              }}
                              className={`${smallButton} ${smallButtonIdle}`}
                              aria-label={`Inspect ${cve.cveId}`}
                            >
                              Inspect
                              <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            <div className="threat-mobile-results">
              {pageResults.length === 0 ? (
                <div className="threat-mobile-empty">
                  <p>No results match these filters.</p>
                  <button type="button" onClick={resetResultControls} className="ui-secondary">
                    Clear filters
                  </button>
                </div>
              ) : (
                pageResults.map((hit) => (
                  <article key={hit.cve.cveId} className="threat-result-card">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <CveLink cveId={hit.cve.cveId} />
                      <SeverityBadge severity={hit.cve.cvss.severity} />
                    </div>
                    <h3>{hit.cve.title || 'No title provided'}</h3>
                    <div className="flex flex-wrap items-center gap-2">
                      <SourceBadge source={hit.source} />
                      {hit.cve.cisaKev?.isKev && <KevBadge />}
                    </div>
                    <div className="threat-card-evidence">
                      <span>Match evidence</span>
                      {hit.matchingCpes.length ? (
                        <>
                          <code title={hit.matchingCpes[0]}>{hit.matchingCpes[0]}</code>
                          {hit.matchingCpes.length > 1 && (
                            <small>+{hit.matchingCpes.length - 1} additional identifiers</small>
                          )}
                        </>
                      ) : (
                        <p>Matched by keyword. Review product applicability.</p>
                      )}
                    </div>
                    <dl>
                      <div>
                        <dt>CVSS</dt>
                        <dd>
                          {hit.cve.cvss.version === 'UNKNOWN' ? 'Unscored' : hit.cve.cvss.score.toFixed(1)}
                        </dd>
                      </div>
                      <div>
                        <dt>Published</dt>
                        <dd>{formatDate(hit.cve.publishedDate)}</dd>
                      </div>
                      <div>
                        <dt>Exploit intelligence</dt>
                        <dd className={exploitTone(hit.cve.exploitStatus)}>
                          {hit.cve.exploitStatus === 'None' ? 'No known exploit' : hit.cve.exploitStatus}
                        </dd>
                      </div>
                      <div>
                        <dt>EPSS probability</dt>
                        <dd>{hasEpss(hit.cve.epss) ? formatEpss(hit.cve.epss!.score) : 'Not scored'}</dd>
                      </div>
                    </dl>
                    <button
                      type="button"
                      aria-label={`Inspect ${hit.cve.cveId}`}
                      onClick={() => {
                        setCopiedDetail(false);
                        setInspect(hit);
                      }}
                      className="ui-secondary"
                    >
                      Inspect vulnerability
                      <ChevronRight size={14} aria-hidden="true" />
                    </button>
                  </article>
                ))
              )}
            </div>

            <Pagination
              currentPage={currentPage}
              totalItems={filteredResults.length}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              pageSizeOptions={[10, 25, 50]}
            />
          </div>
        </section>
      )}

      {/* Detail dialog */}
      {inspect && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/75 p-3 backdrop-blur-sm sm:p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setInspect(null);
          }}
        >
          <ThreatDetailDialog onClose={() => setInspect(null)}>
            <div className="flex items-start justify-between gap-3 border-b border-zinc-800/80 px-4 py-4 light:border-zinc-200 sm:px-5">
              <div className="min-w-0">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                  NVD vulnerability record
                </p>
                <div className="mt-1.5 flex flex-wrap items-center gap-2">
                  <CveLink cveId={inspect.cve.cveId} className="text-base" />
                  <SeverityBadge severity={inspect.cve.cvss.severity} />
                  {inspect.cve.cisaKev?.isKev && <KevBadge />}
                  <SourceBadge source={inspect.source} />
                </div>
                <h2
                  id="threat-detail-title"
                  className="mt-2 text-sm font-semibold leading-snug text-zinc-100 light:text-zinc-900"
                >
                  {inspect.cve.title || 'Untitled NVD record'}
                </h2>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleCopyDetail()}
                  className={`${smallButton} ${smallButtonIdle}`}
                >
                  {copiedDetail ? (
                    <Check
                      className="h-3.5 w-3.5 text-emerald-400 light:text-emerald-700"
                      aria-hidden="true"
                    />
                  ) : (
                    <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  {copiedDetail ? 'Copied' : 'Copy JSON'}
                </button>
                <button
                  type="button"
                  onClick={() => setInspect(null)}
                  aria-label="Close vulnerability details"
                  className="grid h-8 w-8 place-items-center rounded-lg text-zinc-400 dark:text-zinc-500 light:text-zinc-600 transition hover:bg-zinc-800 hover:text-zinc-200 light:hover:bg-zinc-100 light:hover:text-zinc-900"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>
            </div>

            <div className="overflow-y-auto px-4 py-4 sm:px-5">
              <p className="text-sm leading-relaxed text-zinc-300 light:text-zinc-700">
                {inspect.cve.description || 'No description was returned for this record.'}
              </p>

              <dl className="mt-4 grid grid-cols-2 gap-3 rounded-xl border border-zinc-800/80 bg-zinc-950/40 p-3 text-[11px] light:border-zinc-200 light:bg-zinc-50 sm:grid-cols-4">
                <div>
                  <dt className="text-zinc-400 dark:text-zinc-500 light:text-zinc-600">CVSS</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200 light:text-zinc-800">
                    {inspect.cve.cvss.version === 'UNKNOWN'
                      ? 'Unscored'
                      : `${inspect.cve.cvss.score.toFixed(1)} · v${inspect.cve.cvss.version}`}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-400 dark:text-zinc-500 light:text-zinc-600">EPSS</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200 light:text-zinc-800">
                    {hasEpss(inspect.cve.epss)
                      ? `${formatEpss(inspect.cve.epss?.score ?? 0)} · ${formatPercentile(
                          inspect.cve.epss?.percentile ?? 0,
                        )}`
                      : 'Not scored'}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-400 dark:text-zinc-500 light:text-zinc-600">Published</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200 light:text-zinc-800">
                    {formatDate(inspect.cve.publishedDate)}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-400 dark:text-zinc-500 light:text-zinc-600">Modified</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200 light:text-zinc-800">
                    {formatDate(inspect.cve.modifiedDate)}
                  </dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                    Exploit intelligence
                  </dt>
                  <dd className={`mt-0.5 font-medium ${exploitTone(inspect.cve.exploitStatus)}`}>
                    {inspect.cve.exploitStatus === 'None'
                      ? 'No known exploitation'
                      : inspect.cve.exploitStatus}
                  </dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-zinc-400 dark:text-zinc-500 light:text-zinc-600">CISA KEV</dt>
                  <dd className="mt-0.5 text-zinc-200 light:text-zinc-800">
                    {inspect.cve.cisaKev?.isKev ? (
                      <>
                        Known exploited
                        {inspect.cve.cisaKev?.dateAdded
                          ? ` · added ${formatDate(inspect.cve.cisaKev.dateAdded)}`
                          : ''}
                        {inspect.cve.cisaKev?.dueDate
                          ? ` · due ${formatDate(inspect.cve.cisaKev.dueDate)}`
                          : ''}
                      </>
                    ) : (
                      'Not listed'
                    )}
                  </dd>
                </div>
                {inspect.cve.cisaKev?.requiredAction && (
                  <div className="col-span-2 sm:col-span-4">
                    <dt className="text-zinc-400 dark:text-zinc-500 light:text-zinc-600">Required action</dt>
                    <dd className="mt-0.5 leading-relaxed text-zinc-300 light:text-zinc-700">
                      {inspect.cve.cisaKev?.requiredAction}
                    </dd>
                  </div>
                )}
              </dl>

              <section className="mt-5">
                <h3 className="flex items-center gap-2 text-xs font-semibold text-zinc-200 light:text-zinc-800">
                  Matched CPE 2.3 entries
                  <span className="rounded-full bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400 light:bg-zinc-200 light:text-zinc-600">
                    {inspect.matchingCpes.length}
                  </span>
                </h3>
                {inspect.matchingCpes.length > 0 ? (
                  <ul className="mt-2 max-h-44 space-y-1 overflow-y-auto rounded-xl border border-zinc-800 bg-zinc-950 p-2 light:border-zinc-300 light:bg-zinc-50">
                    {inspect.matchingCpes.map((cpe) => (
                      <li
                        key={cpe}
                        className="break-all rounded px-2 py-1 font-mono text-[10px] text-zinc-400 light:text-zinc-600"
                      >
                        {cpe}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-1 text-[11px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                    No CPE entries matched for this result.
                  </p>
                )}
              </section>

              <section className="mt-5">
                <h3 className="flex items-center gap-2 text-xs font-semibold text-zinc-200 light:text-zinc-800">
                  <Tag
                    className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500 light:text-zinc-600"
                    aria-hidden="true"
                  />
                  Weaknesses
                </h3>
                {inspect.cve.cwe.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {inspect.cve.cwe.map((cwe) => (
                      <span
                        key={cwe}
                        className="rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-600"
                      >
                        {cwe}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="mt-1 text-[11px] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                    No CWE assigned.
                  </p>
                )}
              </section>

              {(inspect.cve.remediation?.patchUrl ||
                (inspect.cve.remediation?.immediateActions?.length ?? 0) > 0 ||
                (inspect.cve.remediation?.workarounds?.length ?? 0) > 0) && (
                <section className="mt-5">
                  <h3 className="text-xs font-semibold text-zinc-200 light:text-zinc-800">
                    Remediation guidance
                  </h3>
                  {inspect.cve.remediation?.patchUrl && (
                    <a
                      href={inspect.cve.remediation.patchUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mt-2 inline-flex items-center gap-1 text-[11px] font-medium text-blue-400 underline-offset-4 hover:underline light:text-blue-700"
                    >
                      Vendor patch or advisory
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    </a>
                  )}
                  {(inspect.cve.remediation?.immediateActions?.length ?? 0) > 0 && (
                    <div className="mt-2">
                      <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                        Immediate actions
                      </p>
                      <ul className="mt-1 list-disc space-y-1 pl-4 text-[11px] leading-relaxed text-zinc-400 light:text-zinc-600">
                        {inspect.cve.remediation.immediateActions.map((action) => (
                          <li key={action}>{action}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {(inspect.cve.remediation?.workarounds?.length ?? 0) > 0 && (
                    <div className="mt-2">
                      <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-zinc-400 dark:text-zinc-500 light:text-zinc-600">
                        Workarounds
                      </p>
                      <ul className="mt-1 list-disc space-y-1 pl-4 text-[11px] leading-relaxed text-zinc-400 light:text-zinc-600">
                        {inspect.cve.remediation.workarounds.map((workaround) => (
                          <li key={workaround}>{workaround}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </section>
              )}

              <section className="mt-5">
                <h3 className="text-xs font-semibold text-zinc-200 light:text-zinc-800">Sources</h3>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <span className="rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-600">
                    {inspect.source === 'NVD_API' ? 'NVD exact CPE' : 'NVD keyword fallback'}
                  </span>
                  {inspect.cve.sourceFeeds.map((source) => (
                    <span
                      key={source}
                      className="rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-600"
                    >
                      {source}
                    </span>
                  ))}
                </div>
              </section>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-800/80 px-4 py-3 light:border-zinc-200 sm:px-5">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(inspect.cve.cveId)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="ui-secondary min-h-9 px-3 text-[11px]"
              >
                Open on NVD
                <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
              </a>
              <button
                type="button"
                onClick={() => setInspect(null)}
                className="ui-primary min-h-9 px-4 text-[11px]"
              >
                Close
              </button>
            </div>
          </ThreatDetailDialog>
        </div>
      )}
    </div>
  );
};
