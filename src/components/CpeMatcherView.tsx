import { PageHeading } from './PageHeading';
import React, { useState, useMemo, useRef } from 'react';
import { useApp } from '../context/AppContext';
import {
  CpeMatchSimulation,
  CpeParseResult,
  NvdCpeSearchResponse,
  NvdCpeSearchResult,
  SeverityClassification,
} from '../types';
import {
  ScanLine,
  Check,
  X,
  Copy,
  Loader2,
  AlertCircle,
  Shield,
  ShieldCheck,
  ShieldX,
  Search,
  Database,
  Hash,
  ChevronDown,
  ChevronRight,
  RotateCcw,
} from 'lucide-react';
import { copyText } from '../utils/clipboard';
import { parseCPE23 } from '../utils/cpeMatcher';
import './investigation-pages.css';

function validateCpeInput(cpe: string): { valid: boolean; message?: string } {
  if (!cpe.trim()) return { valid: false, message: 'Enter a CPE 2.3 name.' };
  return parseCPE23(cpe.trim()).isValid
    ? { valid: true }
    : { valid: false, message: 'Enter a valid CPE 2.3 name with all 11 components.' };
}

const SEVERITY_TONES: Record<string, { border: string; bg: string; text: string; light: string }> = {
  CRITICAL: {
    border: 'border-rose-500/30',
    bg: 'bg-rose-500/10',
    text: 'text-rose-300',
    light: 'light:text-rose-800',
  },
  HIGH: {
    border: 'border-orange-500/30',
    bg: 'bg-orange-500/10',
    text: 'text-orange-300',
    light: 'light:text-orange-800',
  },
  MEDIUM: {
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/10',
    text: 'text-amber-300',
    light: 'light:text-amber-800',
  },
  LOW: {
    border: 'border-emerald-500/30',
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-300',
    light: 'light:text-emerald-800',
  },
  INFORMATIONAL: {
    border: 'border-zinc-500/30',
    bg: 'bg-zinc-800/60',
    text: 'text-zinc-300',
    light: 'light:text-zinc-600',
  },
};

interface CpePreset {
  label: string;
  assetCpe: string;
  vulnerabilityCpe: string;
  assetVendor: string;
  assetProduct: string;
  assetVersion: string;
  versionEndExcluding: string;
  description: string;
}

const CPE_PRESETS: CpePreset[] = [
  {
    label: 'Log4Shell (Log4j 2)',
    description: 'Classic RCE via JNDI in Apache Log4j 2 < 2.15.0',
    assetCpe: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    vulnerabilityCpe: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
    assetVendor: 'apache',
    assetProduct: 'log4j',
    assetVersion: '2.14.1',
    versionEndExcluding: '2.15.0',
  },
  {
    label: 'OpenSSL Heartbleed',
    description: 'Buffer over-read in OpenSSL 1.0.1 < 1.0.1g',
    assetCpe: 'cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*',
    vulnerabilityCpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
    assetVendor: 'openssl',
    assetProduct: 'openssl',
    assetVersion: '1.0.1f',
    versionEndExcluding: '1.0.1g',
  },
  {
    label: 'Windows DHCP RCE',
    description: 'Wormable RCE in Windows Server DHCP < 10.0.17763.2686',
    assetCpe: 'cpe:2.3:o:microsoft:windows_server_2019:10.0.17763:*:*:*:*:*:*:*',
    vulnerabilityCpe: 'cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*',
    assetVendor: 'microsoft',
    assetProduct: 'windows_server_2019',
    assetVersion: '10.0.17763',
    versionEndExcluding: '10.0.17763.2686',
  },
];

export const CpeMatcherView: React.FC = () => {
  const { simulateCpeMatch, searchNvdCpes } = useApp();
  const [assetCpe, setAssetCpe] = useState('cpe:2.3:o:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*');
  const [vulnerabilityCpe, setVulnerabilityCpe] = useState('cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*');
  const [assetVendor, setAssetVendor] = useState('microsoft');
  const [assetProduct, setAssetProduct] = useState('windows_10');
  const [assetVersion, setAssetVersion] = useState('10.0.19041');
  const [versionStartIncluding, setVersionStartIncluding] = useState('');
  const [versionEndExcluding, setVersionEndExcluding] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [result, setResult] = useState<CpeMatchSimulation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const simulationSequence = useRef(0);
  const [copiedCpe, setCopiedCpe] = useState('');

  const [activeTab, setActiveTab] = useState<'match' | 'lookup'>('match');
  const [lookupVendor, setLookupVendor] = useState('microsoft');
  const [lookupProduct, setLookupProduct] = useState('windows_10');
  const [lookupResults, setLookupResults] = useState<NvdCpeSearchResponse | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  const assetCpeValid = useMemo(() => validateCpeInput(assetCpe), [assetCpe]);
  const vulnCpeValid = useMemo(() => validateCpeInput(vulnerabilityCpe), [vulnerabilityCpe]);

  const handlePreset = (preset: CpePreset) => {
    simulationSequence.current++;
    setLoading(false);
    setResult(null);
    setError(null);
    setVersionStartIncluding('');
    setAssetCpe(preset.assetCpe);
    setVulnerabilityCpe(preset.vulnerabilityCpe);
    setAssetVendor(preset.assetVendor);
    setAssetProduct(preset.assetProduct);
    setAssetVersion(preset.assetVersion);
    setVersionEndExcluding(preset.versionEndExcluding);
    setShowAdvanced(true);
  };

  const handleClear = () => {
    simulationSequence.current++;
    setLoading(false);
    setAssetCpe('');
    setVulnerabilityCpe('');
    setAssetVendor('');
    setAssetProduct('');
    setAssetVersion('');
    setVersionStartIncluding('');
    setVersionEndExcluding('');
    setShowAdvanced(false);
    setResult(null);
    setError(null);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      handleClear();
      return;
    }
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      void handleSimulate();
    }
  };

  const handleSimulate = async () => {
    if (loading || !assetCpeValid.valid || !vulnCpeValid.valid || !assetVendor.trim() || !assetProduct.trim())
      return;
    const sequence = ++simulationSequence.current;
    setResult(null);
    setLoading(true);
    setError(null);
    try {
      const resp = await simulateCpeMatch({
        assetCpe,
        vulnerabilityCpe,
        assetVendor,
        assetProduct,
        assetVersion: assetVersion || undefined,
        versionRange:
          versionStartIncluding || versionEndExcluding
            ? {
                versionStartIncluding: versionStartIncluding || undefined,
                versionEndExcluding: versionEndExcluding || undefined,
              }
            : undefined,
      });
      if (sequence === simulationSequence.current) setResult(resp);
    } catch (err) {
      if (sequence === simulationSequence.current)
        setError(err instanceof Error ? err.message : 'Simulation failed');
    } finally {
      if (sequence === simulationSequence.current) setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!result) return;
    const success = await copyText(JSON.stringify(result, null, 2));
    setCopied(success);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleLookup = async () => {
    // A product name alone is enough: the backend also runs a wildcard-vendor
    // dictionary search, so an unknown or mismatched vendor label doesn't
    // block finding a verified, exact CPE.
    if (!lookupVendor.trim() && !lookupProduct.trim()) return;
    setLookupLoading(true);
    setLookupError(null);
    setLookupResults(null);
    try {
      const resp = await searchNvdCpes(lookupVendor.trim(), lookupProduct.trim(), 50);
      setLookupResults(resp);
    } catch (err) {
      setLookupError(err instanceof Error ? err.message : 'NVD CPE lookup failed');
    } finally {
      setLookupLoading(false);
    }
  };

  return (
    <div className="cpe-workspace space-y-6">
      <PageHeading page="cpe-matcher">
        Compare product identifiers, validate version applicability, and inspect the evidence behind a match.
      </PageHeading>

      <div className="investigation-tabs" aria-label="CPE tools">
        <button
          type="button"
          aria-pressed={activeTab === 'match'}
          onClick={() => setActiveTab('match')}
          className={`flex-1 text-center text-xs font-medium py-1.5 rounded-md transition ${
            activeTab === 'match'
              ? 'bg-zinc-900 dark:bg-zinc-900 light:bg-white text-zinc-100 light:text-zinc-900 shadow'
              : 'text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900'
          }`}
        >
          <ScanLine size={16} aria-hidden="true" /> Match &amp; classify
        </button>
        <button
          type="button"
          aria-pressed={activeTab === 'lookup'}
          onClick={() => setActiveTab('lookup')}
          className={`flex-1 text-center text-xs font-medium py-1.5 rounded-md transition ${
            activeTab === 'lookup'
              ? 'bg-zinc-900 dark:bg-zinc-900 light:bg-white text-zinc-100 light:text-zinc-900 shadow'
              : 'text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900'
          }`}
        >
          <Database size={16} aria-hidden="true" /> NVD dictionary
        </button>
      </div>

      <div
        className={`ui-panel cpe-input-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4 space-y-4 ${activeTab === 'lookup' ? 'hidden' : ''}`}
      >
        <div className="investigation-panel-heading">
          <span className="investigation-icon">
            <ScanLine size={20} aria-hidden="true" />
          </span>
          <div>
            <h2>Compare an asset with an affected product</h2>
            <p>Enter both CPE names, then refine the asset identity and version range.</p>
          </div>
        </div>
        <div className="cpe-presets">
          <span className="px-4 text-xs font-semibold uppercase tracking-wider text-zinc-500 light:text-zinc-600">
            Examples
          </span>
          {CPE_PRESETS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => handlePreset(preset)}
              className="text-xs px-3.5 py-1.5 rounded-md border border-zinc-700 bg-zinc-800/50 text-zinc-300 hover:bg-zinc-700 hover:border-zinc-600 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-800 light:hover:bg-zinc-200 transition-colors"
              title={preset.description}
            >
              {preset.label}
            </button>
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label
              htmlFor="asset-cpe"
              className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
            >
              Asset CPE 2.3
            </label>
            <input
              id="asset-cpe"
              aria-invalid={!!assetCpe && !assetCpeValid.valid}
              aria-describedby={assetCpe && !assetCpeValid.valid ? 'asset-cpe-help' : undefined}
              type="text"
              value={assetCpe}
              onChange={(e) => setAssetCpe(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
              className={`w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md font-mono focus:outline-none focus:ring-1 focus:border-zinc-600 placeholder-zinc-500 ${
                !assetCpeValid.valid ? 'border-rose-500/50 focus:ring-rose-500/50' : 'border-zinc-600'
              }`}
            />
            {!assetCpeValid.valid && assetCpe && (
              <p id="asset-cpe-help" role="status" className="mt-1 text-xs text-rose-400 light:text-rose-700">
                {assetCpeValid.message}
              </p>
            )}
          </div>
          <div>
            <label
              htmlFor="vulnerability-cpe"
              className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
            >
              Vulnerability CPE 2.3
            </label>
            <input
              id="vulnerability-cpe"
              aria-invalid={!!vulnerabilityCpe && !vulnCpeValid.valid}
              aria-describedby={
                vulnerabilityCpe && !vulnCpeValid.valid ? 'vulnerability-cpe-help' : undefined
              }
              type="text"
              value={vulnerabilityCpe}
              onChange={(e) => setVulnerabilityCpe(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
              className={`w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md font-mono focus:outline-none focus:ring-1 focus:border-zinc-600 placeholder-zinc-500 ${
                !vulnCpeValid.valid ? 'border-rose-500/50 focus:ring-rose-500/50' : 'border-zinc-600'
              }`}
            />
            {!vulnCpeValid.valid && vulnerabilityCpe && (
              <p
                id="vulnerability-cpe-help"
                role="status"
                className="mt-1 text-xs text-rose-400 light:text-rose-700"
              >
                {vulnCpeValid.message}
              </p>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label
              htmlFor="asset-vendor"
              className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
            >
              Asset vendor
            </label>
            <input
              id="asset-vendor"
              type="text"
              value={assetVendor}
              onChange={(e) => setAssetVendor(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <div>
            <label
              htmlFor="asset-product"
              className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
            >
              Asset product
            </label>
            <input
              id="asset-product"
              type="text"
              value={assetProduct}
              onChange={(e) => setAssetProduct(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>

        <div>
          <label
            htmlFor="asset-version"
            className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
          >
            Asset version (for range checking)
          </label>
          <input
            id="asset-version"
            type="text"
            value={assetVersion}
            onChange={(e) => setAssetVersion(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="e.g. 10.0.19041"
            className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md font-mono focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-zinc-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            aria-expanded={showAdvanced}
            aria-controls="cpe-version-range"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-1 text-xs text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 transition-colors"
          >
            {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            Refine version range
          </button>
        </div>

        {showAdvanced && (
          <div
            id="cpe-version-range"
            className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200"
          >
            <div>
              <label
                htmlFor="range-start"
                className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
              >
                Version start (inclusive)
              </label>
              <input
                id="range-start"
                type="text"
                value={versionStartIncluding}
                onChange={(e) => setVersionStartIncluding(e.target.value)}
                placeholder="e.g. 10.2.0"
                className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md font-mono focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-zinc-500"
              />
            </div>
            <div>
              <label
                htmlFor="range-end"
                className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
              >
                Version end (exclusive)
              </label>
              <input
                id="range-end"
                type="text"
                value={versionEndExcluding}
                onChange={(e) => setVersionEndExcluding(e.target.value)}
                placeholder="e.g. 10.2.9-h1"
                className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md font-mono focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-zinc-500"
              />
            </div>
          </div>
        )}

        <div className="cpe-form-actions">
          <button
            type="button"
            onClick={handleCopy}
            disabled={!result}
            className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 disabled:opacity-50 rounded transition-colors"
            title="Copy simulation result"
            aria-label="Copy simulation result"
          >
            {copied ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
          </button>
          <button
            type="button"
            onClick={handleClear}
            className="px-4 py-2 border border-zinc-700 bg-zinc-800/30 text-zinc-300 rounded-md font-medium hover:bg-zinc-700 hover:border-zinc-600 light:border-zinc-300 light:bg-white light:text-zinc-800 light:hover:bg-zinc-100 transition-colors flex items-center gap-2 text-xs"
          >
            <RotateCcw size={14} />
            Clear
          </button>
          <button
            type="button"
            onClick={() => void handleSimulate()}
            disabled={
              loading ||
              !assetCpeValid.valid ||
              !vulnCpeValid.valid ||
              !assetVendor.trim() ||
              !assetProduct.trim()
            }
            className="ui-primary"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
            Simulate CPE match
            <kbd className="hidden sm:inline-block text-[10px] text-zinc-500 light:text-zinc-600">
              · Cmd+Enter
            </kbd>
          </button>
        </div>
      </div>

      {activeTab === 'match' && error && (
        <div
          role="alert"
          className="rounded-md border border-rose-500/30 bg-rose-500/10 p-3 flex items-center gap-2"
        >
          <AlertCircle className="h-4 w-4 text-rose-400 light:text-rose-800" />
          <span className="text-sm text-rose-300 light:text-rose-800">{error}</span>
        </div>
      )}

      {activeTab === 'match' && result && !loading && (
        <div className="space-y-6">
          <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 overflow-hidden">
            <div className="p-4 border-b border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  {result.match.matched ? (
                    <ShieldCheck className="h-5 w-5 text-emerald-400 light:text-emerald-700" />
                  ) : (
                    <ShieldX className="h-5 w-5 text-rose-400 light:text-rose-700" />
                  )}
                  <span className="text-lg font-medium text-zinc-100 light:text-zinc-900">
                    Match result:{' '}
                    <span
                      className={
                        result.match.matched
                          ? 'text-emerald-400 light:text-emerald-700'
                          : 'text-rose-400 light:text-rose-700'
                      }
                    >
                      {result.match.matched ? 'MATCHED' : 'NO MATCH'}
                    </span>
                  </span>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-zinc-500 light:text-zinc-600">Confidence:</span>
                <span className="text-sm font-mono font-medium text-zinc-200 light:text-zinc-900">
                  {result.match.confidence}%
                </span>
              </div>
            </div>
            <div className="p-4 space-y-3">
              <div>
                <span className="text-xs font-medium text-zinc-500 light:text-zinc-600">Method</span>
                <div className="text-sm font-mono text-zinc-300 light:text-zinc-800 mt-0.5">
                  {result.match.method}
                </div>
              </div>
              <div>
                <span className="text-xs font-medium text-zinc-500 light:text-zinc-600">Evidence</span>
                <div className="text-sm text-zinc-300 light:text-zinc-800 mt-0.5">
                  {result.match.evidence}
                </div>
              </div>
              {result.match.reason && (
                <div>
                  <span className="text-xs font-medium text-zinc-500 light:text-zinc-600">Reason</span>
                  <div className="text-sm text-zinc-400 light:text-zinc-600 mt-0.5">
                    {result.match.reason}
                  </div>
                </div>
              )}
              {result.match.viaAlias && (
                <div>
                  <span className="text-xs font-medium text-zinc-500 light:text-zinc-600">
                    Matched via alias
                  </span>
                  <span className="text-xs text-teal-300 light:text-teal-800 ml-2">Yes</span>
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CpeParseCard title="Asset CPE" parsed={result.assetCpe} />
            <CpeParseCard title="Vulnerability CPE" parsed={result.vulnerabilityCpe} />
          </div>

          {(result.assetVendorAlias || result.assetProductAlias) && (
            <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
              <h3 className="text-sm font-medium text-zinc-300 light:text-zinc-800 mb-3">Alias Expansion</h3>
              <div className="space-y-2">
                {result.assetVendorAlias && <AliasExpansionDisplay alias={result.assetVendorAlias} />}
                {result.assetProductAlias && <AliasExpansionDisplay alias={result.assetProductAlias} />}
              </div>
            </div>
          )}

          {result.versionRangeCheck && (
            <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
              <h3 className="text-sm font-medium text-zinc-300 light:text-zinc-800 mb-2">
                Version Range Check
              </h3>
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                    result.versionRangeCheck.inRange
                      ? 'bg-emerald-500/10 text-emerald-300 light:text-emerald-800 border border-emerald-500/30'
                      : 'bg-rose-500/10 text-rose-300 light:text-rose-800 border border-rose-500/30'
                  }`}
                >
                  {result.versionRangeCheck.inRange ? 'In range' : 'Out of range'}
                </span>
              </div>
              <p className="text-xs text-zinc-500 light:text-zinc-600 mt-1">
                {result.versionRangeCheck.reason}
              </p>
            </div>
          )}

          <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
            <h3 className="text-sm font-medium text-zinc-300 light:text-zinc-800 mb-3">
              False-Positive Elimination Checks
            </h3>
            {result.falsePositiveChecks.length === 0 ? (
              <p className="text-xs text-zinc-500 light:text-zinc-600">
                No false-positive checks configured for this match.
              </p>
            ) : (
              <div className="space-y-2">
                {result.falsePositiveChecks.map((check, i) => (
                  <div
                    key={i}
                    className={`flex items-start gap-3 p-2 rounded-md border ${
                      check.passed
                        ? 'border-emerald-500/20 bg-emerald-500/5'
                        : 'border-rose-500/20 bg-rose-500/5'
                    }`}
                  >
                    {check.passed ? (
                      <Check className="h-4 w-4 text-emerald-400 light:text-emerald-700 flex-shrink-0 mt-0.5" />
                    ) : (
                      <X className="h-4 w-4 text-rose-400 light:text-rose-800 flex-shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-medium text-zinc-300 light:text-zinc-800">
                          {check.name}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.25 rounded ${
                            check.severity === 'BLOCK'
                              ? 'bg-rose-500/10 text-rose-300 light:text-rose-800'
                              : 'bg-amber-500/10 text-amber-300 light:text-amber-800'
                          }`}
                        >
                          {check.severity}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-500 light:text-zinc-600 mt-0.5">{check.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {result.severity && <SeverityCard severity={result.severity} />}
        </div>
      )}

      {activeTab === 'match' && loading && (
        <div className="ui-panel investigation-empty" role="status" aria-busy="true">
          <Loader2 className="animate-spin" size={24} />
          <h2>Evaluating product applicability</h2>
          <p>Checking identifiers, aliases, and version constraints.</p>
        </div>
      )}
      {activeTab === 'match' && !result && !loading && !error && (
        <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-8 text-center">
          <ScanLine className="mx-auto h-10 w-10 text-zinc-600 light:text-zinc-400 mb-3" />
          <p className="text-sm text-zinc-400 light:text-zinc-600">
            Run a comparison to see match confidence, parsed components, and version evidence.
          </p>
        </div>
      )}
      {activeTab === 'lookup' && (
        <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-300 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4 space-y-4">
          <div className="investigation-panel-heading">
            <span className="investigation-icon">
              <Database size={20} aria-hidden="true" />
            </span>
            <div>
              <h2>Find a verified CPE name</h2>
              <p>Search the official NVD dictionary, then use a result in your comparison.</p>
            </div>
          </div>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (!lookupLoading) void handleLookup();
            }}
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  htmlFor="lookup-vendor"
                  className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
                >
                  Vendor
                </label>
                <input
                  id="lookup-vendor"
                  type="text"
                  value={lookupVendor}
                  onChange={(e) => setLookupVendor(e.target.value)}
                  placeholder="e.g. microsoft, cisco, paloaltonetworks"
                  className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:border-zinc-600 placeholder-zinc-500"
                />
              </div>
              <div>
                <label
                  htmlFor="lookup-product"
                  className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1"
                >
                  Product (optional)
                </label>
                <input
                  id="lookup-product"
                  type="text"
                  value={lookupProduct}
                  onChange={(e) => setLookupProduct(e.target.value)}
                  placeholder="e.g. windows_10, ios, pan-os"
                  className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:border-zinc-600 placeholder-zinc-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="submit"
                disabled={lookupLoading || (!lookupVendor.trim() && !lookupProduct.trim())}
                className="ui-primary"
              >
                {lookupLoading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                Search NVD
              </button>
            </div>
          </form>

          {lookupError && (
            <div
              role="alert"
              className="rounded-md border border-rose-500/30 bg-rose-500/10 p-3 flex items-center gap-2"
            >
              <AlertCircle className="h-4 w-4 text-rose-400 light:text-rose-800" />
              <span className="text-sm text-rose-300 light:text-rose-800">{lookupError}</span>
            </div>
          )}

          {lookupLoading && (
            <div className="investigation-empty" role="status">
              <Loader2 className="animate-spin" size={22} />
              <p>Searching the NVD dictionary…</p>
            </div>
          )}
          {lookupResults && (
            <div className="space-y-2">
              <div className="text-xs text-zinc-500 light:text-zinc-600">
                {lookupResults.totalResults} result{lookupResults.totalResults !== 1 ? 's' : ''} found
              </div>
              {lookupResults.results.length === 0 ? (
                <p className="text-xs text-zinc-500 light:text-zinc-600">
                  No verified CPEs found in the NVD dictionary for this vendor/product.
                </p>
              ) : (
                <div className="cpe-lookup-results">
                  {(lookupResults.results as NvdCpeSearchResult[]).map((cpe) => (
                    <div
                      key={cpe.cpeNameId || cpe.cpeName}
                      className="bg-zinc-950/70 dark:bg-zinc-950/70 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg p-2 flex items-center justify-between"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <code className="text-[10px] text-zinc-300 light:text-zinc-800 font-mono break-all block">
                            {cpe.cpeName}
                          </code>
                          {cpe.viaWildcardVendor && (
                            <span
                              className="shrink-0 text-[8px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border border-sky-500/30 bg-sky-500/10 text-sky-300 light:text-sky-800"
                              title="Found by matching the product name only — the NVD vendor label differs from what you typed"
                            >
                              matched by product
                            </span>
                          )}
                        </div>
                        {(cpe.vendor || cpe.product || cpe.title) && (
                          <div className="text-[9px] text-zinc-500 light:text-zinc-600 mt-0.5 truncate">
                            {[cpe.vendor, cpe.product, cpe.title].filter(Boolean).join(' / ')}
                          </div>
                        )}
                      </div>
                      <button
                        type="button"
                        className="ui-secondary cpe-use-result"
                        onClick={() => {
                          simulationSequence.current++;
                          setLoading(false);
                          setResult(null);
                          setError(null);
                          setAssetCpe(cpe.cpeName);
                          setAssetVendor(cpe.vendor);
                          setAssetProduct(cpe.product);
                          setAssetVersion(['*', '-'].includes(cpe.version) ? '' : cpe.version);
                          setVersionStartIncluding('');
                          setVersionEndExcluding('');
                          setActiveTab('match');
                        }}
                      >
                        Use as asset
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          if (await copyText(cpe.cpeName)) {
                            setCopiedCpe(cpe.cpeName);
                            setTimeout(() => setCopiedCpe(''), 2000);
                          }
                        }}
                        className="ml-2 p-1.5 rounded text-zinc-400 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900 hover:bg-zinc-800 light:hover:bg-zinc-200 transition"
                        aria-label={`Copy ${cpe.cpeName}`}
                        title="Copy CPE 2.3 name"
                      >
                        {copiedCpe === cpe.cpeName ? <Check size={15} /> : <Copy size={15} />}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

function CpeParseCard({ title, parsed }: { title: string; parsed: CpeParseResult }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="ui-panel rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium text-zinc-300 light:text-zinc-800">{title}</h3>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs text-zinc-500 light:text-zinc-600 hover:text-zinc-300 light:hover:text-zinc-800"
        >
          {expanded ? 'Collapse' : 'Expand'}
        </button>
      </div>
      <div className="font-mono text-xs text-zinc-400 light:text-zinc-600 break-all mb-2">{parsed.cpe}</div>
      {parsed.errors.length > 0 && (
        <div className="mb-2 space-y-1">
          {parsed.errors.map((err, i) => (
            <div key={i} className="flex items-center gap-1 text-xs text-rose-400 light:text-rose-700">
              <AlertCircle size={12} />
              {err}
            </div>
          ))}
        </div>
      )}
      {parsed.parsed && (
        <div>
          <div
            className={`inline-flex items-center px-1.5 py-0.25 rounded text-xs font-medium ${
              parsed.parsed.isValid
                ? 'bg-emerald-500/10 text-emerald-300 light:text-emerald-800 border border-emerald-500/30'
                : 'bg-rose-500/10 text-rose-300 light:text-rose-800 border border-rose-500/30'
            }`}
          >
            {parsed.parsed.isValid ? 'Valid CPE 2.3' : 'Invalid CPE'}
          </div>
        </div>
      )}
      {expanded && parsed.components.length > 0 && (
        <div className="mt-3 space-y-1">
          {parsed.components.map((comp) => (
            <div key={comp.field} className="grid grid-cols-4 gap-2 text-xs">
              <span className="text-zinc-500 light:text-zinc-600">{comp.field}</span>
              <span className="col-span-2 font-mono text-zinc-400 light:text-zinc-700 break-all">
                {comp.value || '—'}
              </span>
              <span className="text-zinc-600 light:text-zinc-500 text-right">
                {comp.isWildcard ? 'wildcard' : ''}
                {comp.isAmbiguous ? 'ambiguous' : ''}
                {!comp.isWildcard && !comp.isAmbiguous ? '' : ''}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AliasExpansionDisplay({ alias }: { alias: NonNullable<CpeMatchSimulation['assetVendorAlias']> }) {
  return (
    <div className="flex items-start gap-3">
      <Hash className="h-4 w-4 text-zinc-500 light:text-zinc-600 flex-shrink-0 mt-0.5" />
      <div className="flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium text-zinc-300 light:text-zinc-800">
            {alias.scope === 'VENDOR' ? 'Vendor' : 'Product'} alias:
          </span>
          <span className="text-xs font-mono text-zinc-400 light:text-zinc-600">{alias.canonical}</span>
          {alias.builtInMatches && (
            <span className="text-[10px] px-1.5 py-0.25 rounded bg-blue-500/10 text-blue-300 light:text-blue-800">
              Built-in
            </span>
          )}
          {alias.customMatches && (
            <span className="text-[10px] px-1.5 py-0.25 rounded bg-purple-500/10 text-purple-300 light:text-purple-800">
              Custom
            </span>
          )}
        </div>
        {alias.matchedAliases.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1">
            {alias.matchedAliases.map((a) => (
              <code
                key={a}
                className="text-[10px] px-1 py-0.25 bg-zinc-800/60 dark:bg-zinc-800 light:bg-zinc-100 rounded text-zinc-400 light:text-zinc-600"
              >
                {a}
              </code>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SeverityCard({ severity }: { severity: SeverityClassification }) {
  const tone = SEVERITY_TONES[severity.tier] || SEVERITY_TONES.INFORMATIONAL;
  return (
    <div className={`rounded-lg border p-4 ${tone.border} ${tone.bg}`}>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-zinc-300 light:text-zinc-800">Severity Classification</h3>
        <span className={`px-2 py-0.5 rounded text-sm font-bold ${tone.text} ${tone.light}`}>
          {severity.tier}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-4 text-xs">
        <div>
          <span className="text-zinc-500 light:text-zinc-600">Score</span>
          <div className="font-mono text-zinc-200 light:text-zinc-900">{severity.score.toFixed(1)}</div>
        </div>
        <div>
          <span className="text-zinc-500 light:text-zinc-600">Source</span>
          <div className="text-zinc-200 light:text-zinc-900">{severity.source}</div>
        </div>
      </div>
      {severity.vector && (
        <div className="mt-2">
          <span className="text-xs text-zinc-500 light:text-zinc-600">CVSS Vector</span>
          <div className="font-mono text-xs text-zinc-400 light:text-zinc-600 mt-0.5 break-all">
            {severity.vector}
          </div>
        </div>
      )}
      {severity.rationale.length > 0 && (
        <div className="mt-3 space-y-1">
          <span className="text-xs text-zinc-500 light:text-zinc-600">Rationale</span>
          <ul className="space-y-1">
            {severity.rationale.map((r, i) => (
              <li key={i} className="text-xs text-zinc-400 light:text-zinc-600 flex items-start gap-1">
                <span className="text-blue-400 light:text-blue-700">•</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
