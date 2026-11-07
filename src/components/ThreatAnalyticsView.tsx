import { PageHeading } from './PageHeading';
import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useApp } from '../context/AppContext';
import { ThreatAnalytics, TimelinePoint, VendorAnalytics, CveScoreBin } from '../types';
import {
  BarChart3,
  RefreshCw,
  Download,
  Copy,
  Check,
  Loader2,
  Calendar,
  TrendingUp,
  Flame,
  Database,
  AlertCircle,
} from 'lucide-react';
import { copyText } from '../utils/clipboard';
import { niceTicks } from '../utils/chartTicks';

import { formatDate as fmtDate } from '../utils/dateTime';

const formatDate = (value: string, timezone?: string) => fmtDate(value, timezone);

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#22c55e',
  UNKNOWN: '#9ca3af',
};

const TIMELINE_OPTIONS: { value: string; label: string }[] = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: '365d', label: 'Last 365 days' },
  { value: 'all', label: 'All time' },
];

const SCORE_COLORS = ['#3b82f6', '#60a5fa', '#f59e0b', '#f97316', '#ef4444'];

function fmtNum(value: number) {
  return value >= 1000 ? value.toLocaleString() : String(value);
}

function truncateLabel(label: string, maxChars: number) {
  return label.length > maxChars ? `${label.slice(0, maxChars)}…` : label;
}

function Axis({
  ticks,
  maxValue,
  plotHeight,
  plotWidth,
  originY,
  originX,
  label,
}: {
  ticks: number[];
  maxValue: number;
  plotHeight: number;
  plotWidth: number;
  originY: number;
  originX: number;
  label?: string;
}) {
  const yFor = (v: number) => originY - (v / Math.max(maxValue, 1)) * plotHeight;
  return (
    <g>
      {label && (
        <text
          x={-plotHeight / 2 - 10}
          y={-24}
          textAnchor="middle"
          fontSize={10}
          fill="currentColor"
          className="text-zinc-500 light:text-zinc-600"
          transform={`rotate(-90 ${-plotHeight / 2 - 24} 0)`}
        >
          {label}
        </text>
      )}
      {ticks.map((t) => (
        <g key={t}>
          <line
            x1={originX}
            y1={yFor(t)}
            x2={originX + plotWidth}
            y2={yFor(t)}
            stroke="currentColor"
            strokeWidth={1}
            opacity={0.08}
          />
          <text
            x={originX - 8}
            y={yFor(t) + 3}
            textAnchor="end"
            fontSize={10}
            fill="currentColor"
            className="text-zinc-500 light:text-zinc-600"
          >
            {fmtNum(t)}
          </text>
        </g>
      ))}
      <line
        x1={originX}
        y1={originY}
        x2={originX + plotWidth}
        y2={originY}
        stroke="currentColor"
        strokeWidth={1}
        opacity={0.25}
      />
      <line
        x1={originX}
        y1={originY - plotHeight}
        x2={originX}
        y2={originY}
        stroke="currentColor"
        strokeWidth={1}
        opacity={0.25}
      />
    </g>
  );
}

function BarChart({
  data,
  maxValue,
  color,
  unit = '',
  showLabels = true,
}: {
  data: { label: string; value: number }[];
  maxValue: number;
  color?: string;
  unit?: string;
  showLabels?: boolean;
}) {
  const barHeight = 140;
  const barWidth = 44;
  const gap = 14;
  const chartHeight = barHeight + 50;
  const chartWidth = Math.max(data.length * (barWidth + gap) + 60, 220);
  const plotTop = 16;
  const plotBottom = 44;
  const plotHeight = barHeight;
  const originX = 36;
  const originY = plotTop + plotHeight;
  const plotWidth = chartWidth - originX - 16;
  const ticks = niceTicks(maxValue);
  const yFor = (v: number) => originY - (v / Math.max(maxValue, 1)) * plotHeight;

  if (data.length === 0) {
    return (
      <div className="h-40 flex items-center justify-center text-zinc-500 light:text-zinc-600">
        <span className="text-sm">No data</span>
      </div>
    );
  }

  return (
    <svg
      width="100%"
      height={chartHeight}
      viewBox={`0 0 ${chartWidth} ${chartHeight}`}
      shapeRendering="crispEdges"
    >
      <Axis
        ticks={ticks}
        maxValue={maxValue}
        plotHeight={plotHeight}
        plotWidth={plotWidth}
        originX={originX}
        originY={originY}
        label={unit ? unit : 'Count'}
      />
      {data.map((d, i) => {
        const height = (d.value / Math.max(maxValue, 1)) * plotHeight;
        const x = originX + i * (barWidth + gap);
        return (
          <g key={d.label} transform={`translate(${x}, ${originY})`}>
            <rect
              x={0}
              y={-height}
              width={barWidth}
              height={Math.max(height, 0)}
              fill={color || '#3b82f6'}
              rx={3}
              opacity={0.92}
            />
            <text
              x={barWidth / 2}
              y={-height - 5}
              textAnchor="middle"
              fontSize={10}
              fill="currentColor"
              className="text-zinc-300 light:text-zinc-800"
            >
              {d.value > 0 ? `${fmtNum(d.value)}${unit}` : ''}
            </text>
            {showLabels && (
              <text
                x={barWidth / 2}
                y={16}
                textAnchor="middle"
                fontSize={10}
                fill="currentColor"
                className="text-zinc-500 light:text-zinc-600"
              >
                {truncateLabel(d.label, 12)}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

function TimelineChart({ data }: { data: TimelinePoint[] }) {
  const chartHeight = 200;
  const chartWidth = 580;
  const padding = { top: 26, right: 16, bottom: 46, left: 46 };
  const plotWidth = chartWidth - padding.left - padding.right;
  const plotHeight = chartHeight - padding.top - padding.bottom;
  const originX = padding.left;
  const originY = padding.top + plotHeight;

  const totalMax = Math.max(...data.map((d) => d.cveCount), 1);
  const critMax = Math.max(...data.map((d) => d.critical), 1);
  const highMax = Math.max(...data.map((d) => d.high), 1);
  const ticks = niceTicks(totalMax);
  const yMax = Math.max(ticks[ticks.length - 1], 1);

  if (data.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-zinc-500 light:text-zinc-600">
        <Database className="h-6 w-6 mr-2" />
        <span className="text-sm">No data for the selected timeline.</span>
      </div>
    );
  }

  const slot = plotWidth / data.length;
  const groupWidth = Math.min(Math.max(slot - 6, 2), 28);
  const halfWidth = groupWidth / 2;
  const showLabelEvery = Math.ceil(Math.max(data.length / 12, 1));
  const rotateLabels = data.length > 8;

  return (
    <svg
      width="100%"
      height={chartHeight}
      viewBox={`0 0 ${chartWidth} ${chartHeight}`}
      shapeRendering="crispEdges"
    >
      <g transform={`translate(${originX + plotWidth - 100}, ${padding.top})`}>
        <rect x={0} y={0} width={96} height={20} rx={4} fill="currentColor" opacity={0.06} />
        <rect x={8} y={5} width={9} height={9} fill={SEVERITY_COLORS.CRITICAL} rx={1} />
        <text x={22} y={13} fontSize={10} fill="currentColor" className="text-zinc-400 light:text-zinc-600">
          Critical
        </text>
        <rect x={60} y={5} width={9} height={9} fill={SEVERITY_COLORS.HIGH} rx={1} />
        <text x={74} y={13} fontSize={10} fill="currentColor" className="text-zinc-400 light:text-zinc-600">
          High
        </text>
      </g>
      <Axis
        ticks={ticks}
        maxValue={yMax}
        plotHeight={plotHeight}
        plotWidth={plotWidth}
        originX={originX}
        originY={originY}
        label="CVEs published"
      />
      {data.map((d, i) => {
        const gx = originX + i * slot + (slot - groupWidth) / 2;
        const critH = (d.critical / critMax) * plotHeight;
        const highH = (d.high / highMax) * plotHeight;
        const valueY = originY - Math.max(critH, highH);
        const showLabel = i % showLabelEvery === 0 || i === data.length - 1;
        const angle = rotateLabels ? -40 : 0;
        return (
          <g key={d.label} transform={`translate(${gx}, 0)`}>
            <rect
              x={0}
              y={originY - critH}
              width={halfWidth}
              height={Math.max(critH, 0)}
              fill={SEVERITY_COLORS.CRITICAL}
              stroke={`${SEVERITY_COLORS.CRITICAL}80`}
              strokeWidth={0.5}
              rx={2}
            />
            <rect
              x={halfWidth}
              y={originY - highH}
              width={halfWidth}
              height={Math.max(highH, 0)}
              fill={SEVERITY_COLORS.HIGH}
              stroke={`${SEVERITY_COLORS.HIGH}80`}
              strokeWidth={0.5}
              rx={2}
            />
            {d.cveCount > 0 && (
              <g>
                <rect
                  x={-10}
                  y={valueY - 12}
                  width={groupWidth + 20}
                  height={11}
                  fill="currentColor"
                  opacity={0.08}
                  rx={3}
                />
                <text
                  x={groupWidth / 2}
                  y={valueY - 4}
                  textAnchor="middle"
                  fontSize={9}
                  fontWeight="700"
                  fill="currentColor"
                  className="text-zinc-300 light:text-zinc-700"
                >
                  {fmtNum(d.cveCount)}
                </text>
              </g>
            )}
            {showLabel && (
              <text
                x={groupWidth / 2}
                y={originY + 16}
                textAnchor="middle"
                fontSize={9}
                fill="currentColor"
                className="text-zinc-500 light:text-zinc-600"
                transform={`rotate(${angle} ${gx + groupWidth / 2} ${originY + 16})`}
              >
                {truncateLabel(d.label, rotateLabels ? 8 : 12)}
              </text>
            )}
          </g>
        );
      })}
      <text
        x={originX + plotWidth / 2}
        y={chartHeight - 6}
        textAnchor="middle"
        fontSize={10}
        fill="currentColor"
        className="text-zinc-500 light:text-zinc-600"
      >
        Timeline bucket
      </text>
    </svg>
  );
}

function PieChart({
  data,
  size = 170,
}: {
  data: { label: string; value: number; color?: string }[];
  size?: number;
}) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  if (total === 0) {
    return (
      <div className="h-36 flex items-center justify-center text-zinc-500 light:text-zinc-600">
        <span className="text-sm">No data</span>
      </div>
    );
  }
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 14;
  const rInner = r * 0.55;

  let offset = 0;
  const slices = data
    .map((d) => {
      const percentage = d.value / total;
      const degrees = percentage * 360;
      const startAngle = offset;
      const endAngle = offset + degrees;
      offset += degrees;
      if (percentage <= 0) return null;

      const startRad = (startAngle - 90) * (Math.PI / 180);
      const endRad = (endAngle - 90) * (Math.PI / 180);
      const x1 = cx + r * Math.cos(startRad);
      const y1 = cy + r * Math.sin(startRad);
      const x2 = cx + r * Math.cos(endRad);
      const y2 = cy + r * Math.sin(endRad);
      const x1i = cx + rInner * Math.cos(startRad);
      const y1i = cy + rInner * Math.sin(startRad);
      const x2i = cx + rInner * Math.cos(endRad);
      const y2i = cy + rInner * Math.sin(endRad);
      const largeArc = degrees > 180 ? 1 : 0;
      const path = `M ${x1},${y1} A ${r},${r} 0 ${largeArc} 1 ${x2},${y2} L ${x2i},${y2i} A ${rInner},${rInner} 0 ${largeArc} 0 ${x1i},${y1i} Z`;
      const midAngle = (startAngle + endAngle) / 2;
      const midRad = (midAngle - 90) * (Math.PI / 180);
      const labelR = (r + rInner) / 2;
      const lx = cx + labelR * Math.cos(midRad);
      const ly = cy + labelR * Math.sin(midRad);
      const pct = Math.round(percentage * 100);
      return {
        path,
        color: d.color || '#9ca3af',
        label: d.label,
        value: d.value,
        percentage: pct,
        lx,
        ly,
      };
    })
    .filter(Boolean) as Array<{
    path: string;
    color: string;
    label: string;
    value: number;
    percentage: number;
    lx: number;
    ly: number;
  }>;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} shapeRendering="crispEdges">
      {slices.map((s, i) => (
        <g key={`${s.label}-${i}`}>
          <path d={s.path} fill={s.color} opacity={0.92} />
          {s.percentage >= 6 && (
            <text
              x={s.lx}
              y={s.ly}
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={11}
              fontWeight="600"
              fill="#ffffff"
            >
              {s.percentage}%
            </text>
          )}
        </g>
      ))}
      <text
        x={cx}
        y={cy - 4}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={15}
        fontWeight="700"
        fill="currentColor"
        className="text-zinc-100 light:text-zinc-900"
      >
        {total}
      </text>
      <text
        x={cx}
        y={cy + 14}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={10}
        fill="currentColor"
        className="text-zinc-500 light:text-zinc-600"
      >
        total
      </text>
    </svg>
  );
}

function HistogramChart({ bins }: { bins: CveScoreBin[] }) {
  const maxValue = Math.max(...bins.map((b) => b.count), 1);
  const barHeight = 140;
  const chartHeight = barHeight + 50;
  const chartWidth = 460;
  const padding = { top: 16, right: 24, bottom: 44, left: 44 };
  const plotHeight = barHeight;
  const originX = padding.left;
  const originY = padding.top + plotHeight;
  const plotWidth = chartWidth - padding.left - padding.right;
  const ticks = niceTicks(maxValue);
  const yFor = (v: number) => originY - (v / Math.max(maxValue, 1)) * plotHeight;
  const barWidth = 46;
  const gap = 8;

  if (bins.length === 0) {
    return (
      <div className="h-36 flex items-center justify-center text-zinc-500 light:text-zinc-600">
        <span className="text-sm">No data</span>
      </div>
    );
  }

  return (
    <svg
      width="100%"
      height={chartHeight}
      viewBox={`0 0 ${chartWidth} ${chartHeight}`}
      shapeRendering="crispEdges"
    >
      <Axis
        ticks={ticks}
        maxValue={maxValue}
        plotHeight={plotHeight}
        plotWidth={plotWidth}
        originX={originX}
        originY={originY}
        label="CVE count"
      />
      {bins.map((bin, i) => {
        const height = (bin.count / Math.max(maxValue, 1)) * plotHeight;
        const x = originX + i * (barWidth + gap);
        return (
          <g key={bin.range} transform={`translate(${x}, ${originY})`}>
            <rect
              x={0}
              y={-height}
              width={barWidth}
              height={Math.max(height, 0)}
              fill={SCORE_COLORS[i % SCORE_COLORS.length]}
              rx={2}
              opacity={0.9}
            />
            {bin.count > 0 && (
              <text
                x={barWidth / 2}
                y={-height - 4}
                textAnchor="middle"
                fontSize={10}
                fill="currentColor"
                className="text-zinc-300 light:text-zinc-800"
              >
                {fmtNum(bin.count)}
              </text>
            )}
            <text
              x={barWidth / 2}
              y={16}
              textAnchor="middle"
              fontSize={9}
              fill="currentColor"
              className="text-zinc-500 light:text-zinc-600"
            >
              {bin.range}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

function Legend({ items }: { items: { label: string; color: string; value: number }[] }) {
  const total = items.reduce((sum, i) => sum + i.value, 0);
  return (
    <div className="flex flex-wrap gap-3">
      {items.map((item) => {
        const pct = total > 0 ? ((item.value / total) * 100).toFixed(1) : '0';
        return (
          <div key={item.label} className="flex items-center gap-2">
            <span className="w-3 h-3 rounded" style={{ backgroundColor: item.color }} />
            <span className="text-xs text-zinc-400 light:text-zinc-600">{item.label}</span>
            <span className="text-xs font-mono text-zinc-300 light:text-zinc-800">
              {fmtNum(item.value)} ({pct}%)
            </span>
          </div>
        );
      })}
    </div>
  );
}

export const ThreatAnalyticsView: React.FC = () => {
  const { fetchThreatAnalytics, settings } = useApp();
  const fetchRef = useRef(fetchThreatAnalytics);
  // The context value is rebuilt on every render, which makes `fetchThreatAnalytics`
  // a new reference each render. Holding the latest ref decouples data loading from
  // that reference, so analytics are only re-fetched when the selected range changes
  // (not on every re-render). This eliminates the loading-spinner "blink".
  useEffect(() => {
    fetchRef.current = fetchThreatAnalytics;
  });

  const [range, setRange] = useState('30d');
  const [analytics, setAnalytics] = useState<ThreatAnalytics | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const requestId = useRef(0);

  const loadAnalytics = useCallback(async () => {
    setLoading(true);
    setError(null);
    const currentId = ++requestId.current;
    try {
      const data = await fetchRef.current(range, 10);
      // Ignore results from superseded requests (e.g. rapid range changes).
      if (requestId.current !== currentId) return;
      setAnalytics(data);
    } catch (err) {
      if (requestId.current !== currentId) return;
      setError(err instanceof Error ? err.message : 'Failed to load analytics');
    } finally {
      if (requestId.current !== currentId) return;
      setLoading(false);
    }
  }, [range]);

  useEffect(() => {
    void loadAnalytics();
  }, [loadAnalytics]);

  const handleRangeChange = (newRange: string) => {
    setRange(newRange);
  };

  const handleDownload = () => {
    if (!analytics) return;
    const blob = new Blob([JSON.stringify(analytics, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-analytics-${range}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopy = async () => {
    if (!analytics) return;
    const success = await copyText(JSON.stringify(analytics, null, 2));
    setCopied(success);
    setTimeout(() => setCopied(false), 2000);
  };

  const severityData = useMemo(
    () =>
      analytics
        ? [
            {
              label: 'Critical',
              value: analytics.severityDistribution.critical,
              color: SEVERITY_COLORS.CRITICAL,
            },
            { label: 'High', value: analytics.severityDistribution.high, color: SEVERITY_COLORS.HIGH },
            { label: 'Medium', value: analytics.severityDistribution.medium, color: SEVERITY_COLORS.MEDIUM },
            { label: 'Low', value: analytics.severityDistribution.low, color: SEVERITY_COLORS.LOW },
            {
              label: 'Unknown',
              value: analytics.severityDistribution.unknown,
              color: SEVERITY_COLORS.UNKNOWN,
            },
          ]
        : [],
    [analytics],
  );

  const exploitData = useMemo(
    () =>
      analytics
        ? [
            {
              label: 'Active Weaponized',
              value: analytics.exploitStatusDistribution.activeWeaponized,
              color: SEVERITY_COLORS.CRITICAL,
            },
            {
              label: 'Reported In Wild',
              value: analytics.exploitStatusDistribution.reportedInWild,
              color: SEVERITY_COLORS.HIGH,
            },
            {
              label: 'PoC Available',
              value: analytics.exploitStatusDistribution.pocAvailable,
              color: SEVERITY_COLORS.MEDIUM,
            },
            {
              label: 'No Known Exploit',
              value: analytics.exploitStatusDistribution.none,
              color: SEVERITY_COLORS.LOW,
            },
          ]
        : [],
    [analytics],
  );

  return (
    <div className="space-y-6">
      <PageHeading
        page="threat-analytics"
        title="Threat Analytics & Trends"
        children={
          <span className="text-sm text-zinc-400 light:text-zinc-600">
            Aggregated vulnerability trends and severity distributions from the NVD CVE cache. Select a time
            range to update all charts below.
          </span>
        }
      />

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <Calendar className="h-4 w-4 text-zinc-500" />
          <span className="text-sm text-zinc-400 light:text-zinc-600">Timeline:</span>
          {TIMELINE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              onClick={() => handleRangeChange(opt.value)}
              className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                range === opt.value
                  ? 'bg-blue-500/15 border border-blue-400/30 text-blue-300 light:text-blue-800'
                  : 'bg-zinc-800/50 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-300 light:text-zinc-700 hover:bg-zinc-700/50'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          {analytics && (
            <>
              <button
                onClick={handleCopy}
                className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 rounded transition-colors"
                title="Copy analytics JSON"
              >
                {copied ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
              </button>
              <button
                onClick={handleDownload}
                className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 rounded transition-colors"
                title="Download analytics JSON"
              >
                <Download size={16} />
              </button>
            </>
          )}
          <button
            onClick={loadAnalytics}
            className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 rounded transition-colors"
            title="Refresh analytics"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/10 p-3 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 text-rose-400 light:text-rose-800" />
          <span className="text-sm text-rose-300 light:text-rose-800">{error}</span>
        </div>
      )}

      {loading && !analytics && (
        <div className="rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 text-blue-400 animate-spin mb-2" />
          <p className="text-sm text-zinc-400 light:text-zinc-600">Loading threat analytics data...</p>
        </div>
      )}

      {!analytics && !loading && !error && (
        <div className="rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-8 text-center">
          <BarChart3 className="mx-auto h-10 w-10 text-zinc-600 light:text-zinc-400 mb-3" />
          <p className="text-sm text-zinc-400 light:text-zinc-600">
            Select a timeline range to view threat analytics.
          </p>
        </div>
      )}

      {analytics && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <KpiCard
              icon={<Database className="h-5 w-5 text-blue-400" />}
              label="Total CVEs"
              value={analytics.totalCves.toLocaleString()}
              subtitle="In selected range"
            />
            <KpiCard
              icon={<Flame className="h-5 w-5 text-amber-400" />}
              label="CISA KEV"
              value={analytics.kevCount.toLocaleString()}
              subtitle="Known exploited"
            />
            <KpiCard
              icon={<TrendingUp className="h-5 w-5 text-rose-400" />}
              label="Critical + High"
              value={(
                analytics.severityDistribution.critical + analytics.severityDistribution.high
              ).toLocaleString()}
              subtitle="Severe vulnerabilities"
            />
            <KpiCard
              icon={<BarChart3 className="h-5 w-5 text-teal-400" />}
              label="Generated"
              value={formatDate(analytics.generatedAt, settings.timezone)}
              subtitle="Data freshness"
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <ChartCard title="CVEs Published Over Time" subtitle="Critical vs High severity">
              <div className="overflow-x-auto">
                <TimelineChart data={analytics.timeline} />
              </div>
            </ChartCard>

            <ChartCard title="Severity Distribution" subtitle="Share of CVEs by severity">
              <div className="flex flex-col items-center gap-3">
                <PieChart data={severityData} />
                <Legend items={severityData} />
              </div>
            </ChartCard>

            <ChartCard title="Exploit Status" subtitle="Active exploitation posture">
              <div className="flex flex-col items-center gap-3">
                <PieChart data={exploitData} />
                <Legend items={exploitData} />
              </div>
            </ChartCard>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ChartCard
              title="Top Vendors by CVE Count"
              subtitle={`Top ${Math.min(10, analytics.topVendors.length)} vendors`}
            >
              <div className="overflow-x-auto">
                <BarChart
                  data={analytics.topVendors.map((v: VendorAnalytics) => ({
                    label: v.vendor,
                    value: v.cveCount,
                  }))}
                  maxValue={Math.max(...analytics.topVendors.map((v) => v.cveCount), 1)}
                  color="#3b82f6"
                  unit=""
                  showLabels={false}
                />
              </div>
              <div className="mt-3 space-y-1">
                {analytics.topVendors.map((v: VendorAnalytics) => (
                  <div key={v.vendor} className="flex items-center justify-between text-xs">
                    <span className="text-zinc-400 light:text-zinc-600 truncate max-w-[140px]">
                      {v.vendor}
                    </span>
                    <span className="font-mono text-zinc-300 light:text-zinc-800">
                      {v.cveCount.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </ChartCard>

            <ChartCard title="CVSS Score Distribution" subtitle="Score bands">
              <div className="overflow-x-auto">
                <HistogramChart bins={analytics.cvssScoreHistogram} />
              </div>
            </ChartCard>
          </div>
        </>
      )}
    </div>
  );
};

function KpiCard({
  icon,
  label,
  value,
  subtitle,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  subtitle: string;
}) {
  return (
    <div className="rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
      <div className="flex items-center gap-2 mb-1">{icon}</div>
      <div className="text-2xl font-bold text-zinc-100 light:text-zinc-900">{value}</div>
      <div className="text-sm text-zinc-400 light:text-zinc-600">{label}</div>
      <div className="text-xs text-zinc-500 light:text-zinc-600 mt-0.5">{subtitle}</div>
    </div>
  );
}

function ChartCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
      <div className="mb-3">
        <h2 className="text-sm font-medium text-zinc-300 light:text-zinc-800">{title}</h2>
        {subtitle && <p className="text-xs text-zinc-500 light:text-zinc-600">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}
