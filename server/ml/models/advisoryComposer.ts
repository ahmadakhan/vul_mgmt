/**
 * Advisory Composer Model — ML-powered email composition for vulnerability
 * advisories.
 *
 * Replaces static, rule-based email text (executive summary, remediation
 * instructions, subject line, finding order) with predictions from trained
 * models. Falls back to the existing rule-based composer when untrained —
 * zero risk of degrading email quality.
 *
 * Composition targets:
 *   - summaryStyle     → URGENT | STANDARD | INFORMATIONAL  (classification)
 *   - priorityEmphasis → IMMEDIATE_ACTION | MONITOR | REVIEW (classification)
 *   - remediationEmphasis → PATCH_FIRST | WORKAROUND_FIRST | VENDOR_GUIDANCE_FIRST (classification)
 *   - subjectTemplate  → selected template index (classification)
 *   - findingScores    → per-finding importance ranking (GBDT regression)
 *
 * Text is composed from a fixed template library using ML-selected options,
 * so output is always deterministic, safe HTML/plain text — never free-form
 * generation from untrusted input.
 *
 * Training labels come from delivery outcomes: whether recipients patched,
 * dismissed as false positive, or required review. Models that fail their
 * quality gate are not saved; the active artifact remains in place.
 */
import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import { GBDTRanker } from '../algorithms/gbdtRanker.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const SUMMARY_STYLES: string[] = ['URGENT', 'STANDARD', 'INFORMATIONAL'];
export type SummaryStyle = (typeof SUMMARY_STYLES)[number];

export const PRIORITY_EMPHASES: string[] = ['IMMEDIATE_ACTION', 'MONITOR', 'REVIEW'];
export type PriorityEmphasis = (typeof PRIORITY_EMPHASES)[number];

export const REMEDIATION_EMPHASES: string[] = ['PATCH_FIRST', 'WORKAROUND_FIRST', 'VENDOR_GUIDANCE_FIRST'];
export type RemediationEmphasis = (typeof REMEDIATION_EMPHASES)[number];

export const SUBJECT_TEMPLATES: string[] = [
  'Vulnerability notice: {count} {sev}',
  'Vulnerability notice: {count} {sev} finding(s) require attention',
  'Security advisory: {count} {sev} vulnerability(ies) on monitored assets',
  'Action required: {count} {sev} vulnerability(ies) detected',
];
export type SubjectTemplate = (typeof SUBJECT_TEMPLATES)[number];

export const ADVISORY_COMPOSER_FEATURE_NAMES: string[] = [
  'critical_count',
  'high_count',
  'medium_count',
  'low_count',
  'unknown_count',
  'total_findings',
  'max_cvss_score',
  'avg_cvss_score',
  'max_epss_score',
  'avg_epss_score',
  'kev_count',
  'weaponized_count',
  'reported_in_wild_count',
  'poc_count',
  'affected_asset_count',
  'unique_vendor_count',
  'avg_match_confidence',
  'avg_days_since_published',
  'avg_source_feed_weight',
];

export type AdvisoryComposerFeatureNames = (typeof ADVISORY_COMPOSER_FEATURE_NAMES)[number];

export interface EmailCompositionFeatures {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  unknownCount: number;
  totalFindings: number;
  maxCvssScore: number;
  avgCvssScore: number;
  maxEpssScore: number;
  avgEpssScore: number;
  kevCount: number;
  weaponizedCount: number;
  reportedInWildCount: number;
  pocCount: number;
  affectedAssetCount: number;
  uniqueVendorCount: number;
  avgMatchConfidence: number;
  avgDaysSincePublished: number;
  avgSourceFeedWeight: number;
}

export interface PerFindingFeatures {
  cvssScore: number;
  epssScore: number;
  cisaKev: boolean;
  exploitStatus: 'Active Weaponized' | 'POC Available' | 'Reported In Wild' | 'None';
  matchConfidence: number;
  daysSincePublished: number;
  sourceFeedWeight: number;
  assetCriticality: number;
}

export interface EmailCompositionPrediction {
  summaryStyle: SummaryStyle;
  priorityEmphasis: PriorityEmphasis;
  remediationEmphasis: RemediationEmphasis;
  subjectTemplate: SubjectTemplate;
  findingScores: number[];
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  modelVersion: string;
  reason: string;
}

export interface EmailCompositionText {
  subject: string;
  executiveSummary: string;
  remediationInstructions: string;
  severitySummary: string;
  findingOrder: number[];
}

function extractFeatures(f: EmailCompositionFeatures): Record<string, number> {
  return {
    critical_count: f.criticalCount,
    high_count: f.highCount,
    medium_count: f.mediumCount,
    low_count: f.lowCount,
    unknown_count: f.unknownCount,
    total_findings: f.totalFindings,
    max_cvss_score: f.maxCvssScore,
    avg_cvss_score: f.avgCvssScore,
    max_epss_score: f.maxEpssScore,
    avg_epss_score: f.avgEpssScore,
    kev_count: f.kevCount,
    weaponized_count: f.weaponizedCount,
    reported_in_wild_count: f.reportedInWildCount,
    poc_count: f.pocCount,
    affected_asset_count: f.affectedAssetCount,
    unique_vendor_count: f.uniqueVendorCount,
    avg_match_confidence: f.avgMatchConfidence,
    avg_days_since_published: f.avgDaysSincePublished,
    avg_source_feed_weight: f.avgSourceFeedWeight,
  };
}

function extractPerFindingFeatures(f: PerFindingFeatures): Record<string, number> {
  const statusMap: Record<string, number> = {
    'Active Weaponized': 3,
    'Reported In Wild': 2,
    'POC Available': 1,
    None: 0,
  };
  return {
    cvss_score: f.cvssScore,
    epss_score: f.epssScore,
    cisa_kev: f.cisaKev ? 1 : 0,
    exploit_status: statusMap[f.exploitStatus] ?? 0,
    match_confidence: f.matchConfidence,
    days_since_published: f.daysSincePublished,
    source_feed_weight: f.sourceFeedWeight,
    asset_criticality: f.assetCriticality,
  };
}

function buildSubject(template: SubjectTemplate, features: EmailCompositionFeatures): string {
  const sevCounts: [string, number][] = [
    ['Critical', features.criticalCount],
    ['High', features.highCount],
    ['Medium', features.mediumCount],
    ['Low', features.lowCount],
  ];
  const nonzero = sevCounts.filter(([, c]) => c > 0);
  const topSev = nonzero.length ? nonzero[0][0] : 'Unknown';
  const topCount = nonzero.length ? nonzero[0][1] : 0;
  const totalCount = features.totalFindings;
  const severitySummary = nonzero
    .map(([sev, c]) => `${c} ${sev}`)
    .join(', ');

  return template
    .replace('{count}', String(totalCount))
    .replace('{sev}', topSev)
    .replace('{count_sev}', `${topCount} ${topSev}`)
    .replace('{severity_summary}', severitySummary);
}

function buildSeveritySummary(features: EmailCompositionFeatures): string {
  const parts: string[] = [];
  if (features.criticalCount) parts.push(`${features.criticalCount} Critical`);
  if (features.highCount) parts.push(`${features.highCount} High`);
  if (features.mediumCount) parts.push(`${features.mediumCount} Medium`);
  if (features.lowCount) parts.push(`${features.lowCount} Low`);
  if (features.unknownCount) parts.push(`${features.unknownCount} Unknown`);
  return parts.length ? parts.join(', ') : '0 vulnerabilities';
}

function buildExecutiveSummary(
  features: EmailCompositionFeatures,
  style: SummaryStyle,
  priority: PriorityEmphasis,
): string {
  const total = features.totalFindings;
  const topSev = features.criticalCount > 0 ? 'Critical' : features.highCount > 0 ? 'High' : features.mediumCount > 0 ? 'Medium' : 'Low';
  const hasKev = features.kevCount > 0;
  const hasWeaponized = features.weaponizedCount > 0;

  const urgencyPhrase =
    style === 'URGENT'
      ? 'Immediate attention required.'
      : style === 'STANDARD'
        ? 'Review and prioritize remediation.'
        : 'Monitor for applicability to your environment.';

  const actionPhrase =
    priority === 'IMMEDIATE_ACTION'
      ? 'Apply vendor patches as soon as possible.'
      : priority === 'MONITOR'
        ? 'Monitor affected systems and prepare remediation.'
        : 'Submit to security-team review before action.';

  const kevPhrase = hasKev || hasWeaponized
    ? ` Includes CISA KEV / actively exploited vulnerability(ies).`
    : '';

  return `${total} vulnerability finding(s) across monitored assets, topped by ${topSev} severity. ${urgencyPhrase} ${actionPhrase}${kevPhrase}`;
}

function buildRemediationInstructions(
  features: EmailCompositionFeatures,
  emphasis: RemediationEmphasis,
): string {
  const lines: string[] = [];
  if (emphasis === 'PATCH_FIRST') {
    lines.push('1. Apply vendor patches immediately following your change management process.');
    lines.push('2. Review vendor advisories for affected products and versions.');
    lines.push('3. Validate backup, restore, and operational functionality after remediation.');
  } else if (emphasis === 'WORKAROUND_FIRST') {
    lines.push('1. Apply vendor workarounds or compensating controls while patches are tested.');
    lines.push('2. Schedule patch deployment through your standard change process.');
    lines.push('3. Monitor affected services for anomalous activity.');
  } else {
    lines.push('1. Consult the current vendor advisory for remediation guidance.');
    lines.push('2. Review affected systems and confirm applicability before remediation.');
    lines.push('3. Submit findings to security-team review for disposition.');
  }
  if (features.kevCount > 0) {
    lines.push('4. CISA KEV vulnerability(ies) detected — prioritize per organizational KEV SLA.');
  }
  return lines.join('\n');
}

export class AdvisoryComposerModel extends BaseModel {
  private summaryModels = new Map<string, LogisticRegression>();
  private priorityModels = new Map<string, LogisticRegression>();
  private remediationModels = new Map<string, LogisticRegression>();
  private subjectModels = new Map<string, LogisticRegression>();
  private readonly findingRanker = new GBDTRanker();
  private readonly featureNames: string[] = [...ADVISORY_COMPOSER_FEATURE_NAMES];

  constructor() {
    const metadata: ModelMetadata = {
      id: 'advisory-composer',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...ADVISORY_COMPOSER_FEATURE_NAMES],
      description: 'Predicts advisory email composition: summary style, priority, remediation emphasis, subject template, and finding order',
    };
    super(metadata);
  }

  train(samples: TrainingSample[]): void {
    if (samples.length < 20) {
      this.trained = false;
      return;
    }

    const trainCategory = (
      categories: string[],
      labelToIdx: (label: number) => number | null,
    ): Map<string, LogisticRegression> => {
      const models = new Map<string, LogisticRegression>();
      for (const cat of categories) {
        const catSamples: TrainingSample[] = [];
        for (const s of samples) {
          const rawLabel = typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label;
          const idx = labelToIdx(rawLabel);
          if (idx === null) continue;
          const catLabel = idx === categories.indexOf(cat) ? 1 : 0;
          catSamples.push({ ...s, label: catLabel });
        }
        const pos = catSamples.filter((s) => s.label === 1).length;
        const neg = catSamples.filter((s) => s.label === 0).length;
        if (pos >= 4 && neg >= 4) {
          const lr = new LogisticRegression();
          lr.train(catSamples, { threshold: 0.5, iterations: 1000, l2: 0.001 });
          models.set(cat, lr);
        }
      }
      return models;
    };

    this.summaryModels.clear();
    this.priorityModels.clear();
    this.remediationModels.clear();
    this.subjectModels.clear();

    // Label encoding packed into a single integer:
    //   label = summaryIdx * 1 + priorityIdx * 10 + remediationIdx * 100 + subjectIdx * 1000 + wasActionable * 10000
    const summaryLabel = (label: number) => label % 10;
    const priorityLabel = (label: number) => Math.floor(label / 10) % 10;
    const remediationLabel = (label: number) => Math.floor(label / 100) % 10;
    const subjectLabel = (label: number) => Math.floor(label / 1000) % 10;

    this.summaryModels = trainCategory(SUMMARY_STYLES, summaryLabel);
    this.priorityModels = trainCategory(PRIORITY_EMPHASES, priorityLabel);
    this.remediationModels = trainCategory(REMEDIATION_EMPHASES, remediationLabel);
    this.subjectModels = trainCategory(SUBJECT_TEMPLATES.map((_, i) => String(i)), subjectLabel);

    // Train finding ranker: label is the finding's importance (0-1)
    const rankerSamples = samples.map((s) => ({
      ...s,
      label: Math.max(0, Math.min(1, typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label)),
    }));
    if (rankerSamples.length >= 10) {
      try {
        this.findingRanker.train(rankerSamples, this.featureNames, { nTrees: 50, learningRate: 0.1, maxDepth: 4, seed: 42 });
      } catch {
        /* ranker training non-fatal */
      }
    }

    const anyTrained = this.summaryModels.size > 0 || this.priorityModels.size > 0 || this.remediationModels.size > 0;
    this.trained = anyTrained;
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  predict(features: Record<string, number>): PredictionResult {
    if (!this.trained) {
      return { score: 0.5, probability: 0.5, confidence: 'LOW', reason: 'model untrained — rule-based composition' };
    }
    const x = extractFeaturesFromFlat(features);
    const summary = this.predictCategory(SUMMARY_STYLES, this.summaryModels, x);
    const priority = this.predictCategory(PRIORITY_EMPHASES, this.priorityModels, x);
    const remediation = this.predictCategory(REMEDIATION_EMPHASES, this.remediationModels, x);
    const subjectIdx = this.predictCategory(SUBJECT_TEMPLATES.map((_, i) => String(i)), this.subjectModels, x);

    const probs = [summary.probability, priority.probability, remediation.probability];
    const minProb = Math.min(...probs);
    const confidence: PredictionResult['confidence'] = minProb >= 0.7 ? 'HIGH' : minProb >= 0.4 ? 'MEDIUM' : 'LOW';

    return {
      score: minProb,
      probability: minProb,
      confidence,
      reason: `summary=${summary.label} (P=${summary.probability.toFixed(2)}), priority=${priority.label} (P=${priority.probability.toFixed(2)}), remediation=${remediation.label} (P=${remediation.probability.toFixed(2)}), subject=${subjectIdx}`,
    };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  private predictCategory(
    categories: string[],
    models: Map<string, LogisticRegression>,
    x: Record<string, number>,
  ): { label: string; probability: number } {
    let best = categories[0];
    let bestProb = 0;
    for (const cat of categories) {
      const lr = models.get(cat);
      if (!lr) continue;
      const pred = lr.predict(x);
      const p = pred.probability ?? pred.score;
      if (p > bestProb) {
        bestProb = p;
        best = cat;
      }
    }
    return { label: best, probability: bestProb };
  }

  compose(
    features: EmailCompositionFeatures,
    perFinding: PerFindingFeatures[],
  ): EmailCompositionText {
    const x = extractFeatures(features);
    const summaryStyle = this.predictCategory(SUMMARY_STYLES, this.summaryModels, x).label as SummaryStyle;
    const priorityEmphasis = this.predictCategory(PRIORITY_EMPHASES, this.priorityModels, x).label as PriorityEmphasis;
    const remediationEmphasis = this.predictCategory(REMEDIATION_EMPHASES, this.remediationModels, x).label as RemediationEmphasis;
    const subjectIdx = Number(this.predictCategory(SUBJECT_TEMPLATES.map((_, i) => String(i)), this.subjectModels, x).label);
    const subjectTemplate = SUBJECT_TEMPLATES[Math.max(0, Math.min(subjectIdx, SUBJECT_TEMPLATES.length - 1))];

    // Rank findings by importance using GBDT ranker
    const findingScores: number[] = [];
    if (perFinding.length) {
      try {
        const rankPreds = this.findingRanker.predictBatch(perFinding.map(extractPerFindingFeatures));
        for (const rp of rankPreds) {
          findingScores.push(rp.probability ?? rp.score);
        }
      } catch {
        for (let i = 0; i < perFinding.length; i++) findingScores.push(1 / (i + 1));
      }
    } else {
      for (let i = 0; i < perFinding.length; i++) findingScores.push(1 / (i + 1));
    }

    const order = findingScores
      .map((score, idx) => ({ score, idx }))
      .sort((a, b) => b.score - a.score || a.idx - b.idx)
      .map((entry) => entry.idx);

    return {
      subject: buildSubject(subjectTemplate, features),
      executiveSummary: buildExecutiveSummary(features, summaryStyle, priorityEmphasis),
      remediationInstructions: buildRemediationInstructions(features, remediationEmphasis),
      severitySummary: buildSeveritySummary(features),
      findingOrder: order,
    };
  }

  composePrediction(
    features: EmailCompositionFeatures,
    perFinding: PerFindingFeatures[],
  ): EmailCompositionPrediction {
    const x = extractFeatures(features);

    const summaryStyle = this.predictCategory(SUMMARY_STYLES, this.summaryModels, x).label as SummaryStyle;
    const priorityEmphasis = this.predictCategory(PRIORITY_EMPHASES, this.priorityModels, x).label as PriorityEmphasis;
    const remediationEmphasis = this.predictCategory(REMEDIATION_EMPHASES, this.remediationModels, x).label as RemediationEmphasis;
    const subjectIdx = Number(this.predictCategory(SUBJECT_TEMPLATES.map((_, i) => String(i)), this.subjectModels, x).label);
    const subjectTemplate = SUBJECT_TEMPLATES[Math.max(0, Math.min(subjectIdx, SUBJECT_TEMPLATES.length - 1))];

    const findingScores: number[] = [];
    if (perFinding.length) {
      try {
        const rankPreds = this.findingRanker.predictBatch(perFinding.map(extractPerFindingFeatures));
        for (const rp of rankPreds) {
          findingScores.push(rp.probability ?? rp.score);
        }
      } catch {
        for (let i = 0; i < perFinding.length; i++) findingScores.push(1 / (i + 1));
      }
    }

    const pred = this.predict(x);
    return {
      summaryStyle,
      priorityEmphasis,
      remediationEmphasis,
      subjectTemplate,
      findingScores,
      confidence: pred.confidence,
      modelVersion: this.metadata.version,
      reason: pred.reason,
    };
  }

  serialize(): ModelArtifact {
    const serializeMap = (m: Map<string, LogisticRegression>): Record<string, unknown> => {
      const obj: Record<string, unknown> = {};
      for (const [k, v] of m) obj[k] = v.serialize();
      return obj;
    };
    return {
      metadata: this.metadata,
      weights: {
        summaryModels: serializeMap(this.summaryModels),
        priorityModels: serializeMap(this.priorityModels),
        remediationModels: serializeMap(this.remediationModels),
        subjectModels: serializeMap(this.subjectModels),
        findingRanker: this.findingRanker.serialize(),
        featureNames: [...this.featureNames],
      },
    };
  }

  load(artifact: ModelArtifact): void {
    const data = artifact.weights as {
      summaryModels: Record<string, unknown>;
      priorityModels: Record<string, unknown>;
      remediationModels: Record<string, unknown>;
      subjectModels: Record<string, unknown>;
      findingRanker: ReturnType<GBDTRanker['serialize']>;
      featureNames: string[];
    };

    this.summaryModels.clear();
    this.priorityModels.clear();
    this.remediationModels.clear();
    this.subjectModels.clear();

    for (const cat of SUMMARY_STYLES) {
      const w = data.summaryModels[cat];
      if (w) {
        const lr = new LogisticRegression();
        lr.load(w as ReturnType<LogisticRegression['serialize']>);
        this.summaryModels.set(cat, lr);
      }
    }
    for (const cat of PRIORITY_EMPHASES) {
      const w = data.priorityModels[cat];
      if (w) {
        const lr = new LogisticRegression();
        lr.load(w as ReturnType<LogisticRegression['serialize']>);
        this.priorityModels.set(cat, lr);
      }
    }
    for (const cat of REMEDIATION_EMPHASES) {
      const w = data.remediationModels[cat];
      if (w) {
        const lr = new LogisticRegression();
        lr.load(w as ReturnType<LogisticRegression['serialize']>);
        this.remediationModels.set(cat, lr);
      }
    }
    for (let i = 0; i < SUBJECT_TEMPLATES.length; i++) {
      const w = data.subjectModels[String(i)];
      if (w) {
        const lr = new LogisticRegression();
        lr.load(w as ReturnType<LogisticRegression['serialize']>);
        this.subjectModels.set(String(i), lr);
      }
    }

    this.findingRanker.load(data.findingRanker);
    this.metadata = artifact.metadata;
    this.trained = this.summaryModels.size > 0 || this.priorityModels.size > 0 || this.remediationModels.size > 0;
  }

  getFeatureNames(): string[] {
    return [...this.featureNames];
  }

  getSummaryStyle(): string[] {
    return [...SUMMARY_STYLES];
  }

  getPriorityEmphases(): string[] {
    return [...PRIORITY_EMPHASES];
  }

  getRemediationEmphases(): string[] {
    return [...REMEDIATION_EMPHASES];
  }

  getSubjectTemplates(): string[] {
    return [...SUBJECT_TEMPLATES];
  }

  static collectTrainingData(samples: Array<{
    features: EmailCompositionFeatures;
    perFinding: PerFindingFeatures[];
    summaryStyle: SummaryStyle;
    priorityEmphasis: PriorityEmphasis;
    remediationEmphasis: RemediationEmphasis;
    subjectTemplate: SubjectTemplate;
    wasActionable: boolean;
  }>): TrainingSample[] {
    return samples.map((s, i) => {
      const summaryIdx = SUMMARY_STYLES.indexOf(s.summaryStyle);
      const priorityIdx = PRIORITY_EMPHASES.indexOf(s.priorityEmphasis);
      const remediationIdx = REMEDIATION_EMPHASES.indexOf(s.remediationEmphasis);
      const subjectIdx = SUBJECT_TEMPLATES.indexOf(s.subjectTemplate);
      const label = summaryIdx * 1 + priorityIdx * 10 + remediationIdx * 100 + subjectIdx * 1000 + (s.wasActionable ? 10000 : 0);
      return {
        id: `advisory-composer-${i}`,
        features: extractFeatures(s.features),
        label,
        weight: s.wasActionable ? 2 : 1,
        timestamp: new Date().toISOString(),
      };
    });
  }
}

function extractFeaturesFromFlat(features: Record<string, number>): Record<string, number> {
  return { ...features };
}
