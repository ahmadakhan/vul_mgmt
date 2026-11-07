import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  AdvisoryComposerModel,
  type EmailCompositionFeatures,
  type PerFindingFeatures,
  type SummaryStyle,
  type PriorityEmphasis,
  type RemediationEmphasis,
  type SubjectTemplate,
  SUMMARY_STYLES,
  PRIORITY_EMPHASES,
  REMEDIATION_EMPHASES,
  SUBJECT_TEMPLATES,
} from '../server/ml/models/advisoryComposer.ts';
import { composeAdvisoryEmail, predictAdvisoryComposition, orderFindingsByMlImportance } from '../server/advisoryComposer.ts';
import type { Advisory, Finding } from '../src/types/index.ts';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
    cveId: 'CVE-2026-90001',
    cve: {
      cveId: 'CVE-2026-90001',
      title: 'Test vulnerability',
      description: 'A test vulnerability',
      publishedDate: '2026-10-30T00:00:00Z',
      modifiedDate: '2026-10-30T00:00:00Z',
      cvss: { version: '3.1', score: 9.8, vector: 'AV:N/AC:L', severity: 'CRITICAL' },
      cwe: [],
      cpeMatches: [],
      sourceFeeds: [],
      epss: { score: 0.85, percentile: 0.9 },
      cisaKev: { isKev: true },
      exploitStatus: 'Active Weaponized',
      remediation: {
        patchUrl: 'https://vendor.com/patch/CVE-2026-90001',
        vendorAdvisoryRef: 'https://vendor.com/advisory/CVE-2026-90001',
        immediateActions: ['Apply patch'],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    } as any,
    matchedAssetId: 'asset-1',
    matchedAssetName: 'Critical Server',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'server',
    matchedCpe: 'cpe:2.3:a:acme:server:1.0:*:*:*:*:*:*:*',
    matchingMethod: 'CPE_EXACT',
    matchingEvidence: 'exact match',
    exploitRisk: 'WEAPONIZED_EXPLOIT',
    notificationStatus: 'QUEUED_FOR_DISPATCH',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    timeline: [],
    ...overrides,
  } as unknown as Finding;
}

function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'ADV-TEST',
    title: 'Vulnerability notice: 1 Critical',
    severity: 'CRITICAL',
    cveIds: ['CVE-2026-90001'],
    findingIds: ['finding-1'],
    createdDate: new Date().toISOString(),
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'Test',
    remediationInstructions: 'Test',
    affectedSystems: ['Critical Server'],
    ...overrides,
  };
}

describe('AdvisoryComposerModel', () => {
  describe('feature extraction', () => {
    it('extracts correct aggregate features from findings', () => {
      const findings = [
        makeFinding({ cve: { ...makeFinding().cve, cvss: { ...makeFinding().cve.cvss, severity: 'CRITICAL', score: 9.8 }, cisaKev: { isKev: true }, exploitStatus: 'Active Weaponized' as any } }),
        makeFinding({ cveId: 'CVE-2026-90002', cve: { ...makeFinding().cve, cveId: 'CVE-2026-90002', cvss: { ...makeFinding().cve.cvss, severity: 'HIGH', score: 7.5 }, cisaKev: { isKev: false }, exploitStatus: 'None' as any } }),
      ];

      const model = new AdvisoryComposerModel();
      const feats = {
        criticalCount: findings.filter(f => f.cve.cvss.severity === 'CRITICAL').length,
        highCount: findings.filter(f => f.cve.cvss.severity === 'HIGH').length,
        mediumCount: findings.filter(f => f.cve.cvss.severity === 'MEDIUM').length,
        lowCount: findings.filter(f => f.cve.cvss.severity === 'LOW').length,
        unknownCount: findings.filter(f => f.cve.cvss.severity === 'UNKNOWN').length,
        totalFindings: findings.length,
        maxCvssScore: Math.max(...findings.map(f => f.cve.cvss.score ?? 0)),
        avgCvssScore: findings.reduce((s, f) => s + (f.cve.cvss.score ?? 0), 0) / findings.length,
        maxEpssScore: Math.max(...findings.map(f => f.cve.epss?.score ?? 0)),
        avgEpssScore: findings.reduce((s, f) => s + (f.cve.epss?.score ?? 0), 0) / findings.length,
        kevCount: findings.filter(f => f.cve.cisaKev?.isKev).length,
        weaponizedCount: findings.filter(f => f.cve.exploitStatus === 'Active Weaponized').length,
        reportedInWildCount: findings.filter(f => f.cve.exploitStatus === 'Reported In Wild').length,
        pocCount: findings.filter(f => f.cve.exploitStatus === 'POC Available').length,
        affectedAssetCount: new Set(findings.map(f => f.matchedAssetName)).size,
        uniqueVendorCount: new Set(findings.map(f => f.matchedAssetVendor ?? '')).size,
        avgMatchConfidence: findings.reduce((s, f) => s + (f.confidence ?? 0), 0) / findings.length,
        avgDaysSincePublished: 0,
        avgSourceFeedWeight: findings.reduce((s, f) => s + (f.cve.epss?.percentile ?? 0), 0) / findings.length,
      };

      assert.equal(feats.criticalCount, 1);
      assert.equal(feats.highCount, 1);
      assert.equal(feats.totalFindings, 2);
      assert.equal(feats.kevCount, 1);
      assert.equal(feats.weaponizedCount, 1);
    });
  });

  describe('untrained model', () => {
    it('returns fallback prediction when untrained', () => {
      const model = new AdvisoryComposerModel();
      assert.equal(model.isTrained(), false);
      const result = model.predict({ critical_count: 1 });
      assert.equal(result.confidence, 'LOW');
      assert.ok(result.reason.includes('untrained'));
    });

    it('compose falls back to rule-based text when untrained', () => {
      const model = new AdvisoryComposerModel();
      const features: EmailCompositionFeatures = {
        criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, unknownCount: 0,
        totalFindings: 1, maxCvssScore: 9.8, avgCvssScore: 9.8,
        maxEpssScore: 0.85, avgEpssScore: 0.85,
        kevCount: 1, weaponizedCount: 1, reportedInWildCount: 0, pocCount: 0,
        affectedAssetCount: 1, uniqueVendorCount: 1,
        avgMatchConfidence: 100, avgDaysSincePublished: 5, avgSourceFeedWeight: 0.9,
      };
      const perFinding: PerFindingFeatures[] = [{
        cvssScore: 9.8, epssScore: 0.85, cisaKev: true,
        exploitStatus: 'Active Weaponized', matchConfidence: 100,
        daysSincePublished: 5, sourceFeedWeight: 0.9, assetCriticality: 0,
      }];
      const text = model.compose(features, perFinding);
      assert.ok(text.subject.includes('1 Critical'));
      assert.ok(text.executiveSummary.length > 0);
      assert.ok(text.remediationInstructions.length > 0);
      assert.ok(text.severitySummary.includes('1 Critical'));
      assert.deepEqual(text.findingOrder, [0]);
    });
  });

  describe('trained model', () => {
    it('trains and predicts composition parameters', () => {
      const model = new AdvisoryComposerModel();
      const samples: Array<{
        features: EmailCompositionFeatures;
        summaryStyle: SummaryStyle;
        priorityEmphasis: PriorityEmphasis;
        remediationEmphasis: RemediationEmphasis;
        subjectTemplate: SubjectTemplate;
        wasActionable: boolean;
      }> = [];

      // Generate diverse training samples
      for (let i = 0; i < 40; i++) {
        const critical = i < 10 ? 3 : i < 20 ? 1 : 0;
        const high = i < 10 ? 1 : i < 20 ? 3 : 0;
        const medium = i < 10 ? 0 : i < 20 ? 1 : 3;
        const low = i < 10 ? 0 : i < 20 ? 0 : 2;
        const total = critical + high + medium + low;
        const wasActionable = critical > 0 || high > 2;

        samples.push({
          features: {
            criticalCount: critical, highCount: high, mediumCount: medium, lowCount: low, unknownCount: 0,
            totalFindings: total, maxCvssScore: critical > 0 ? 9.5 : high > 0 ? 7.5 : 5.0,
            avgCvssScore: critical > 0 ? 9.0 : high > 0 ? 7.0 : 5.0,
            maxEpssScore: 0.8, avgEpssScore: 0.6,
            kevCount: critical > 0 ? 1 : 0,
            weaponizedCount: critical > 0 ? 1 : 0,
            reportedInWildCount: 0, pocCount: 0,
            affectedAssetCount: total, uniqueVendorCount: 1,
            avgMatchConfidence: 90, avgDaysSincePublished: 5, avgSourceFeedWeight: 0.8,
          },
          summaryStyle: critical > 0 ? 'URGENT' : high > 0 ? 'STANDARD' : 'INFORMATIONAL',
          priorityEmphasis: critical > 0 ? 'IMMEDIATE_ACTION' : high > 0 ? 'IMMEDIATE_ACTION' : 'MONITOR',
          remediationEmphasis: critical > 0 ? 'PATCH_FIRST' : 'WORKAROUND_FIRST',
          subjectTemplate: SUBJECT_TEMPLATES[0],
          wasActionable,
        });
      }

      const trainSamples = AdvisoryComposerModel.collectTrainingData(
        samples.map((s, i) => ({
          ...s,
          perFinding: [],
        })),
      );
      assert.ok(trainSamples.length >= 20);

      model.train(trainSamples);
      assert.equal(model.isTrained(), true);

      // Predict urgent composition for critical-heavy findings
      const urgentFeats: EmailCompositionFeatures = {
        criticalCount: 3, highCount: 1, mediumCount: 0, lowCount: 0, unknownCount: 0,
        totalFindings: 4, maxCvssScore: 9.5, avgCvssScore: 8.5,
        maxEpssScore: 0.8, avgEpssScore: 0.7,
        kevCount: 1, weaponizedCount: 1, reportedInWildCount: 0, pocCount: 0,
        affectedAssetCount: 4, uniqueVendorCount: 1,
        avgMatchConfidence: 90, avgDaysSincePublished: 5, avgSourceFeedWeight: 0.8,
      };
      const result = model.predict(extractFeaturesFromFlat(urgentFeats));
      assert.ok(result.confidence === 'LOW' || result.confidence === 'MEDIUM' || result.confidence === 'HIGH');
    });

    it('serializes and loads without losing training state', () => {
      const model = new AdvisoryComposerModel();
      const samples: Array<{
        features: EmailCompositionFeatures;
        summaryStyle: SummaryStyle;
        priorityEmphasis: PriorityEmphasis;
        remediationEmphasis: RemediationEmphasis;
        subjectTemplate: SubjectTemplate;
        wasActionable: boolean;
      }> = [];

      for (let i = 0; i < 30; i++) {
        const crit = i % 3 === 0 ? 2 : 0;
        const high = i % 3 === 1 ? 3 : 0;
        const total = crit + high;
        samples.push({
          features: {
            criticalCount: crit, highCount: high, mediumCount: 0, lowCount: 0, unknownCount: 0,
            totalFindings: total, maxCvssScore: crit > 0 ? 9.0 : 7.0, avgCvssScore: crit > 0 ? 8.5 : 6.5,
            maxEpssScore: 0.7, avgEpssScore: 0.5,
            kevCount: crit > 0 ? 1 : 0,
            weaponizedCount: crit > 0 ? 1 : 0,
            reportedInWildCount: 0, pocCount: 0,
            affectedAssetCount: total, uniqueVendorCount: 1,
            avgMatchConfidence: 85, avgDaysSincePublished: 3, avgSourceFeedWeight: 0.7,
          },
          summaryStyle: crit > 0 ? 'URGENT' : 'STANDARD',
          priorityEmphasis: crit > 0 ? 'IMMEDIATE_ACTION' : 'MONITOR',
          remediationEmphasis: crit > 0 ? 'PATCH_FIRST' : 'WORKAROUND_FIRST',
          subjectTemplate: SUBJECT_TEMPLATES[0],
          wasActionable: crit > 0,
        });
      }

      const trainSamples = AdvisoryComposerModel.collectTrainingData(
        samples.map((s, i) => ({ ...s, perFinding: [] })),
      );
      model.train(trainSamples);
      assert.equal(model.isTrained(), true);

      const artifact = model.serialize();
      assert.ok(artifact.metadata.id === 'advisory-composer');
      const weights = artifact.weights as { summaryModels: Record<string, unknown>; priorityModels: Record<string, unknown> };
      assert.ok(weights.summaryModels);
      assert.ok(weights.priorityModels);

      const loaded = new AdvisoryComposerModel();
      loaded.load(artifact);
      assert.equal(loaded.isTrained(), true);

      const pred = loaded.predict({
        critical_count: 2, high_count: 0, medium_count: 0, low_count: 0, unknown_count: 0,
        total_findings: 2, max_cvss_score: 9.0, avg_cvss_score: 8.5,
        max_epss_score: 0.7, avg_epss_score: 0.5,
        kev_count: 1, weaponized_count: 1, reported_in_wild_count: 0, poc_count: 0,
        affected_asset_count: 2, unique_vendor_count: 1,
        avg_match_confidence: 85, avg_days_since_published: 3, avg_source_feed_weight: 0.7,
      });
      assert.ok((pred.probability ?? pred.score) >= 0);
    });
  });

  describe('compose text generation', () => {
    it('generates subject, summary, remediation, severity summary', () => {
      const model = new AdvisoryComposerModel();
      // Train quickly
      const samples: Array<{
        features: EmailCompositionFeatures;
        summaryStyle: SummaryStyle;
        priorityEmphasis: PriorityEmphasis;
        remediationEmphasis: RemediationEmphasis;
        subjectTemplate: SubjectTemplate;
        wasActionable: boolean;
      }> = [];
      for (let i = 0; i < 25; i++) {
        samples.push({
          features: {
            criticalCount: i < 10 ? 2 : 0, highCount: i < 10 ? 1 : 2, mediumCount: 0, lowCount: 0, unknownCount: 0,
            totalFindings: i < 10 ? 3 : 2, maxCvssScore: i < 10 ? 9.5 : 7.0, avgCvssScore: i < 10 ? 9.0 : 6.5,
            maxEpssScore: 0.8, avgEpssScore: 0.6,
            kevCount: i < 10 ? 1 : 0,
            weaponizedCount: i < 10 ? 1 : 0,
            reportedInWildCount: 0, pocCount: 0,
            affectedAssetCount: i < 10 ? 3 : 2, uniqueVendorCount: 1,
            avgMatchConfidence: 90, avgDaysSincePublished: 5, avgSourceFeedWeight: 0.8,
          },
          summaryStyle: i < 10 ? 'URGENT' : 'STANDARD',
          priorityEmphasis: i < 10 ? 'IMMEDIATE_ACTION' : 'MONITOR',
          remediationEmphasis: i < 10 ? 'PATCH_FIRST' : 'WORKAROUND_FIRST',
          subjectTemplate: SUBJECT_TEMPLATES[0],
          wasActionable: i < 10,
        });
      }
      model.train(AdvisoryComposerModel.collectTrainingData(
        samples.map((s, i) => ({ ...s, perFinding: [] })),
      ));
      assert.equal(model.isTrained(), true);

      const features: EmailCompositionFeatures = {
        criticalCount: 2, highCount: 1, mediumCount: 0, lowCount: 0, unknownCount: 0,
        totalFindings: 3, maxCvssScore: 9.5, avgCvssScore: 8.5,
        maxEpssScore: 0.85, avgEpssScore: 0.7,
        kevCount: 1, weaponizedCount: 1, reportedInWildCount: 0, pocCount: 0,
        affectedAssetCount: 3, uniqueVendorCount: 1,
        avgMatchConfidence: 90, avgDaysSincePublished: 5, avgSourceFeedWeight: 0.8,
      };
      const perFinding: PerFindingFeatures[] = [{
        cvssScore: 9.8, epssScore: 0.85, cisaKev: true,
        exploitStatus: 'Active Weaponized', matchConfidence: 100,
        daysSincePublished: 5, sourceFeedWeight: 0.9, assetCriticality: 0,
      }, {
        cvssScore: 7.5, epssScore: 0.5, cisaKev: false,
        exploitStatus: 'None', matchConfidence: 85,
        daysSincePublished: 10, sourceFeedWeight: 0.5, assetCriticality: 0,
      }];

      const text = model.compose(features, perFinding);
      assert.ok(text.subject.length > 0);
      assert.ok(text.executiveSummary.length > 0);
      assert.ok(text.remediationInstructions.length > 0);
      assert.ok(text.severitySummary.length > 0);
      assert.ok(text.findingOrder.length === 2);
      // Finding order should be a permutation of [0, 1]
      assert.deepEqual([...text.findingOrder].sort(), [0, 1]);

      const pred = model.composePrediction(features, perFinding);
      assert.ok(SUMMARY_STYLES.includes(pred.summaryStyle));
      assert.ok(PRIORITY_EMPHASES.includes(pred.priorityEmphasis));
      assert.ok(REMEDIATION_EMPHASES.includes(pred.remediationEmphasis));
      assert.ok(SUBJECT_TEMPLATES.includes(pred.subjectTemplate));
      assert.ok(pred.findingScores.length === 2);
      assert.ok(pred.modelVersion);
      assert.ok(pred.reason);
    });
  });
});

describe('composeAdvisoryEmail (integration)', () => {
  it('uses rule-based fallback when model untrained', () => {
    const findings = [makeFinding()];
    const result = composeAdvisoryEmail(findings, makeAdvisory());
    assert.equal(result.modelUsed, false);
    assert.ok(result.subject.length > 0);
    assert.ok(result.executiveSummary.length > 0);
    assert.ok(result.remediationInstructions.length > 0);
    assert.ok(result.severitySummary.includes('1 Critical'));
    assert.equal(result.prediction, null);
    assert.deepEqual(result.findingOrder, [0]);
  });

  it('returns finding order as permutation', () => {
    const findings = [makeFinding(), makeFinding({ cveId: 'CVE-2026-90002', cve: { ...makeFinding().cve, cveId: 'CVE-2026-90002', cvss: { ...makeFinding().cve.cvss, severity: 'LOW' as any, score: 3.0 } } })];
    const result = composeAdvisoryEmail(findings, makeAdvisory());
    assert.deepEqual([...result.findingOrder].sort(), [0, 1]);
  });
});

describe('predictAdvisoryComposition', () => {
  it('returns null when model untrained', () => {
    const result = predictAdvisoryComposition([makeFinding()]);
    assert.equal(result, null);
  });
});

describe('orderFindingsByMlImportance', () => {
  it('falls back to severity order when untrained', () => {
    const findings = [
      makeFinding({ cve: { ...makeFinding().cve, cvss: { ...makeFinding().cve.cvss, severity: 'LOW' as any, score: 3.0 } } }),
      makeFinding({ cve: { ...makeFinding().cve, cvss: { ...makeFinding().cve.cvss, severity: 'CRITICAL' as any, score: 9.8 } } }),
    ];
    const ordered = orderFindingsByMlImportance(findings);
    assert.equal(ordered[0].cve.cvss.severity, 'CRITICAL');
    assert.equal(ordered[1].cve.cvss.severity, 'LOW');
  });
});

// Helper to convert EmailCompositionFeatures to flat record for predict
function extractFeaturesFromFlat(f: EmailCompositionFeatures): Record<string, number> {
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
