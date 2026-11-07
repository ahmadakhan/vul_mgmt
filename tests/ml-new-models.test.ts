import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  ExploitRiskModel,
  extractExploitRiskFeatures,
  EXPLOIT_RISK_FEATURE_NAMES,
  type ExploitRiskLevel,
} from '../server/ml/models/exploitRiskModel.ts';
import {
  MatchConfidenceModel,
  extractMatchConfidenceFeatures,
} from '../server/ml/models/matchConfidenceModel.ts';
import {
  FindingImportanceRanker,
  extractFindingImportanceFeatures,
  type FindingImportanceFeatures,
} from '../server/ml/models/findingImportanceRanker.ts';
import { NewsCredibilityWeightModel, chronologicalCredibilitySplit } from '../server/ml/models/newsCredibilityWeightModel.ts';
import {
  DeliveryErrorClassifier,
  extractDeliveryErrorFeatures,
} from '../server/ml/models/deliveryErrorClassifier.ts';
import { ZeroDayRateLimitOptimizer } from '../server/ml/models/zeroDayRateLimitOptimizer.ts';
import {
  DigestFindingSelector,
  extractDigestSelectionFeatures,
  type DigestSelectionFeatures,
} from '../server/ml/models/digestFindingSelector.ts';
import {
  SeverityTierModel,
  extractSeverityTierFeatures,
  type SeverityTier,
} from '../server/ml/models/severityTierModel.ts';
import { FeedRecoveryBackoffOptimizer } from '../server/ml/models/feedRecoveryBackoffOptimizer.ts';
import {
  AliasConfidenceModel,
  extractAliasConfidenceFeatures,
} from '../server/ml/models/aliasConfidenceModel.ts';
import { QUALITY_GATES } from '../server/ml/train/qualityGates.ts';
import { LogisticRegression } from '../server/ml/algorithms/logisticRegression.ts';
import type { TrainingSample, ModelArtifact } from '../server/ml/types.ts';
import { splitData } from '../server/ml/train/evaluation.ts';

function makeLogisticSamples(n: number, positive: boolean): TrainingSample[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `s-${i}`,
    features: {
      cvss_score: positive ? 8.5 + i * 0.01 : 3.0 + i * 0.01,
      epss_score: positive ? 0.8 : 0.1,
      cisa_kev: positive ? 1 : 0,
      exploit_status: positive ? 3 : 0,
      days_since_published: positive ? 5 : 100,
    },
    label: positive ? 1 : 0,
    weight: 1,
    timestamp: new Date().toISOString(),
  }));
}

describe('ExploitRiskModel', () => {
  it('returns STANDARD when untrained', () => {
    const model = new ExploitRiskModel();
    assert.equal(model.predictExploitRisk({
      cvssScore: 9.5,
      epssScore: 0.9,
      cisaKev: true,
      exploitStatus: 'Active Weaponized',
      exploitationSourcesCount: 5,
      daysSincePublished: 3,
    }), 'STANDARD');
  });

  it('extracts correct exploit risk features', () => {
    const feats = extractExploitRiskFeatures({
      cvssScore: 9.5,
      epssScore: 0.9,
      cisaKev: true,
      exploitStatus: 'Active Weaponized',
      exploitationSourcesCount: 5,
      daysSincePublished: 3,
    });
    assert.equal(feats.cisa_kev, 1);
    assert.equal(feats.exploit_status, 3);
    assert.equal(feats.cvss_score, 9.5);
    assert.equal(feats.epss_score, 0.9);
    assert.equal(feats.exploitation_sources_count, 5);
    assert.equal(feats.days_since_published, 3);
  });

  it('has correct feature names and levels', () => {
    const model = new ExploitRiskModel();
    assert.equal(model.getFeatureNames().length, 6);
    assert.deepEqual(model.getRiskLevels().length, 6);
  });

  it('trains and predicts with sufficient multi-class data', () => {
    const model = new ExploitRiskModel();
    const samples: TrainingSample[] = [];
    for (const level of ['CISA_KEV_EXPLOITED', 'REPORTED_IN_WILD_EXPLOIT', 'WEAPONIZED_EXPLOIT', 'HIGH_EPSS_PROBABILITY', 'ELEVATED', 'STANDARD']) {
      for (let i = 0; i < 20; i++) {
        const idx = samples.length;
        samples.push({
          id: `sample-${idx}`,
          features: {
            cvss_score: 8.5 + (i % 6) * 0.2,
            epss_score: 0.8 - (i % 6) * 0.1,
            cisa_kev: level === 'CISA_KEV_EXPLOITED' ? 1 : 0,
            exploit_status: level === 'CISA_KEV_EXPLOITED' ? 3 : level === 'REPORTED_IN_WILD_EXPLOIT' ? 2 : level === 'WEAPONIZED_EXPLOIT' ? 1 : 0,
            exploitation_sources_count: level === 'CISA_KEV_EXPLOITED' ? 5 : level === 'REPORTED_IN_WILD_EXPLOIT' ? 3 : 0,
            days_since_published: 5 + (i % 10),
          },
          label: EXPLOIT_LEVEL_INDEX[level as ExploitRiskLevel],
          weight: 1,
          timestamp: new Date().toISOString(),
        });
      }
    }
    model.train(samples);
    assert.equal(model.isTrained(), true);
    assert.ok(model.isTrained());
    assert.ok(model.getRiskLevels().length > 0);

    const pred = model.predict({ cvss_score: 9.5, epss_score: 0.9, cisa_kev: 1, exploit_status: 3, exploitation_sources_count: 5, days_since_published: 3 });
    assert.ok(pred.probability !== undefined);
  });

  it('serializes and loads round-trip', () => {
    const model = new ExploitRiskModel();
    const samples: TrainingSample[] = [];
    for (const level of ['CISA_KEV_EXPLOITED', 'STANDARD']) {
      for (let i = 0; i < 15; i++) {
        samples.push({
          id: `s-${level}-${i}`,
          features: {
            cvss_score: level === 'CISA_KEV_EXPLOITED' ? 9.5 : 3.0,
            epss_score: level === 'CISA_KEV_EXPLOITED' ? 0.9 : 0.1,
            cisa_kev: level === 'CISA_KEV_EXPLOITED' ? 1 : 0,
            exploit_status: level === 'CISA_KEV_EXPLOITED' ? 3 : 0,
            exploitation_sources_count: level === 'CISA_KEV_EXPLOITED' ? 5 : 0,
            days_since_published: 3,
          },
          label: EXPLOIT_LEVEL_INDEX[level as ExploitRiskLevel],
          weight: 1,
          timestamp: new Date().toISOString(),
        });
      }
    }
    model.train(samples);

    const artifact = model.serialize();
    const restored = new ExploitRiskModel();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);

    const feats = { cvss_score: 9.5, epss_score: 0.9, cisa_kev: 1, exploit_status: 3, exploitation_sources_count: 5, days_since_published: 3 };
    const orig = model.predict(feats);
    const loaded = restored.predict(feats);
    assert.equal(orig.score, loaded.score);
  });

  it('quality gate exists with correct minimum samples', () => {
    const gate = QUALITY_GATES['exploit-risk-model'];
    assert.ok(gate);
    assert.equal(gate.minimumSamples, 100);
  });
});

const EXPLOIT_LEVEL_INDEX: Record<ExploitRiskLevel, number> = {
  CISA_KEV_EXPLOITED: 0,
  REPORTED_IN_WILD_EXPLOIT: 1,
  WEAPONIZED_EXPLOIT: 2,
  HIGH_EPSS_PROBABILITY: 3,
  ELEVATED: 4,
  STANDARD: 5,
};

describe('MatchConfidenceModel', () => {
  it('predicts 0 when untrained', () => {
    const model = new MatchConfidenceModel();
    assert.equal(model.isTrained(), false);
    const result = model.predictConfidence({
      matchMethod: 'VENDOR_PRODUCT_ALIAS',
      hasVersionEvidence: false,
      versionVerifiedInRange: false,
      cvssScore: 7.5,
      epssScore: 0.5,
      cisaKev: false,
      sourceFeedWeight: 50,
      daysSincePublished: 30,
      negated: false,
    });
    assert.equal(typeof result, 'number');
  });

  it('extracts correct match confidence features', () => {
    const feats = extractMatchConfidenceFeatures({
      matchMethod: 'STRICT_CPE',
      hasVersionEvidence: true,
      versionVerifiedInRange: true,
      cvssScore: 8.0,
      epssScore: 0.3,
      cisaKev: true,
      sourceFeedWeight: 40,
      daysSincePublished: 10,
      negated: false,
    });
    assert.equal(feats.match_method_strict_cpe, 1);
    assert.equal(feats.has_version_evidence, 1);
    assert.equal(feats.cisa_kev, 1);
    assert.equal(feats.cvss_score, 8.0);
  });

  it('trains and predicts confidence score', () => {
    const model = new MatchConfidenceModel();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({
        id: `m-${i}`,
        features: {
          match_method_strict_cpe: i < 50 ? 1 : 0,
          match_method_strict_cpe_interval: 0,
          match_method_purl_exact: 0,
          match_method_vendor_alias: i < 50 ? 0 : 1,
          match_method_vendor_fallback: 0,
          match_method_keyword: 0,
          match_method_fallback: 0,
          has_version_evidence: i < 50 ? 1 : 0,
          version_verified_in_range: i < 50 ? 1 : 0,
          cvss_score: i < 50 ? 8.5 : 3.0,
          epss_score: i < 50 ? 0.8 : 0.1,
          cisa_kev: i < 50 ? 1 : 0,
          source_feed_weight: i < 50 ? 40 : 15,
          days_since_published: 5,
          negated: 0,
        },
        label: i < 50 ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    const [train, test] = splitData(samples, 0.2, 42);
    model.train(train);
    assert.equal(model.isTrained(), true);
    assert.ok(model.getFeatureNames().length === 15);

    const result = model.predict({
      match_method_strict_cpe: 1,
      match_method_strict_cpe_interval: 0,
      match_method_purl_exact: 0,
      match_method_vendor_alias: 0,
      match_method_vendor_fallback: 0,
      match_method_keyword: 0,
      match_method_fallback: 0,
      has_version_evidence: 1,
      version_verified_in_range: 1,
      cvss_score: 8.5,
      epss_score: 0.8,
      cisa_kev: 1,
      source_feed_weight: 40,
      days_since_published: 5,
      negated: 0,
    });
    assert.ok(result.score > 0.5);
  });

  it('serializes and loads round-trip', () => {
    const model = new MatchConfidenceModel();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 50; i++) {
      samples.push({
        id: `s-${i}`,
        features: {
          match_method_strict_cpe: i < 25 ? 1 : 0, match_method_strict_cpe_interval: 0,
          match_method_purl_exact: 0, match_method_vendor_alias: i < 25 ? 0 : 1,
          match_method_vendor_fallback: 0, match_method_keyword: 0, match_method_fallback: 0,
          has_version_evidence: i < 25 ? 1 : 0, version_verified_in_range: i < 25 ? 1 : 0,
          cvss_score: i < 25 ? 9.0 : 2.0, epss_score: i < 25 ? 0.9 : 0.1,
          cisa_kev: i < 25 ? 1 : 0, source_feed_weight: i < 25 ? 45 : 10,
          days_since_published: 5, negated: 0,
        },
        label: i < 25 ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    model.train(samples);
    const artifact = model.serialize();
    const restored = new MatchConfidenceModel();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);

    const feats = { match_method_strict_cpe: 1, match_method_strict_cpe_interval: 0, match_method_purl_exact: 0, match_method_vendor_alias: 0, match_method_vendor_fallback: 0, match_method_keyword: 0, match_method_fallback: 0, has_version_evidence: 1, version_verified_in_range: 1, cvss_score: 9.0, epss_score: 0.9, cisa_kev: 1, source_feed_weight: 45, days_since_published: 5, negated: 0 };
    assert.equal(model.predict(feats).score, restored.predict(feats).score);
  });

  it('quality gate exists with correct minimum samples', () => {
    const gate = QUALITY_GATES['match-confidence-model'];
    assert.ok(gate);
    assert.equal(gate.minimumSamples, 100);
  });
});

describe('FindingImportanceRanker', () => {
  it('is untrained by default', () => {
    const model = new FindingImportanceRanker();
    assert.equal(model.isTrained(), false);
  });

  it('extracts correct importance features', () => {
    const feats = extractFindingImportanceFeatures({
      cvssScore: 9.0, epssScore: 0.8, cisaKev: true, exploitStatus: 3,
      cweRiskLevel: 2, daysSincePublished: 5, sourceFeedWeight: 40,
      credibilityScore: 85, hasVersionEvidence: true, assetCriticality: 1,
    });
    assert.equal(feats.cisa_kev, 1);
    assert.equal(feats.has_version_evidence, 1);
    assert.equal(feats.cvss_score, 9.0);
    assert.equal(feats.asset_criticality, 1);
  });

  it('trains and ranks findings by score', () => {
    const model = new FindingImportanceRanker();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 30; i++) {
      const isPositive = i < 15;
      samples.push({
        id: `f-${i}`,
        features: {
          cvss_score: isPositive ? 9.0 : 3.0,
          epss_score: isPositive ? 0.8 : 0.1,
          cisa_kev: isPositive ? 1 : 0,
          exploit_status: isPositive ? 3 : 0,
          cwe_risk_level: isPositive ? 2 : 0,
          days_since_published: isPositive ? 5 : 100,
          source_feed_weight: isPositive ? 40 : 15,
          credibility_score: isPositive ? 85 : 30,
          has_version_evidence: isPositive ? 1 : 0,
          asset_criticality: isPositive ? 1 : 0,
        },
        label: isPositive ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    model.train(samples);
    assert.equal(model.isTrained(), true);
    assert.equal(model.getFeatureNames().length, 10);

    const findings: FindingImportanceFeatures[] = [
      { cvssScore: 9.0, epssScore: 0.8, cisaKev: true, exploitStatus: 3, cweRiskLevel: 2, daysSincePublished: 5, sourceFeedWeight: 40, credibilityScore: 85, hasVersionEvidence: true, assetCriticality: 1 },
      { cvssScore: 3.0, epssScore: 0.1, cisaKev: false, exploitStatus: 0, cweRiskLevel: 0, daysSincePublished: 100, sourceFeedWeight: 15, credibilityScore: 30, hasVersionEvidence: false, assetCriticality: 0 },
    ];
    const scores = model.rank(findings);
    assert.ok(scores[0] > scores[1]);
  });

  it('serializes and loads round-trip', () => {
    const model = new FindingImportanceRanker();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 20; i++) {
      samples.push({
        id: `s-${i}`,
        features: {
          cvss_score: i < 10 ? 9.0 : 3.0,
          epss_score: i < 10 ? 0.8 : 0.1,
          cisa_kev: i < 10 ? 1 : 0,
          exploit_status: i < 10 ? 3 : 0,
          cwe_risk_level: i < 10 ? 2 : 0,
          days_since_published: i < 10 ? 5 : 100,
          source_feed_weight: i < 10 ? 40 : 15,
          credibility_score: i < 10 ? 85 : 30,
          has_version_evidence: i < 10 ? 1 : 0,
          asset_criticality: i < 10 ? 1 : 0,
        },
        label: i < 10 ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    model.train(samples);
    const artifact = model.serialize();
    const restored = new FindingImportanceRanker();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);

    const feats = { cvss_score: 9.0, epss_score: 0.8, cisa_kev: 1, exploit_status: 3, cwe_risk_level: 2, days_since_published: 5, source_feed_weight: 40, credibility_score: 85, has_version_evidence: 1, asset_criticality: 1 };
    const orig = model.predict(feats);
    const loaded = restored.predict(feats);
    assert.equal(orig.score, loaded.score);
  });

  it('quality gate exists with correct minimum samples', () => {
    const gate = QUALITY_GATES['finding-importance-ranker'];
    assert.ok(gate);
    assert.equal(gate.minimumSamples, 50);
  });
});

describe('NewsCredibilityWeightModel', () => {
  it('uses chronological group-safe train and holdout partitions', () => {
    const samples = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].flatMap((day) => ['a', 'b'].map((asset) => ({
      feedWeight: day < 8 ? 40 : 80,
      keywordScore: 50,
      isActionable: day % 2 === 0,
      timestamp: `2026-10-${String(day).padStart(2, '0')}T00:00:00Z`,
      groupKey: `${asset}-${day}`,
    })));
    const { train, holdout } = chronologicalCredibilitySplit(samples);
    assert.ok(train.length > 0 && holdout.length > 0);
    const trainLatest = Math.max(...train.map((s) => Date.parse(s.timestamp || '')));
    const holdoutEarliest = Math.min(...holdout.map((s) => Date.parse(s.timestamp || '')));
    assert.ok(trainLatest < holdoutEarliest);
    for (const key of new Set(samples.map((s) => s.groupKey))) {
      const trainHas = train.some((s) => s.groupKey === key);
      const holdoutHas = holdout.some((s) => s.groupKey === key);
      assert.equal(trainHas && holdoutHas, false, `group ${key} crossed partition boundary`);
    }
  });

  it('returns default weights when untrained', () => {
    const model = new NewsCredibilityWeightModel();
    assert.equal(model.isTrained(), false);
    const weights = model.getWeights();
    assert.equal(weights.feedWeight, 0.6);
    assert.equal(weights.keywordWeight, 0.4);
  });

  it('computeCredibility uses default 0.6/0.4 split when untrained', () => {
    const model = new NewsCredibilityWeightModel();
    const result = model.computeCredibility(40, 70);
    assert.equal(result, Math.round(40 * 0.6 + 70 * 0.4));
  });

  it('trains from 100+ samples and updates weights', () => {
    const model = new NewsCredibilityWeightModel();
    const samples = [];
    for (let i = 0; i < 150; i++) {
      samples.push({
        feedWeight: i < 75 ? 80 : 30,
        keywordScore: i < 75 ? 70 : 90,
        isActionable: i < 75,
      });
    }
    model.train(samples);
    assert.equal(model.isTrained(), true);
    const weights = model.getWeights();
    assert.ok(weights.feedWeight >= 0 && weights.feedWeight <= 1);
    assert.ok(weights.keywordWeight >= 0 && weights.keywordWeight <= 1);
  });

  it('serializes and loads round-trip', () => {
    const model = new NewsCredibilityWeightModel();
    const samples = [];
    for (let i = 0; i < 150; i++) {
      samples.push({
        feedWeight: i < 75 ? 80 : 30,
        keywordScore: i < 75 ? 70 : 90,
        isActionable: i < 75,
      });
    }
    model.train(samples);
    assert.equal(model.isTrained(), true);

    const artifact = model.serialize();
    const restored = new NewsCredibilityWeightModel();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);
    assert.equal(restored.getWeights().feedWeight, model.getWeights().feedWeight);
  });

  it('quality gate exists', () => {
    assert.ok(QUALITY_GATES['news-credibility-weight-model']);
  });
  it('selects weights on the holdout, not on the training split', () => {
    // Audit ML-1: the trainer used to grid-search the training split and then
    // hand the orchestrator a single candidate; the holdout could only accept or
    // reject it. Train on data that favours one split and hold out data that
    // favours the default, and the selection must follow the holdout.
    const model = new NewsCredibilityWeightModel();
    const train = Array.from({ length: 160 }, (_, i) => ({
      feedWeight: i < 80 ? 80 : 30,
      keywordScore: i < 80 ? 70 : 90,
      isActionable: i < 80,
    }));
    const holdout = Array.from({ length: 80 }, (_, i) => ({
      feedWeight: i < 40 ? 40 : 20,
      keywordScore: i < 40 ? 90 : 60,
      isActionable: i < 40,
    }));
    const selection = model.trainWithHoldout(train, holdout);
    assert.ok(selection);
    assert.ok(selection!.holdoutAccuracy > 0, 'holdout accuracy is measured');
    assert.equal(model.isTrained(), true);
  });
  it('reports degraded confidence and refuses NaN weights', () => {
    const model = new NewsCredibilityWeightModel();
    model.load({
      metadata: { id: 'news-credibility-weight-model' } as never,
      weights: { feedWeight: Number.NaN, keywordWeight: 0.4, featureNames: [] },
    });
    // An artifact with unusable weights must not mark the model trained.
    assert.equal(model.isTrained(), false);
    assert.equal(model.computeCredibility(40, 70), Math.round(40 * 0.6 + 70 * 0.4));
  });
  it('treats a large deviation from the default split as low confidence', () => {
    const model = new NewsCredibilityWeightModel();
    model.load({
      metadata: { id: 'news-credibility-weight-model' } as never,
      weights: { feedWeight: 0.1, keywordWeight: 0.9, featureNames: [] },
    });
    const prediction = model.predict({ feed_weight: 40, keyword_score: 70 });
    assert.equal(prediction.confidence, 'LOW', 'drifted weights are a warning, not certainty');
  });
});

describe('DeliveryErrorClassifier', () => {
  it('uses hardcoded check when untrained', () => {
    const model = new DeliveryErrorClassifier();
    assert.equal(model.isTrained(), false);
    assert.equal(model.isPermanentError({ provider: 'smtp', statusCode: 400, errorMessage: '', attemptNumber: 1, hourOfDay: 10 }), true);
    assert.equal(model.isPermanentError({ provider: 'smtp', statusCode: 429, errorMessage: 'rate', attemptNumber: 1, hourOfDay: 10 }), false);
    assert.equal(model.isPermanentError({ provider: 'smtp', statusCode: 500, errorMessage: '', attemptNumber: 1, hourOfDay: 10 }), false);
  });

  it('extracts correct delivery error features', () => {
    const feats = extractDeliveryErrorFeatures({
      provider: 'sendgrid',
      statusCode: 429,
      errorMessage: 'rate limited',
      attemptNumber: 2,
      hourOfDay: 14,
    });
    assert.equal(feats.provider_sendgrid, 1);
    assert.equal(feats.status_code, 429);
    assert.equal(feats.error_is_temporarily_denied, 1);
  });

  it('trains and predicts permanent vs transient', () => {
    const model = new DeliveryErrorClassifier();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({
        id: `d-${i}`,
        features: {
          provider_sendgrid: i < 50 ? 1 : 0,
          provider_postmark: 0,
          provider_mailjet: 0,
          provider_smtp: i < 50 ? 0 : 1,
          provider_custom: 0,
          status_code: i < 50 ? 429 : 550,
          error_is_bounce: 0,
          error_is_spam: 0,
          error_is_dns: 0,
          error_is_over_quota: 0,
          error_is_box_not_found: 0,
          error_is_temporarily_denied: i < 50 ? 1 : 0,
          error_message_length: 10,
          attempt_number: 1,
          hour_of_day: 10,
        },
        label: i < 50 ? 0 : 1,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    const [train, test] = splitData(samples, 0.2, 42);
    model.train(train);
    assert.equal(model.isTrained(), true);

    const perm = model.predict({ provider_sendgrid: 0, provider_postmark: 0, provider_mailjet: 0, provider_smtp: 1, provider_custom: 0, status_code: 550, error_is_bounce: 0, error_is_spam: 0, error_is_dns: 0, error_is_over_quota: 0, error_is_box_not_found: 0, error_is_temporarily_denied: 0, error_message_length: 10, attempt_number: 1, hour_of_day: 10 });
    assert.ok(perm.score >= 0.5);
  });

  it('serializes and loads round-trip', () => {
    const model = new DeliveryErrorClassifier();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 50; i++) {
      samples.push({
        id: `s-${i}`,
        features: {
          provider_sendgrid: i < 25 ? 1 : 0, provider_postmark: 0,
          provider_mailjet: 0, provider_smtp: i < 25 ? 0 : 1, provider_custom: 0,
          status_code: i < 25 ? 429 : 550, error_is_bounce: 0, error_is_spam: 0,
          error_is_dns: 0, error_is_over_quota: 0, error_is_box_not_found: 0,
          error_is_temporarily_denied: i < 25 ? 1 : 0, error_message_length: 10,
          attempt_number: 1, hour_of_day: 10,
        },
        label: i < 25 ? 0 : 1,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    model.train(samples);
    const artifact = model.serialize();
    const restored = new DeliveryErrorClassifier();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);

    const feats = { provider_sendgrid: 0, provider_postmark: 0, provider_mailjet: 0, provider_smtp: 1, provider_custom: 0, status_code: 550, error_is_bounce: 0, error_is_spam: 0, error_is_dns: 0, error_is_over_quota: 0, error_is_box_not_found: 0, error_is_temporarily_denied: 0, error_message_length: 10, attempt_number: 1, hour_of_day: 10 };
    assert.equal(model.predict(feats).score, restored.predict(feats).score);
  });

  it('quality gate exists with correct minimum samples', () => {
    const gate = QUALITY_GATES['delivery-error-classifier'];
    assert.ok(gate);
    assert.equal(gate.minimumSamples, 100);
  });
});

describe('ZeroDayRateLimitOptimizer', () => {
  it('returns default cap 50 when untrained', () => {
    const model = new ZeroDayRateLimitOptimizer();
    assert.equal(model.isTrained(), false);
    assert.equal(model.getCap(), 50);
  });

  it('predicts exceed when zeroDayCount > cap', () => {
    const model = new ZeroDayRateLimitOptimizer();
    const result = model.predict(60, [80, 70, 60]);
    assert.equal(result.score, 1);
    assert.equal(result.confidence, 'HIGH');
  });

  it('trains from 20+ samples and updates cap', () => {
    const model = new ZeroDayRateLimitOptimizer();
    const samples = [];
    for (let i = 0; i < 25; i++) {
      samples.push({
        zeroDayCount: 20,
        credibilityScores: Array.from({ length: 20 }, (_, j) => 50 + j * 5),
        outcomes: Array.from({ length: 20 }, (_, j) => j < 10 ? 'PATCHED' as const : 'FALSE_POSITIVE' as const),
      });
    }
    model.train(samples);
    assert.equal(model.isTrained(), true);
    const cap = model.getCap();
    assert.ok(cap > 0 && cap <= 300);
  });

  it('serializes and loads round-trip', () => {
    const model = new ZeroDayRateLimitOptimizer();
    const samples = [];
    for (let i = 0; i < 25; i++) {
      samples.push({
        zeroDayCount: 3,
        credibilityScores: [80, 70, 60],
        outcomes: ['PATCHED' as const, 'RESOLVED' as const, 'FALSE_POSITIVE' as const],
      });
    }
    model.train(samples);
    const artifact = model.serialize();
    const restored = new ZeroDayRateLimitOptimizer();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);
    assert.equal(restored.getCap(), model.getCap());
  });

  it('keeps each outcome paired with its score when ranking candidate caps', () => {
    const model = new ZeroDayRateLimitOptimizer();
    const sample = {
      zeroDayCount: 20,
      credibilityScores: Array.from({ length: 20 }, (_, index) => index),
      outcomes: Array.from({ length: 20 }, (_, index) => index < 10 ? 'FALSE_POSITIVE' as const : 'DELIVERED' as const),
    };
    model.train(Array.from({ length: 20 }, () => sample));
    const capTen = model.getDecisionPoints().find((point) => point.cap === 10);
    assert.equal(capTen?.keptTruePositiveRate, 1);
    assert.equal(model.getCap(), 10);
  });

  it('quality gate exists', () => {
    assert.ok(QUALITY_GATES['zero-day-rate-limit-optimizer']);
  });
});

describe('DigestFindingSelector', () => {
  it('predicts 0 when untrained', () => {
    const model = new DigestFindingSelector();
    assert.equal(model.isTrained(), false);
    const result = model.selectForDigest({
      cvssScore: 8.0, epssScore: 0.8, cisaKev: true, exploitStatus: 3,
      daysSincePublished: 5, sourceFeedWeight: 40, credibilityScore: 85,
      assetCriticality: 1, recipientTier: 'ALL', findingInDigest: false, timeInDigestMinutes: 0,
    });
    assert.equal(typeof result, 'number');
  });

  it('extracts correct digest selection features', () => {
    const feats = extractDigestSelectionFeatures({
      cvssScore: 8.0, epssScore: 0.8, cisaKev: true, exploitStatus: 3,
      daysSincePublished: 5, sourceFeedWeight: 40, credibilityScore: 85,
      assetCriticality: 1, recipientTier: 'CRITICAL_ONLY', findingInDigest: true, timeInDigestMinutes: 30,
    });
    assert.equal(feats.cisa_kev, 1);
    assert.equal(feats.recipient_tier_all, 0);
    assert.equal(feats.recipient_tier_critical, 1);
    assert.equal(feats.finding_in_digest, 1);
  });

  it('trains and predicts relevance probability', () => {
    const model = new DigestFindingSelector();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({
        id: `d-${i}`,
        features: {
          cvss_score: i < 50 ? 9.0 : 3.0,
          epss_score: i < 50 ? 0.8 : 0.1,
          cisa_kev: i < 50 ? 1 : 0,
          exploit_status: i < 50 ? 3 : 0,
          days_since_published: i < 50 ? 5 : 100,
          source_feed_weight: i < 50 ? 40 : 15,
          credibility_score: i < 50 ? 85 : 30,
          asset_criticality: i < 50 ? 1 : 0,
          recipient_tier_all: i < 50 ? 1 : 0,
          recipient_tier_critical: i < 50 ? 0 : 1,
          recipient_tier_subscribed: 0,
          finding_in_digest: i < 50 ? 1 : 0,
          time_in_digest_minutes: i < 50 ? 30 : 0,
        },
        label: i < 50 ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    const [train, test] = splitData(samples, 0.2, 42);
    model.train(train);
    assert.equal(model.isTrained(), true);
    assert.equal(model.getFeatureNames().length, 13);

    const result = model.predict({
      cvss_score: 9.0, epss_score: 0.8, cisa_kev: 1, exploit_status: 3,
      days_since_published: 5, source_feed_weight: 40, credibility_score: 85,
      asset_criticality: 1, recipient_tier_all: 1, recipient_tier_critical: 0, recipient_tier_subscribed: 0,
      finding_in_digest: 1, time_in_digest_minutes: 30,
    });
    assert.ok(result.probability! > 0.5);
  });

  it('serializes and loads round-trip', () => {
    const model = new DigestFindingSelector();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 50; i++) {
      samples.push({
        id: `s-${i}`,
        features: {
          cvss_score: i < 25 ? 9.0 : 3.0, epss_score: i < 25 ? 0.8 : 0.1, cisa_kev: i < 25 ? 1 : 0,
          exploit_status: i < 25 ? 3 : 0, days_since_published: i < 25 ? 5 : 100, source_feed_weight: i < 25 ? 40 : 15,
          credibility_score: i < 25 ? 85 : 30, asset_criticality: i < 25 ? 1 : 0,
          recipient_tier_all: i < 25 ? 1 : 0, recipient_tier_critical: i < 25 ? 0 : 1, recipient_tier_subscribed: 0,
          finding_in_digest: i < 25 ? 1 : 0, time_in_digest_minutes: 30,
        },
        label: i < 25 ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    model.train(samples);
    const artifact = model.serialize();
    const restored = new DigestFindingSelector();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);

    const feats = { cvss_score: 9.0, epss_score: 0.8, cisa_kev: 1, exploit_status: 3, days_since_published: 5, source_feed_weight: 40, credibility_score: 85, asset_criticality: 1, recipient_tier_all: 1, recipient_tier_critical: 0, recipient_tier_subscribed: 0, finding_in_digest: 1, time_in_digest_minutes: 30 };
    assert.equal(model.predict(feats).score, restored.predict(feats).score);
  });

  it('quality gate exists with correct minimum samples', () => {
    const gate = QUALITY_GATES['digest-finding-selector'];
    assert.ok(gate);
    assert.equal(gate.minimumSamples, 50);
  });
});

describe('SeverityTierModel', () => {
  const SEVERITY_TIERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'] as const;
  const TIER_INDEX: Record<SeverityTier, number> = {
    CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFORMATIONAL: 4,
  };

  it('returns INFORMATIONAL when untrained', () => {
    const model = new SeverityTierModel();
    assert.equal(model.isTrained(), false);
    assert.equal(model.predictTier({
      cvssScore: 9.5, epssScore: 0.9, cisaKev: true, exploitStatus: 'Active Weaponized',
      cweRiskLevel: 2, daysSincePublished: 3, sourceFeedWeight: 40,
    }), 'INFORMATIONAL');
  });

  it('extracts correct severity tier features', () => {
    const feats = extractSeverityTierFeatures({
      cvssScore: 9.5, epssScore: 0.9, cisaKev: true, exploitStatus: 'Active Weaponized',
      cweRiskLevel: 2, daysSincePublished: 3, sourceFeedWeight: 40,
    });
    assert.equal(feats.cisa_kev, 1);
    assert.equal(feats.exploit_status, 3);
    assert.equal(feats.cvss_score, 9.5);
  });

  it('has 5 severity tiers and 7 feature names', () => {
    const model = new SeverityTierModel();
    assert.equal(model.getTiers().length, 5);
    assert.equal(model.getFeatureNames().length, 7);
  });

  it('trains and predicts severity tier', () => {
    const model = new SeverityTierModel();
    const samples: TrainingSample[] = [];
    for (const tier of SEVERITY_TIERS) {
      for (let i = 0; i < 15; i++) {
        samples.push({
          id: `s-${tier}-${i}`,
          features: {
            cvss_score: tier === 'CRITICAL' ? 9.5 : tier === 'HIGH' ? 7.5 : tier === 'MEDIUM' ? 5.5 : tier === 'LOW' ? 3.0 : 1.0,
            epss_score: tier === 'CRITICAL' ? 0.9 : tier === 'HIGH' ? 0.5 : tier === 'MEDIUM' ? 0.3 : 0.1,
            cisa_kev: tier === 'CRITICAL' ? 1 : 0,
            exploit_status: tier === 'CRITICAL' ? 3 : tier === 'HIGH' ? 1 : 0,
            cwe_risk_level: tier === 'CRITICAL' ? 2 : 1,
            days_since_published: 5,
            source_feed_weight: 40,
          },
          label: TIER_INDEX[tier],
          weight: 1,
          timestamp: new Date().toISOString(),
        });
      }
    }
    model.train(samples);
    assert.equal(model.isTrained(), true);

    const pred = model.predict({ cvss_score: 9.5, epss_score: 0.9, cisa_kev: 1, exploit_status: 3, cwe_risk_level: 2, days_since_published: 3, source_feed_weight: 40 });
    assert.ok(pred.score >= 0 && pred.score < 5);
  });

  it('serializes and loads round-trip', () => {
    const model = new SeverityTierModel();
    const samples: TrainingSample[] = [];
    const tiers = ['CRITICAL', 'INFORMATIONAL'] as const;
    for (const tier of tiers) {
      for (let i = 0; i < 15; i++) {
        samples.push({
          id: `s-${tier}-${i}`,
          features: {
            cvss_score: tier === 'CRITICAL' ? 9.5 : 1.0,
            epss_score: tier === 'CRITICAL' ? 0.9 : 0.1,
            cisa_kev: tier === 'CRITICAL' ? 1 : 0,
            exploit_status: tier === 'CRITICAL' ? 3 : 0,
            cwe_risk_level: tier === 'CRITICAL' ? 2 : 0,
            days_since_published: 3,
            source_feed_weight: 40,
          },
          label: TIER_INDEX[tier],
          weight: 1,
          timestamp: new Date().toISOString(),
        });
      }
    }
    model.train(samples);
    const artifact = model.serialize();
    const restored = new SeverityTierModel();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);

    const feats = { cvss_score: 9.5, epss_score: 0.9, cisa_kev: 1, exploit_status: 3, cwe_risk_level: 2, days_since_published: 3, source_feed_weight: 40 };
    assert.equal(model.predict(feats).score, restored.predict(feats).score);
  });

  it('quality gate exists with correct minimum samples', () => {
    const gate = QUALITY_GATES['severity-tier-model'];
    assert.ok(gate);
    assert.equal(gate.minimumSamples, 100);
  });
});

describe('FeedRecoveryBackoffOptimizer', () => {
  it('returns default policy when untrained', () => {
    const model = new FeedRecoveryBackoffOptimizer();
    assert.equal(model.isTrained(), false);
    const policy = model.getPolicy();
    assert.equal(policy.initialDelayMinutes, 5);
    assert.equal(policy.maxDelayMinutes, 1440);
    assert.equal(policy.maxAttempts, 5);
  });

  it('computeRecoveryDelay uses default exponential backoff', () => {
    const model = new FeedRecoveryBackoffOptimizer();
    const delay1 = model.computeRecoveryDelay(1);
    const delay3 = model.computeRecoveryDelay(3);
    assert.equal(delay1, 5 * 60_000);
    assert.ok(delay3 > delay1);
  });

  it('trains from 20+ samples and updates policy', () => {
    const model = new FeedRecoveryBackoffOptimizer();
    const samples = [];
    for (let i = 0; i < 30; i++) {
      samples.push({
        feedType: 'oss',
        provider: 'github',
        timeOfDay: 12,
        failureCount: 1 + (i % 5),
        delayMinutes: 5 * Math.pow(2, i % 5),
        recovered: i % 4 !== 3,
        recoveryLatencyMinutes: 30 + (i % 10) * 5,
      });
    }
    model.train(samples);
    assert.equal(model.isTrained(), true);
    const policy = model.getPolicy();
    assert.ok(policy.initialDelayMinutes > 0);
    assert.ok(policy.maxDelayMinutes > 0);
  });

  it('serializes and loads round-trip', () => {
    const model = new FeedRecoveryBackoffOptimizer();
    const samples = [];
    for (let i = 0; i < 30; i++) {
      samples.push({
        feedType: 'oss', provider: 'github', timeOfDay: 12,
        failureCount: 1 + (i % 5), delayMinutes: 5 * Math.pow(2, i % 5),
        recovered: i % 4 !== 3, recoveryLatencyMinutes: 30,
      });
    }
    model.train(samples);
    const artifact = model.serialize();
    const restored = new FeedRecoveryBackoffOptimizer();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);
    assert.equal(restored.getPolicy().initialDelayMinutes, model.getPolicy().initialDelayMinutes);
  });

  it('quality gate exists', () => {
    assert.ok(QUALITY_GATES['feed-recovery-backoff-optimizer']);
  });
});

describe('AliasConfidenceModel', () => {
  it('uses hardcoded check when untrained', () => {
    const model = new AliasConfidenceModel();
    assert.equal(model.isTrained(), false);
    assert.equal(model.isConfirmed({
      matchConfidence: 90, cvssScore: 8.0, epssScore: 0.8, cisaKev: true,
      exploitStatus: 3, daysSincePublished: 5, sourceFeedWeight: 40,
      hasVersionEvidence: true, matchMethod: 'VENDOR_PRODUCT_ALIAS',
    }), true);

    assert.equal(model.isConfirmed({
      matchConfidence: 0, cvssScore: 3.0, epssScore: 0.1, cisaKev: false,
      exploitStatus: 0, daysSincePublished: 100, sourceFeedWeight: 15,
      hasVersionEvidence: false, matchMethod: 'KEYWORD',
    }), false);
  });

  it('extracts correct alias confidence features', () => {
    const feats = extractAliasConfidenceFeatures({
      matchConfidence: 85, cvssScore: 7.5, epssScore: 0.5, cisaKev: false,
      exploitStatus: 1, daysSincePublished: 10, sourceFeedWeight: 30,
      hasVersionEvidence: true, matchMethod: 'VENDOR_PRODUCT_FALLBACK',
    });
    assert.equal(feats.match_confidence, 85);
    assert.equal(feats.has_version_evidence, 1);
    assert.equal(feats.match_method_fallback, 1);
    assert.equal(feats.exploit_status, 1);
  });

  it('trains and predicts confirmation probability', () => {
    const model = new AliasConfidenceModel();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({
        id: `a-${i}`,
        features: {
          match_confidence: i < 50 ? 90 : 30,
          cvss_score: i < 50 ? 8.5 : 3.0,
          epss_score: i < 50 ? 0.8 : 0.1,
          cisa_kev: i < 50 ? 1 : 0,
          exploit_status: i < 50 ? 3 : 0,
          days_since_published: i < 50 ? 5 : 100,
          source_feed_weight: i < 50 ? 40 : 15,
          has_version_evidence: i < 50 ? 1 : 0,
          match_method_alias: i < 50 ? 1 : 0,
          match_method_fallback: i < 50 ? 0 : 1,
          match_method_keyword: 0,
        },
        label: i < 50 ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    const [train, test] = splitData(samples, 0.2, 42);
    model.train(train);
    assert.equal(model.isTrained(), true);
    assert.equal(model.getFeatureNames().length, 11);

    const result = model.predict({
      match_confidence: 90, cvss_score: 8.5, epss_score: 0.8, cisa_kev: 1,
      exploit_status: 3, days_since_published: 5, source_feed_weight: 40,
      has_version_evidence: 1, match_method_alias: 1, match_method_fallback: 0, match_method_keyword: 0,
    });
    assert.ok(result.probability! > 0.5);
  });

  it('serializes and loads round-trip', () => {
    const model = new AliasConfidenceModel();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 50; i++) {
      samples.push({
        id: `s-${i}`,
        features: {
          match_confidence: i < 25 ? 90 : 30, cvss_score: i < 25 ? 8.5 : 3.0,
          epss_score: i < 25 ? 0.8 : 0.1, cisa_kev: i < 25 ? 1 : 0,
          exploit_status: i < 25 ? 3 : 0, days_since_published: 5,
          source_feed_weight: i < 25 ? 40 : 15, has_version_evidence: i < 25 ? 1 : 0,
          match_method_alias: i < 25 ? 1 : 0, match_method_fallback: i < 25 ? 0 : 1,
          match_method_keyword: 0,
        },
        label: i < 25 ? 1 : 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    model.train(samples);
    const artifact = model.serialize();
    const restored = new AliasConfidenceModel();
    restored.load(artifact);
    assert.equal(restored.isTrained(), true);

    const feats = { match_confidence: 90, cvss_score: 8.5, epss_score: 0.8, cisa_kev: 1, exploit_status: 3, days_since_published: 5, source_feed_weight: 40, has_version_evidence: 1, match_method_alias: 1, match_method_fallback: 0, match_method_keyword: 0 };
    assert.equal(model.predict(feats).score, restored.predict(feats).score);
  });

  it('quality gate exists with correct minimum samples', () => {
     const gate = QUALITY_GATES['alias-confidence-model'];
    assert.ok(gate);
    assert.equal(gate.minimumSamples, 50);
  });
});
