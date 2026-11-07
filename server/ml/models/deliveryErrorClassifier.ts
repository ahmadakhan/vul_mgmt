/**
 * Delivery Error Classifier — binary classifier that predicts whether a
 * delivery failure is permanent (don't retry) or transient (retry),
 * replacing the hardcoded HTTP status classification in
 * delivery.ts:1557,1566 and emailProviders.ts:375-407.
 *
 * File target: server/delivery.ts:1557 (HTTP status permanent/transient)
 *              server/delivery.ts:1566 (EmailProviderError permanent classification)
 *              server/emailProviders.ts:375-407 (interpret() provider-specific codes)
 *
 * Uses LogisticRegression to learn from historical delivery outcomes:
 *   features = provider, status_code, error_message_features, attempt_number, hour
 *   label    = 1 if permanent (FAILED/BOUNCED), 0 if transient (should retry)
 *
 * The hardcoded status-code rules (4xx permanent except 408/429, 5xx transient)
 * are the fallback when the model is untrained.
 */
import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const DELIVERY_ERROR_FEATURE_NAMES = [
  'provider_sendgrid',
  'provider_postmark',
  'provider_mailjet',
  'provider_smtp',
  'provider_custom',
  'status_code',
  'error_is_bounce',
  'error_is_spam',
  'error_is_dns',
  'error_is_over_quota',
  'error_is_box_not_found',
  'error_is_temporarily_denied',
  'error_message_length',
  'attempt_number',
  'hour_of_day',
] as const;

export interface DeliveryErrorFeatures {
  provider: string;
  statusCode: number;
  errorMessage: string;
  attemptNumber: number;
  hourOfDay: number;
}

export function extractDeliveryErrorFeatures(f: DeliveryErrorFeatures): Record<string, number> {
  const providerKey = f.provider.toLowerCase();
  const msg = (f.errorMessage ?? '').toLowerCase();

  return {
    provider_sendgrid: providerKey.includes('sendgrid') ? 1 : 0,
    provider_postmark: providerKey.includes('postmark') ? 1 : 0,
    provider_mailjet: providerKey.includes('mailjet') ? 1 : 0,
    provider_smtp: providerKey.includes('smtp') ? 1 : 0,
    provider_custom: providerKey.includes('custom') || providerKey.includes('api') ? 1 : 0,
    status_code: f.statusCode,
    error_is_bounce: msg.includes('bounce') && !msg.includes('hard bounce') ? 1 : 0,
    error_is_spam: msg.includes('spam') || msg.includes('content rejected') ? 1 : 0,
    error_is_dns: msg.includes('dns') || (msg.includes('domain') && msg.includes('not found')) ? 1 : 0,
    error_is_over_quota: msg.includes('quota') || msg.includes('over quota') || msg.includes('mailbox full') ? 1 : 0,
    error_is_box_not_found: msg.includes('not found') || msg.includes('no such') || (msg.includes('address') && msg.includes('invalid')) ? 1 : 0,
    error_is_temporarily_denied: msg.includes('temporarily') || msg.includes('throttl') || msg.includes('rate') ? 1 : 0,
    error_message_length: msg.length,
    attempt_number: f.attemptNumber,
    hour_of_day: f.hourOfDay,
  };
}

export class DeliveryErrorClassifier extends BaseModel {
  private readonly algo: LogisticRegression;

  constructor() {
    const metadata: ModelMetadata = {
      id: 'delivery-error-classifier',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...DELIVERY_ERROR_FEATURE_NAMES],
      description: 'Classifies delivery errors as permanent vs transient',
    };
    super(metadata);
    this.algo = new LogisticRegression();
  }

  train(samples: TrainingSample[]): void {
    this.algo.train(samples, { threshold: 0.5, iterations: 1000 });
    this.trained = true;
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  predict(features: Record<string, number>): PredictionResult {
    return this.algo.predict(features);
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return this.algo.predictBatch(features);
  }

  isPermanentError(f: DeliveryErrorFeatures): boolean {
    if (!this.trained) {
      return this.hardcodedPermanentCheck(f);
    }
    const feats = extractDeliveryErrorFeatures(f);
    const result = this.predict(feats);
    return result.score >= 0.5;
  }

  isTransientError(f: DeliveryErrorFeatures): boolean {
    return !this.isPermanentError(f);
  }

  private hardcodedPermanentCheck(f: DeliveryErrorFeatures): boolean {
    const s = f.statusCode;
    if (s === 408 || s === 429) return false;
    if (s >= 400 && s < 500) return true;
    return false;
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.algo.serialize(),
    };
  }

  load(artifact: ModelArtifact): void {
    this.algo.load(artifact.weights as ReturnType<LogisticRegression['serialize']>);
    this.metadata = artifact.metadata;
    this.trained = true;
  }

  getFeatureNames(): string[] {
    return [...DELIVERY_ERROR_FEATURE_NAMES];
  }

  static collectTrainingData(samples: Array<{
    provider: string;
    statusCode: number;
    errorMessage: string;
    attemptNumber: number;
    hourOfDay: number;
    isPermanent: boolean;
  }>): TrainingSample[] {
    return samples.map((s, i) => ({
      id: `delivery-err-${i}`,
      features: extractDeliveryErrorFeatures({
        provider: s.provider,
        statusCode: s.statusCode,
        errorMessage: s.errorMessage,
        attemptNumber: s.attemptNumber,
        hourOfDay: s.hourOfDay,
      }),
      label: s.isPermanent ? 1 : 0,
      weight: 1,
      timestamp: new Date().toISOString(),
    }));
  }
}
