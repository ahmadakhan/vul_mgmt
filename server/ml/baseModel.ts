/**
 * Base model wrapper: bridges the pure-algorithm engines to the TrainableModel
 * interface used by ModelRegistry. Handles metadata, versioning, and the
 * serialize/load cycle (ModelArtifact ↔ algorithm weights).
 *
 * Concrete models extend this and implement train, predict, serialize, and load.
 * Those that need custom batch logic can override predictBatch.
 */
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample, TrainableModel } from './types.ts';

export abstract class BaseModel implements TrainableModel {
  protected metadata: ModelMetadata;
  protected trained = false;

  constructor(metadata: ModelMetadata) {
    this.metadata = metadata;
  }

  abstract train(samples: TrainingSample[]): void;
  abstract predict(features: Record<string, number>): PredictionResult;
  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }
  abstract serialize(): ModelArtifact;
  abstract load(artifact: ModelArtifact): void;
  abstract getFeatureNames(): string[];

  getMetadata(): ModelMetadata {
    return this.metadata;
  }

  isTrained(): boolean {
    return this.trained;
  }
}
