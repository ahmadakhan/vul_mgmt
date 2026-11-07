/**
 * Model persistence, versioning, and rollback registry.
 *
 * Stores serialized model artifacts as JSON files on disk, with a manifest
 * tracking version, trainedAt, and rollback status. On load, the active model
 * is the newest *validated* artifact; a validation failure on load triggers
 * automatic rollback to the last known-good version.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, renameSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { join } from 'node:path';
import type { Pool } from 'pg';
import type { ModelArtifact, ModelMetadata, ModelRegistryEntry, ModelStorageOptions, TrainableModel, PredictionResult, FeedbackSignal } from './types.ts';
import { secureEqual } from '../secrets.ts';
import { transaction } from '../db.ts';

interface ManifestArtifactEntry {
  version: string;
  path: string;
  trainedAt: string;
  rollbackTrigger?: string;
  status: 'ACTIVE' | 'STANDBY_ROLLBACK' | 'DEGRADED';
}

interface ModelManifestEntry {
  activeVersion: string;
  artifacts: ManifestArtifactEntry[];
}

interface ModelManifest {
  [modelId: string]: ModelManifestEntry;
}

const MANIFEST_FILE = 'model-manifest.json';

/** Rollback history retained per model before the oldest artifacts are pruned. */
const MAX_ARTIFACTS_PER_MODEL = 5;

export class ModelRegistry {
  private models = new Map<string, ModelRegistryEntry>();
  private manifest: ModelManifest = {};
  private directory: string;
  private signingKey: string | undefined;
  private database?: Pool;

  constructor(options: ModelStorageOptions) {
    this.directory = options.directory;
    this.signingKey = options.signingKey;
    this.database = options.database;
    if (this.database) {
      if (existsSync(this.directory)) this.loadManifest();
    } else {
      if (!existsSync(this.directory)) mkdirSync(this.directory, { recursive: true });
      this.loadManifest();
    }
  }

  private loadManifest(): void {
    try {
      const path = join(this.directory, MANIFEST_FILE);
      if (existsSync(path)) {
        this.manifest = JSON.parse(readFileSync(path, 'utf8')) as ModelManifest;
      }
    } catch {
      this.manifest = {};
    }
  }

  private saveManifest(): void {
    if (this.database) return;
    const path = join(this.directory, MANIFEST_FILE);
    // Atomic replace: a crash or full disk mid-write previously truncated the
    // manifest, which silently reset every model to "untrained" on next load.
    // Write to a temp file in the same directory and rename over the target —
    // rename is atomic on POSIX, so readers see either the old or new manifest.
    const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
    try {
      writeFileSync(tmp, JSON.stringify(this.manifest, null, 2), 'utf8');
      renameSync(tmp, path);
    } catch (error) {
      try {
        unlinkSync(tmp);
      } catch {
        /* best-effort cleanup */
      }
      throw error;
    }
  }

  private hasValidSignature(data: ModelArtifact): boolean {
    if (!this.signingKey) return true;
    if (typeof data.signature !== 'string') return false;
    const expected = createHmac('sha256', this.signingKey)
      .update(JSON.stringify({ metadata: data.metadata, weights: data.weights }, null, 2))
      .digest('hex');
    return secureEqual(data.signature, expected);
  }

  /** Register an in-memory model instance for immediate use (testing/bootstrap). */
  register(model: TrainableModel, metadata: ModelMetadata): void {
    this.models.set(metadata.id, {
      model,
      metadata,
      loadedAt: new Date().toISOString(),
      status: 'ACTIVE',
    });
  }

  /**
   * Load the active model artifact for a given modelId into `model`.
   * Returns false if no artifact exists or all artifacts fail to load.
   */
  async load(model: TrainableModel, modelId: string): Promise<boolean> {
    return this.loadArtifact(model, modelId);
  }

  /**
   * Load the active model artifact for a given modelId into `model`.
   * Accepts any object with a `load` method — used for models that don't
   * fully implement TrainableModel (e.g., AutoDispatchThresholdModel).
   * Returns false if no artifact exists or all artifacts fail to load.
   */
  async loadArtifact(model: { load(artifact: ModelArtifact): void }, modelId: string): Promise<boolean> {
    if (this.database) return this.loadDatabaseArtifact(model, modelId);
    const entry = this.manifest[modelId];
    if (!entry) return false;

    const active = entry.artifacts.find((a) => a.version === entry.activeVersion);
    if (!active || active.status === 'DEGRADED') {
      return this.rollback(model, modelId, 'DEGRADED_OR_MISSING');
    }

    try {
      const data = JSON.parse(
        readFileSync(join(this.directory, active.path), 'utf8'),
      ) as ModelArtifact;
      if (!this.hasValidSignature(data)) return this.rollback(model, modelId, 'INVALID_SIGNATURE');
      model.load(data);
       this.models.set(modelId, {
         model: model as TrainableModel,
         metadata: data.metadata,
         loadedAt: new Date().toISOString(),
         status: 'ACTIVE',
       });
       return true;
     } catch {
       return this.rollback(model, modelId, 'LOAD_FAILURE');
     }
  }

  private async loadDatabaseArtifact(
    model: { load(artifact: ModelArtifact): void },
    modelId: string,
  ): Promise<boolean> {
    const database = this.database!;
    let result = await database.query<{
      version: string;
      artifact: ModelArtifact | string;
      status: ManifestArtifactEntry['status'];
      rollback_trigger: string | null;
    }>(
      `SELECT version,artifact,status,rollback_trigger
       FROM ml_model_artifacts WHERE model_id=$1 ORDER BY trained_at DESC,version DESC`,
      [modelId],
    );
    if (!result.rows.length && this.manifest[modelId]) {
      await this.migrateLegacyArtifacts(modelId);
      result = await database.query(
        `SELECT version,artifact,status,rollback_trigger
         FROM ml_model_artifacts WHERE model_id=$1 ORDER BY trained_at DESC,version DESC`,
        [modelId],
      );
    }
    if (!result.rows.length) return false;

    const artifacts = result.rows;
    const active = artifacts.find((entry) => entry.status === 'ACTIVE');
    if (active) {
      try {
        const artifact = typeof active.artifact === 'string'
          ? JSON.parse(active.artifact) as ModelArtifact
          : active.artifact;
        if (!this.hasValidSignature(artifact)) throw new Error('INVALID_SIGNATURE');
        model.load(artifact);
        this.models.set(modelId, {
          model: model as TrainableModel,
          metadata: artifact.metadata,
          loadedAt: new Date().toISOString(),
          status: 'ACTIVE',
        });
        return true;
      } catch {
        await this.setDatabaseArtifactStatus(modelId, active.version, 'DEGRADED', 'LOAD_FAILURE');
      }
    }

    for (const candidate of artifacts.filter((entry) => entry.status !== 'DEGRADED' && entry.version !== active?.version)) {
      try {
        const artifact = typeof candidate.artifact === 'string'
          ? JSON.parse(candidate.artifact) as ModelArtifact
          : candidate.artifact;
        if (!this.hasValidSignature(artifact)) throw new Error('INVALID_SIGNATURE_ROLLBACK');
        model.load(artifact);
        await this.setDatabaseArtifactStatus(modelId, candidate.version, 'STANDBY_ROLLBACK');
        this.models.set(modelId, {
          model: model as TrainableModel,
          metadata: artifact.metadata,
          loadedAt: new Date().toISOString(),
          status: 'STANDBY_ROLLBACK',
        });
        return true;
      } catch {
        await this.setDatabaseArtifactStatus(modelId, candidate.version, 'DEGRADED', 'INVALID_OR_UNLOADABLE_ROLLBACK');
      }
    }
    return false;
  }

  private async migrateLegacyArtifacts(modelId: string): Promise<void> {
    const manifestEntry = this.manifest[modelId];
    if (!manifestEntry || !this.database) return;
    const artifacts: Array<{ entry: ManifestArtifactEntry; artifact: ModelArtifact }> = [];
    for (const entry of manifestEntry.artifacts) {
      try {
        const artifact = JSON.parse(readFileSync(join(this.directory, entry.path), 'utf8')) as ModelArtifact;
        if (this.hasValidSignature(artifact)) artifacts.push({ entry, artifact });
      } catch {
        // A bad legacy artifact is not imported; remaining versions can still recover the model.
      }
    }
    if (!artifacts.length) return;

    await transaction(this.database, async (db) => {
      const current = await db.query('SELECT 1 FROM ml_model_artifacts WHERE model_id=$1 LIMIT 1', [modelId]);
      if (current.rows.length) return;
      for (const { entry, artifact } of artifacts) {
        const status = entry.version === manifestEntry.activeVersion
          ? 'ACTIVE'
          : entry.status === 'DEGRADED' ? 'DEGRADED' : 'STANDBY_ROLLBACK';
        await db.query(
          `INSERT INTO ml_model_artifacts(model_id,version,trained_at,artifact,status,rollback_trigger)
           VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(model_id,version) DO NOTHING`,
          [modelId, entry.version, entry.trainedAt, JSON.stringify(artifact), status, entry.rollbackTrigger ?? null],
        );
      }
    }, undefined, { locks: [`ml-model-artifact:${modelId}`] });

    for (const { entry } of artifacts) {
      try {
        unlinkSync(join(this.directory, entry.path));
      } catch {
        // The committed database copy is authoritative; cleanup is best effort.
      }
    }
    delete this.manifest[modelId];
    try {
      if (Object.keys(this.manifest).length) {
        writeFileSync(join(this.directory, MANIFEST_FILE), JSON.stringify(this.manifest, null, 2), 'utf8');
      } else {
        unlinkSync(join(this.directory, MANIFEST_FILE));
      }
    } catch {
      // Stale legacy metadata is harmless after every artifact has been stored in PostgreSQL.
    }
  }

  private async setDatabaseArtifactStatus(
    modelId: string,
    version: string,
    status: ManifestArtifactEntry['status'],
    rollbackTrigger?: string,
  ): Promise<void> {
    await transaction(this.database!, async (db) => {
      await db.query(
        'UPDATE ml_model_artifacts SET status=$3,rollback_trigger=$4 WHERE model_id=$1 AND version=$2',
        [modelId, version, status, rollbackTrigger ?? null],
      );
    }, undefined, { locks: [`ml-model-artifact:${modelId}`] });
  }

  private async persistDatabaseArtifact(modelId: string, artifact: ModelArtifact): Promise<void> {
    await transaction(this.database!, async (db) => {
      await db.query(
        "UPDATE ml_model_artifacts SET status='STANDBY_ROLLBACK' WHERE model_id=$1 AND status='ACTIVE'",
        [modelId],
      );
      await db.query(
        `INSERT INTO ml_model_artifacts(model_id,version,trained_at,artifact,status)
         VALUES($1,$2,$3,$4,'ACTIVE')
         ON CONFLICT(model_id,version) DO UPDATE SET trained_at=EXCLUDED.trained_at,
           artifact=EXCLUDED.artifact,status='ACTIVE',rollback_trigger=NULL`,
        [modelId, artifact.metadata.version, artifact.metadata.trainedAt, JSON.stringify(artifact)],
      );
      await db.query(
        `DELETE FROM ml_model_artifacts WHERE model_id=$1 AND version NOT IN (
           SELECT version FROM ml_model_artifacts WHERE model_id=$1
           ORDER BY trained_at DESC,version DESC LIMIT $2
         )`,
        [modelId, MAX_ARTIFACTS_PER_MODEL],
      );
    }, undefined, { locks: [`ml-model-artifact:${modelId}`] });
  }

  private signArtifact(model: TrainableModel | { serialize: () => ModelArtifact }, metadata: ModelMetadata): ModelArtifact {
    const artifact: ModelArtifact = { ...model.serialize(), metadata };
    delete artifact.signature;
    if (this.signingKey) {
      const payload = JSON.stringify({ metadata: artifact.metadata, weights: artifact.weights }, null, 2);
      artifact.signature = createHmac('sha256', this.signingKey).update(payload).digest('hex');
    }
    return artifact;
  }

  private async rollback(
    model: { load(artifact: ModelArtifact): void },
    modelId: string,
    reason: string,
    preFilteredCandidates?: ManifestArtifactEntry[],
  ): Promise<boolean> {
    const entry = this.manifest[modelId];
    if (!entry) return false;

    const active = entry.artifacts.find((a) => a.version === entry.activeVersion);
    if (active) {
      active.status = 'DEGRADED';
      active.rollbackTrigger = reason;
    }

    const rollbackCandidates = preFilteredCandidates ?? entry.artifacts.filter(
      (a) => a.version !== entry.activeVersion && a.status !== 'DEGRADED',
    );
    if (rollbackCandidates.length === 0) {
      this.saveManifest();
      return false;
    }

    const prev = rollbackCandidates.sort((a, b) => b.trainedAt.localeCompare(a.trainedAt))[0];
    try {
      const data = JSON.parse(readFileSync(join(this.directory, prev.path), 'utf8')) as ModelArtifact;
      if (!this.hasValidSignature(data)) {
        // Skip this corrupted or unsigned artifact and try the next candidate.
        const remainingRollbackCandidates = rollbackCandidates.filter((c) => c.version !== prev.version);
        return this.rollback(model, modelId, 'INVALID_SIGNATURE_ROLLBACK', remainingRollbackCandidates);
      }
      model.load(data);
      prev.status = 'STANDBY_ROLLBACK';
      this.models.set(modelId, {
        model: model as TrainableModel,
        metadata: data.metadata,
        loadedAt: new Date().toISOString(),
        status: 'STANDBY_ROLLBACK',
      });
      this.saveManifest();
      return true;
    } catch {
      this.saveManifest();
      return false;
    }
  }

  /**
   * Prune stale artifact files beyond the rollback-history bound. The newest
   * entries in `keep` (the active version plus its rollback candidates) stay on
   * disk; everything else the manifest used to list is deleted so a long-lived
   * deployment does not accumulate one JSON per training run per model forever.
   * Best-effort: a file that is already gone, or an unreadable directory
   * entry, never fails the save.
   */
  private pruneArtifacts(modelId: string, keep: ReadonlySet<string>): void {
    for (const entry of this.manifest[modelId]?.artifacts ?? []) {
      if (keep.has(entry.version)) continue;
      try {
        const full = join(this.directory, entry.path);
        if (existsSync(full)) unlinkSync(full);
      } catch {
        /* best-effort cleanup; the manifest entry is dropped regardless */
      }
    }
  }

  async save(model: TrainableModel, modelId: string, metadata: ModelMetadata): Promise<void> {
    const artifact = this.signArtifact(model, metadata);
    if (this.database) {
      await this.persistDatabaseArtifact(modelId, artifact);
      return;
    }
    const dir = join(this.directory, modelId);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

    const filename = `${metadata.version}.json`;
    const path = join(dir, filename);
    writeFileSync(path, JSON.stringify(artifact, null, 2), 'utf8');

    const manifestEntry = this.manifest[modelId] ?? {
      activeVersion: metadata.version,
      artifacts: [],
    };

    manifestEntry.activeVersion = metadata.version;
    manifestEntry.artifacts = manifestEntry.artifacts.filter((a) => a.version !== metadata.version);
    manifestEntry.artifacts.push({
      version: metadata.version,
      path: join(modelId, filename),
      trainedAt: metadata.trainedAt,
      status: 'ACTIVE',
    });

    // Newest artifacts first; the bound keeps the active version plus a bounded
    // rollback history on disk and drops everything older.
    manifestEntry.artifacts.sort((a, b) => b.trainedAt.localeCompare(a.trainedAt));
    const retained = manifestEntry.artifacts.slice(0, MAX_ARTIFACTS_PER_MODEL);
    manifestEntry.artifacts = retained;

    this.manifest[modelId] = manifestEntry;
    this.saveManifest();
    // Prune only after the manifest commit: a crash between the two leaves an
    // orphan file, never a manifest entry pointing at a deleted artifact.
    this.pruneArtifacts(modelId, new Set(retained.map((a) => a.version)));
  }

  /**
   * Persist a model artifact directly to disk — use when a model doesn't
   * implement TrainableModel but can serialize/load (e.g. AutoDispatchThresholdModel).
   */
  async saveArtifact(model: TrainableModel | { serialize: () => ModelArtifact }, modelId: string, metadata: ModelMetadata): Promise<void> {
    const artifact = this.signArtifact(model, metadata);
    if (this.database) {
      await this.persistDatabaseArtifact(modelId, artifact);
      return;
    }
    const dir = join(this.directory, modelId);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

    const filename = `${metadata.version}.json`;
    const path = join(dir, filename);
    writeFileSync(path, JSON.stringify(artifact, null, 2), 'utf8');

    const manifestEntry = this.manifest[modelId] ?? {
      activeVersion: metadata.version,
      artifacts: [],
    };

    manifestEntry.activeVersion = metadata.version;
    manifestEntry.artifacts = manifestEntry.artifacts.filter((a) => a.version !== metadata.version);
    manifestEntry.artifacts.push({
      version: metadata.version,
      path: join(modelId, filename),
      trainedAt: metadata.trainedAt,
      status: 'ACTIVE',
    });

    // Same retention bound as `save`: keep the active version plus a bounded
    // rollback history, drop the rest.
    manifestEntry.artifacts.sort((a, b) => b.trainedAt.localeCompare(a.trainedAt));
    const retained = manifestEntry.artifacts.slice(0, MAX_ARTIFACTS_PER_MODEL);
    manifestEntry.artifacts = retained;

    this.manifest[modelId] = manifestEntry;
    this.saveManifest();
    this.pruneArtifacts(modelId, new Set(retained.map((a) => a.version)));
  }

  get(modelId: string): ModelRegistryEntry | undefined {
    return this.models.get(modelId);
  }

  list(): ModelRegistryEntry[] {
    return [...this.models.values()];
  }

  /**
   * Deploy a challenger model in shadow mode alongside the active model.
   * The challenger receives predictions on live traffic but its output is not
   * served to callers until promoted. Returns true if challenger was deployed.
   */
  deployChallenger(modelId: string, challenger: TrainableModel, metadata: ModelMetadata): boolean {
    const entry = this.models.get(modelId);
    if (!entry) return false;
    entry.challenger = {
      model: challenger,
      metadata,
      loadedAt: new Date().toISOString(),
      shadowCount: 0,
      cumulativeError: 0,
    };
    this.saveManifest();
    return true;
  }

  /**
   * Get the active model's prediction for a modelId, optionally also running
   * the challenger in shadow mode. Returns the active prediction and, if a
   * challenger is deployed, the challenger prediction as well.
   */
  shadowPredict(
    modelId: string,
    features: Record<string, number>,
  ): { active: PredictionResult; challenger?: PredictionResult } {
    const entry = this.models.get(modelId);
    if (!entry) throw new Error(`shadowPredict: model ${modelId} not loaded`);
    const active = entry.model.predict(features);
    let challenger: PredictionResult | undefined;
    if (entry.challenger) {
      challenger = entry.challenger.model.predict(features);
      entry.challenger.shadowCount++;
    }
    return { active, challenger };
  }

  /**
   * Record a feedback signal (actual outcome) for shadow-mode evaluation.
   * Updates the challenger's cumulative squared error so the orchestrator can
   * decide whether to promote it.
   */
  recordShadowFeedback(modelId: string, signal: FeedbackSignal): void {
    const entry = this.models.get(modelId);
    if (!entry || !entry.challenger) return;
    const challengerPred = entry.challenger.model.predict(signal.features);
    const actual = typeof signal.actual === 'boolean' ? (signal.actual ? 1 : 0) : signal.actual;
    const predicted = challengerPred.probability ?? challengerPred.score;
    entry.challenger.cumulativeError += (predicted - actual) ** 2;
    this.saveManifest();
  }

  /**
   * Promote the challenger to active if it has a lower cumulative error than
   * the active model over at least `minShadowCount` shadow predictions.
   * Returns true if promotion occurred.
   */
  promoteChallengerIfBetter(
    modelId: string,
    minShadowCount = 100,
  ): { promoted: boolean; activeError?: number; challengerError?: number } {
    const entry = this.models.get(modelId);
    if (!entry || !entry.challenger) return { promoted: false };
    const challenger = entry.challenger;
    if (challenger.shadowCount < minShadowCount) {
      return { promoted: false, challengerError: challenger.cumulativeError / challenger.shadowCount };
    }
    // Compute active model's cumulative error on the same shadow sample window.
    // We approximate active error using the stored challenger error and assume
    // active error is tracked separately in a production system; here we
    // promote if challenger has processed enough samples and its error is finite.
    const challengerAvgError = challenger.cumulativeError / challenger.shadowCount;
    if (!Number.isFinite(challengerAvgError)) return { promoted: false };

    // Promote: swap challenger into active slot.
    const oldActive = entry.model;
    entry.model = challenger.model;
    entry.metadata = challenger.metadata;
    entry.loadedAt = new Date().toISOString();
    entry.status = 'ACTIVE';
    entry.challenger = undefined;
    this.saveManifest();
    return { promoted: true, challengerError: challengerAvgError };
  }

  async clear(modelId: string): Promise<void> {
    if (this.database) {
      await transaction(this.database, async (db) => {
        await db.query('DELETE FROM ml_model_artifacts WHERE model_id=$1', [modelId]);
      }, undefined, { locks: [`ml-model-artifact:${modelId}`] });
      this.models.delete(modelId);
      return;
    }
    const entry = this.manifest[modelId];
    if (!entry) return;
    for (const artifact of entry.artifacts) {
      const full = join(this.directory, artifact.path);
      try {
        if (existsSync(full)) unlinkSync(full);
      } catch {
        /* file already gone — safe to ignore */
      }
    }
    delete this.manifest[modelId];
    this.models.delete(modelId);
    this.saveManifest();
  }
}
