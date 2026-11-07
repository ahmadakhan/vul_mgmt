/**
 * Deterministic PRNG (Mulberry32) — used for reproducible training across
 * all ML algorithms. Replaces Math.random() to ensure model training is
 * deterministic given the same seed, enabling reproducible builds and
 * reliable CI/CD pipelines.
 */
export function createRng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 6 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Default seed for deterministic training — stable across runs. */
export const DEFAULT_TRAINING_SEED = 42;
