import { sha256 as digest } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import type { AuditLog } from '../types';
import { stableJson } from './deduplicator.ts';

/** Synchronous SHA-256 for browser state updates. */
export function quickHash(input: string): string {
  return bytesToHex(digest(utf8ToBytes(input)));
}

export async function sha256(message: string): Promise<string> {
  return quickHash(message);
}

export function generateHmacSignature(payload: string, secret: string): string {
  return `sha256=${bytesToHex(hmac(digest, utf8ToBytes(secret), utf8ToBytes(payload)))}`;
}

export function hashAuditLog(log: AuditLog): string {
  return quickHash(
    stableJson([
      log.prevHash,
      log.id,
      log.timestamp,
      log.category,
      log.level,
      log.event,
      log.details,
      log.actor,
      log.ipAddress,
      ...(log.context === undefined ? [] : [log.context]),
    ]),
  );
}

/** Input and output are newest-first; use only when adding newly created logs. */
export function chainAuditLogs(logs: AuditLog[], previousHash = '0'.repeat(64)): AuditLog[] {
  return [...logs]
    .reverse()
    .map((log) => {
      const entry = { ...log, prevHash: previousHash };
      entry.hash = hashAuditLog(entry);
      previousHash = entry.hash;
      return entry;
    })
    .reverse();
}

/** Checks retained content and links. An external trusted anchor is still required
 * to detect replacement of the entire chain or deletion of its newest entries. */
export function verifyAuditChain(logs: AuditLog[]): boolean {
  return logs.every(
    (log, i) =>
      /^[a-f0-9]{64}$/.test(log.hash) &&
      log.hash === hashAuditLog(log) &&
      (i === logs.length - 1 || log.prevHash === logs[i + 1].hash),
  );
}

/** Compute a Merkle root hash over a sorted list of audit log hashes.
 *
 * This root can be periodically written to an external write-once store
 * (S3 object lock, cloud logging) so that the full chain content is
 * anchored outside the local database, making wholesale replacement
 * or deletion of the audit chain detectable.
 */
export function merkleRoot(hashes: string[]): string {
  if (!hashes.length) return '0'.repeat(64);
  let level: string[] = [...hashes].sort();
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(quickHash(left + right));
    }
    level = next;
  }
  return level[0];
}

export class SortedMerkleAccumulator {
  private readonly levels: (string | undefined)[] = [];

  add(hash: string): void {
    let node = hash;
    let height = 0;
    while (this.levels[height] !== undefined) {
      node = quickHash(this.levels[height]! + node);
      this.levels[height] = undefined;
      height++;
    }
    this.levels[height] = node;
  }

  root(): string {
    let node: string | undefined;
    let height = 0;
    for (let level = 0; level < this.levels.length; level++) {
      const left = this.levels[level];
      if (left === undefined) continue;
      if (node === undefined) {
        node = left;
        height = level;
        continue;
      }
      while (height < level) {
        node = quickHash(node + node);
        height++;
      }
      node = quickHash(left + node);
      height++;
    }
    return node ?? '0'.repeat(64);
  }
}
