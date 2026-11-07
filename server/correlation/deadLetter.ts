import { timedQuery } from './query.ts';
import { mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { z } from 'zod';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { encrypt, decrypt, encryptionKeys } from '../secrets.ts';
import type { CorrelationTelemetry } from './telemetry.ts';
import { boundedJson } from './boundedJson.ts';
import { lock } from 'proper-lockfile';
interface Letter {
  id: string;
  trackingId: string;
  errorCode: string;
  encryptedPayload: string;
}
const spoolEntryCount = (names: string[]) =>
  names.filter((name) => !/^[a-f0-9-]{36}\.json\.lock$/.test(name)).length;
const letterSchema = z
  .object({
    id: z.uuid(),
    trackingId: z.uuid(),
    errorCode: z.string().regex(/^[A-Z0-9_]{1,100}$/),
    encryptedPayload: z.string().max(360000),
  })
  .strict();
/** Durable encrypted fallback, with a strict disk ceiling. A full spool fails closed. */
export class DeadLetterQueue {
  private tail: Promise<unknown> = Promise.resolve();
  private readonly corruptFiles = new Set<string>();
  constructor(
    private readonly directory: string,
    private readonly keys: string[],
    private readonly telemetry: CorrelationTelemetry,
    private readonly databaseOnly = false,
  ) {
    if (!keys.length || keys.some((key) => Buffer.from(key, 'base64').length !== 32))
      throw new Error('DLQ_KEY_REQUIRED');
  }
  /**
   * Persist a failed advisory. Returns the durability outcome instead of
   * throwing when the spool is full: the spool is the *last* resort, so a full
   * spool must hand the record back to the caller for the database path rather
   * than discard the very data it exists to protect.
   *
   * Encryption happens before any I/O, so even the capacity-rejected payload is
   * already ciphertext in memory and never reaches disk or a log in the clear.
   */
  async capture(
    raw: unknown,
    errorCode: string,
    trackingId: string,
    pool: Pool,
  ): Promise<'SPOOLED' | 'DATABASE' | 'capacity' | 'unavailable'> {
    // JSON inputs from HTTP/NDJSON are bounded upstream. Never serialize arbitrary
    // class instances, cycles, or unlimited object-mode inputs into the fallback.
    const serialized = boundedJson(raw) ?? '"[unsafe or oversized input omitted]"';
    const letter: Letter = {
      id: randomUUID(),
      trackingId,
      errorCode,
      encryptedPayload: encrypt(serialized, this.keys, 'correlation-dlq'),
    };
    if (this.databaseOnly) {
      try {
        await pool.query(
          timedQuery(
            `INSERT INTO correlation_dead_letters(id,tracking_id,error_code,encrypted_payload)
             VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING`,
            [letter.id, letter.trackingId, letter.errorCode, letter.encryptedPayload],
            2000,
          ),
        );
        this.telemetry.deadLetters++;
        this.telemetry.log('WARN', 'dead_letter.persisted_database', { trackingId });
        return 'DATABASE';
      } catch {
        this.telemetry.log('CRITICAL', 'dead_letter.database_unavailable', { trackingId });
        return 'unavailable';
      }
    }
    const persist = async (): Promise<'SPOOLED' | 'capacity'> => {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      const files = await readdir(this.directory);
      // Each serialized letter is <= 351 KiB. 256 files cap disk at ~90 MiB.
      if (spoolEntryCount(files) >= 256) return 'capacity';
      const temporary = join(this.directory, letter.id + '.tmp');
      const file = await open(temporary, 'wx', 0o600);
      try {
        await file.writeFile(JSON.stringify(letter));
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(temporary, join(this.directory, letter.id + '.json'));
      try {
        // Flush the rename to stable storage by syncing the directory handle.
        // On Windows (and any filesystem where a directory cannot be fsynced) the
        // sync fails with EPERM, which would fail the whole spool write even
        // though the letter itself was already flushed by file.sync() above. The
        // directory flush is a durability nicety — the .tmp -> .json rename is
        // already visible to readdir, and a crashed rename is recovered by the
        // flush path's strict filename filter (a leftover .tmp is never matched).
        // So a failure to sync the directory must not lose the letter.
        const dir = await open(this.directory, 'r');
        try {
          await dir.sync();
        } finally {
          await dir.close();
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException)?.code !== 'EPERM') throw error;
      }
      this.telemetry.deadLetters++;
      // The saturation gauge is refreshed opportunistically on every spool
      // write, so the alert fires from the existing metrics endpoint without a
      // new scrape path. It is a count of one bounded directory, so a readdir
      // here stays cheap.
      try {
        this.telemetry.deadLetterSpoolFiles = spoolEntryCount(await readdir(this.directory));
      } catch {
        // A vanished directory is reported by the next write's mkdir.
      }
      return 'SPOOLED' as const;
    };
    const pending = this.tail.then(persist);
    this.tail = pending.catch(() => {});
    const outcome = await pending;
    if (outcome === 'capacity') {
      this.telemetry.log('CRITICAL', 'dead_letter.spool_exhausted', { trackingId });
      return outcome;
    }
    this.telemetry.log('WARN', 'dead_letter.persisted', { trackingId });
    // Flush is handled by the supervisor; never wait for an unavailable DB here.
    void pool;
    return outcome;
  }

  /**
   * Last-resort database persistence, used when the spool is full. This is the
   * only path that keeps an advisory durable when the failure being recorded is
   * itself a database failure, so it is attempted at most once with a short
   * timeout and never blocks the caller.
   */
  async captureToDatabase(raw: unknown, errorCode: string, trackingId: string, pool: Pool): Promise<boolean> {
    const serialized = boundedJson(raw) ?? '"[unsafe or oversized input omitted]"';
    try {
      await pool.query(
        timedQuery(
          `INSERT INTO correlation_dead_letters(id,tracking_id,error_code,encrypted_payload)
           VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING`,
          [randomUUID(), trackingId, errorCode, encrypt(serialized, this.keys, 'correlation-dlq')],
          2000,
        ),
      );
      this.telemetry.deadLetters++;
      this.telemetry.log('WARN', 'dead_letter.persisted_database', { trackingId });
      return true;
    } catch {
      return false;
    }
  }
  async flush(pool: Pool): Promise<number> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const files = (await readdir(this.directory))
      .filter((file) => /^[a-f0-9-]{36}\.json$/.test(file))
      .slice(0, 256);
    let flushed = 0;
    for (const name of files) {
      if (flushed >= 10) break;
      const filename = join(this.directory, name);
      let compromised = false;
      let release: () => Promise<void>;
      try {
        release = await lock(filename, {
          realpath: false,
          retries: 0,
          stale: 30000,
          update: 10000,
          onCompromised: () => {
            compromised = true;
            this.telemetry.log('CRITICAL', 'dead_letter.spool_lease_lost');
          },
        });
      } catch (error) {
        if (['ELOCKED', 'ENOENT'].includes((error as NodeJS.ErrnoException)?.code ?? '')) continue;
        throw error;
      }
      try {
        let letter: Letter;
        try {
          const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
          try {
            const stat = await file.stat();
            if (!stat.isFile() || stat.size > 360000) throw new Error('INVALID_SPOOL_FILE');
            // Bounded read even if a file is enlarged after stat().
            const buffer = Buffer.allocUnsafe(360001);
            let bytes = 0;
            while (bytes < buffer.length) {
              const read = await file.read(buffer, bytes, buffer.length - bytes, bytes);
              if (!read.bytesRead) break;
              bytes += read.bytesRead;
            }
            if (bytes > 360000) throw new Error('INVALID_SPOOL_FILE');
            letter = letterSchema.parse(JSON.parse(buffer.subarray(0, bytes).toString('utf8')));
            if (name !== letter.id + '.json') throw new Error('SPOOL_IDENTITY_MISMATCH');
            decrypt(letter.encryptedPayload, this.keys, 'correlation-dlq');
          } finally {
            await file.close();
          }
        } catch (error) {
          if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') continue;
          if (!this.corruptFiles.has(name)) {
            if (this.corruptFiles.size >= 256) this.corruptFiles.clear();
            this.corruptFiles.add(name);
            this.telemetry.log('CRITICAL', 'dead_letter.corrupt_spool');
          }
          // Preserve evidence for repair; a poison file must not starve valid letters.
          continue;
        }
        if (compromised) throw new Error('SPOOL_LEASE_LOST');
        await pool.query(
          timedQuery(
            `INSERT INTO correlation_dead_letters(id,tracking_id,error_code,encrypted_payload)
        VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING`,
            [letter.id, letter.trackingId, letter.errorCode, letter.encryptedPayload],
            2000,
          ),
        );
        if (compromised) throw new Error('SPOOL_LEASE_LOST');
        await unlink(filename).catch((error) => {
          if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'ENOENT')
            throw error;
        });
        this.corruptFiles.delete(name);
        flushed++;
      } finally {
        await release().catch((error) => {
          if (!compromised) throw error;
        });
      }
    }
    this.telemetry.deadLetterSpoolFiles = spoolEntryCount(await readdir(this.directory));
    return flushed;
  }
}
