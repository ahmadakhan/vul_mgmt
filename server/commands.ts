import { productWildcardCpe } from '../src/utils/registrationCpe.ts';
import { commandAudit } from './audit.ts';
import { findDuplicateFeedSource, feedSourceKey } from './feedIdentity.ts';
import { watchlistIdentity, watchlistDuplicateErrors } from '../shared/watchlistIdentity.ts';
import { syncCorrelationAsset } from './correlation/inventory.ts';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Db } from './db.ts';
import { get, getForUpdate, list, put, remove, appendAudit, schemaLockKey } from './db.ts';
import { transaction } from './db.ts';
import { encryptionKeys } from './secrets.ts';
import type pg from 'pg';

/**
 * Acquire a transaction-scoped advisory lock, waiting for contention.
 *
 * Session-scoped `pg_try_advisory_lock` would NOT serialize two transactions on
 * the same pool: PostgreSQL re-enters an advisory lock held by the same session,
 * so the second writer self-grants and both pass the uniqueness check. The
 * transaction-scoped form actually blocks the contender until the holder commits
 * or rolls back — and because it is owned by the transaction, PostgreSQL
 * releases it on COMMIT, ROLLBACK and connection failure alike, with no
 * per-path unlock to forget.
 *
 * The statement timeout bounds the wait: a caller stalled behind a stuck
 * transaction fails as contention (55P03/57014) rather than hanging the client
 * indefinitely, which is the correct outcome for an operator-facing command.
 */
const acquireAdvisoryLock = async (db: Db, lockName: string): Promise<boolean> => {
  try {
    return (
      (
        await db.query<{ locked: boolean }>(
          `SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey}) AS locked`,
          [lockName],
        )
      ).rows.length > 0
    );
  } catch (error) {
    // Not inside a transaction: fail closed. Opening a private transaction
    // here acquired the lock and COMMITTED it immediately, so the lock was
    // released before the caller did any work — while reporting success. The
    // caller must hold the lock for the whole mutation, so there is no safe
    // fallback; report the contention instead of pretending to serialize.
    console.warn(JSON.stringify({
      level: 'warn',
      event: 'advisory-lock-acquisition-failed',
      lockName,
      error: (error as Error).message,
      code: (error as any).code,
      timestamp: new Date().toISOString(),
    }));
    return false;
  }
};
import {
  feedSchema,
  feedImportSchema,
  assetSchema,
  watchlistImportSchema,
  recipientSchema,
  webhookSchema,
  cveSchema,
  aliasSchema,
  settingsSchema,
  templateSchema,
  HttpError,
} from './validation.ts';
import { encrypt, randomToken } from './secrets.ts';
import { DEFAULT_SETTINGS, DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { emailConfigSchema } from './validation.ts';
import { emailEndpoint } from './emailProviders.ts';
import {
  compileCustomizedTemplate,
  compileDailyDigestTemplate,
  DEFAULT_TEMPLATE_CUSTOMIZATION,
} from '../src/utils/templateCompiler.ts';
import type { Config } from './config';
import {
  isSmtpEmailProvider,
  type AliasEntry,
  type AppSettings,
  type Finding,
  type EmailConfiguration,
  type WatchListItem,
} from '../src/types/index.ts';

export interface CommandRequest {
  action: string;
  id?: string;
  data?: unknown;
  actor: string;
  ipAddress?: string;
}

export interface CommandResult {
  success: boolean;
  imported?: number;
  errors?: string[];
  assetId?: string;
  recipientId?: string;
  webhookId?: string;
  cveId?: string;
  action?: string;
}

/**
 * Commands that may only be executed by an ADMIN.
 *
 * This set is co-located with the dispatcher below on purpose: the previous
 * authorization list lived in the HTTP route while the actions lived here, so
 * a newly added action defaulted to OPERATOR-level access until someone
 * remembered to extend the list in another file. Any handler branch added to
 * `applyCommand` must either appear in this set or be deliberately left out,
 * and the fail-closed role check plus the classification test below make an
 * omission loud instead of silent.
 */
export const ADMIN_COMMAND_ACTIONS: ReadonlySet<string> = new Set([
  'feed.save',
  'feed.import',
  'feed.delete',
  'feed.toggle',
  'recipient.save',
  'recipient.delete',
  'recipient.toggle',
  'webhook.save',
  'webhook.delete',
  'webhook.toggle',
  'settings.save',
  'template.save',
  'dailyDigestTemplate.save',
  'email.configure',
  'alias.save',
  'alias.delete',
  'alias.promote',
  'alias.revoke',
]);

/**
 * Actions any authenticated role may execute. Declared above assertCommandRole
 * so the authorization rule reads top-down; the fail-closed check relies on
 * this set to distinguish a known operator action from a typo or an
 * unclassified future command (which must be rejected, not authorized by
 * default).
 */
export const OPERATOR_COMMAND_ACTIONS: ReadonlySet<string> = new Set([
  'asset.save',
  'asset.import',
  'watchlist.import',
  'cve.save',
  'finding.status',
  'finding.delete',
  'asset.delete',
  'asset.toggle',
]);

/**
 * Commands whose handler parses `data` as a record body. The dispatcher rejects
 * a missing or empty payload for these before touching the database; every
 * other action is id-driven (delete/toggle) or carries its payload in a
 * dedicated field and must accept an absent `data`.
 */
const ACTION_REQUIRES_DATA =
  /^(feed|asset|recipient|webhook|cve|alias|template|dailyDigestTemplate)\.save$|^(alias|watchlist|asset|feed)\.import$|^(settings|email)\.(save|configure)$|^finding\.status$/;

/**
 * Fail closed: an action that is not recognised at all is rejected here before
 * the dispatcher sees it, so an unclassified future action cannot inherit an
 * implicit OPERATOR authorization through omission. Every ADMIN-only action
 * requires the ADMIN role; the remaining operator actions accept any
 * authenticated role.
 *
 * Callers: the HTTP route (server/app.ts) passes the authenticated operator's
 * role. Internal server-side callers (scripts/seed.ts) invoke applyCommand
 * directly and deliberately skip this check — there is no HTTP role context to
 * enforce, and the seeding path is itself an operator action.
 */
export function assertCommandRole(action: string, role: string | undefined): void {
  if (!ADMIN_COMMAND_ACTIONS.has(action)) {
    if (!OPERATOR_COMMAND_ACTIONS.has(action)) throw new HttpError(400, 'Unknown command');
    return;
  }
  if (role !== 'ADMIN') throw new HttpError(403, 'Administrator role required');
}

function assertSpecificInventoryCpes(cpes: string[]) {
  if (cpes.some((cpe) => !productWildcardCpe(cpe)))
    throw new HttpError(
      400,
      'CPEs must have a specific part, vendor, and product. Wildcards are permitted for versions and platforms.',
    );
}

/**
 * The single write path for operator mutations. Every caller — the HTTP command
 * route and the seeding script — goes through here, so validation and encryption
 * cannot be bypassed by a second code path.
 */
export async function applyCommand(db: Db, config: Config, request: CommandRequest): Promise<CommandResult> {
  const { action, id, data, actor, ipAddress = '' } = request;
  // Reject null/empty payloads for actions that consume a record body before
  // any DB operations. Delete/toggle and other id-driven actions carry no
  // payload by design, so a global check would reject them with a 400.
  if (ACTION_REQUIRES_DATA.test(action)) {
    if (data === null || data === undefined) {
      throw new HttpError(400, 'Record data required');
    }
    if (typeof data === 'object' && !Array.isArray(data) && Object.keys(data as object).length === 0) {
      throw new HttpError(400, 'Record data required');
    }
  }
  const now = new Date().toISOString(),
    newId = id || randomUUID();
  const checkExisting = async (kind: string) => {
    const previous = await getForUpdate<any>(db, kind, newId);
    if (id && !previous) throw new HttpError(404, 'Record not found');
    return previous;
  };
  if (action === 'feed.save') {
    const input = feedSchema.parse(data);
    if (!(await acquireAdvisoryLock(db, 'feed-source'))) {
      throw new HttpError(423, 'Resource temporarily unavailable - retry later');
    }
    const old = await checkExisting('feeds');
    const duplicate = findDuplicateFeedSource({ id: newId, url: input.url }, await list<any>(db, 'feeds'));
    if (duplicate) throw new HttpError(409, 'A feed with this endpoint already exists');
    const sameSource =
      old?.url === input.url &&
      old?.type === input.type &&
      old?.authType === input.authType &&
      !input.authSecretKey;
    await put(db, 'feeds', newId, {
      ...old,
      ...input,
      id: newId,
      authSecretKey:
        input.authType === 'NONE'
          ? ''
          : input.authSecretKey
            ? encrypt(input.authSecretKey, encryptionKeys(config), `feed:${newId}`)
            : (sameSource ? old?.authSecretKey : '') || '',
      healthStatus: 'UNTESTED',
      lastSync: sameSource ? old?.lastSync || null : null,
      latencyMs: 0,
      itemCountLastRun: sameSource ? old?.itemCountLastRun || 0 : 0,
      ssrfValidated: false,
      etag: sameSource ? old?.etag : undefined,
      consecutiveFailures: sameSource ? old?.consecutiveFailures : 0,
      circuitOpenUntil: sameSource ? old?.circuitOpenUntil : null,
    });
  } else if (action === 'feed.import') {
    const input = feedImportSchema.parse(data);
    if (!(await acquireAdvisoryLock(db, 'feed-source'))) {
      throw new HttpError(423, 'Resource temporarily unavailable - retry later');
    }
    const incomingIds = new Set<string>();
    const sourceOwners = new Set<string>();
    const existing = (await list<any>(db, 'feeds')).filter((feed) => !input.some((item) => item.id === feed.id));
    for (const feed of existing) {
      sourceOwners.add(feedSourceKey(feed.url));
    }
    for (const feed of input) {
      if (incomingIds.has(feed.id)) throw new HttpError(409, 'Feed import contains duplicate feed IDs');
      incomingIds.add(feed.id);
      const key = feedSourceKey(feed.url);
      if (sourceOwners.has(key)) throw new HttpError(409, 'Feed import contains a duplicate endpoint');
      sourceOwners.add(key);
    }
    for (const feed of input) {
      const old = await getForUpdate<any>(db, 'feeds', feed.id);
      const sameSource =
        old?.url === feed.url &&
        old?.type === feed.type &&
        old?.authType === feed.authType &&
        !feed.authSecretKey;
      await put(db, 'feeds', feed.id, {
        ...old,
        ...feed,
        id: feed.id,
        authSecretKey:
          feed.authType === 'NONE'
            ? ''
            : feed.authSecretKey
              ? encrypt(feed.authSecretKey, encryptionKeys(config), `feed:${feed.id}`)
              : (sameSource ? old?.authSecretKey : '') || '',
        healthStatus: 'UNTESTED',
        lastSync: sameSource ? (old?.lastSync ?? null) : null,
        latencyMs: 0,
        itemCountLastRun: sameSource ? (old?.itemCountLastRun ?? 0) : 0,
        ssrfValidated: false,
        vendorSeed: feed.vendorSeed ?? old?.vendorSeed ?? false,
        etag: sameSource ? old?.etag : undefined,
        consecutiveFailures: sameSource ? (old?.consecutiveFailures ?? 0) : 0,
        circuitOpenUntil: sameSource ? (old?.circuitOpenUntil ?? null) : null,
      });
    }
    await appendAudit(db, 'Feeds imported', `${input.length} feeds`, actor, 'FEED', 'INFO', ipAddress);
    return { success: true, imported: input.length, errors: [] };
  } else if (action === 'asset.save') {
    // ATOMIC: acquire the identity lock before validation so the
    // check-lock-act sequence cannot interleave with another writer.
    if (!(await acquireAdvisoryLock(db, 'watchlist-identity'))) {
      throw new HttpError(423, 'Resource temporarily unavailable - retry later');
    }
    
    try {
      // Validate within the lock context
      const input = assetSchema.parse(data);
      const old = await checkExisting('watchlist');
      assertSpecificInventoryCpes(input.cpes);
      const duplicates = watchlistDuplicateErrors([{ ...input, id: newId }], await list<any>(db, 'watchlist'));
      if (duplicates.length) throw new HttpError(409, duplicates.join(' '));
      const asset = { ...input, id: newId, createdAt: old?.createdAt || now };
      await put(db, 'watchlist', newId, asset);
      await syncCorrelationAsset(db, asset);
      
      // AUDIT LOG: Log successful asset save operation
      await appendAudit(db, 'Asset saved', `ID: ${newId}, assetTag: ${input.assetTag}`, actor, 'WATCHLIST', 'INFO', ipAddress);
      
      return { success: true, assetId: newId, action: 'asset.save' };
    } catch (error) {
      // AUDIT LOG: Log failed asset save operation
      const assetTag = (data as { assetTag?: unknown })?.assetTag;
      await appendAudit(db, 'Asset save failed', `Error: ${(error as Error).message}, assetTag: ${assetTag}`, actor, 'WATCHLIST', 'ERROR', ipAddress);
      throw error;
    }
  } else if (action === 'asset.import') {
    // ATOMIC: acquire the identity lock before validation so the
    // check-lock-act sequence is atomic.
    if (!(await acquireAdvisoryLock(db, 'watchlist-identity'))) {
      return { success: false, imported: 0, errors: ['Resource temporarily unavailable - retry later'] };
    }
    
    try {
      const input = z.array(assetSchema).min(1).max(1000).parse(data);
      input.forEach((item) => assertSpecificInventoryCpes(item.cpes));
      const identity = (item: z.infer<typeof assetSchema>) =>
        JSON.stringify([item.assetTag, watchlistIdentity(item)]);
      const inventory = await list<any>(db, 'watchlist');
      const existing = new Map(inventory.map((item) => [identity(item), item]));
      const unique = new Map(input.map((item) => [identity(item), item]));
      const duplicates = watchlistDuplicateErrors(
        [...unique].map(([key, item]) => ({ ...item, id: existing.get(key)?.id })),
        inventory,
      );
      if (duplicates.length) {
        await appendAudit(
          db,
          'Assets import validation failed',
          `${duplicates.length} duplicate assets found - IDs: ${duplicates.join(', ')}`,
          actor,
          'WATCHLIST',
          'WARNING',
          ipAddress,
        );
        return { success: false, imported: 0, errors: duplicates };
      }
      
      let imported = 0;
      const importErrors: string[] = [];
      for (const [key, item] of unique) {
        try {
          const old = existing.get(key),
            assetId = old?.id || randomUUID();
          const asset = { ...old, ...item, id: assetId, createdAt: old?.createdAt || now };
          await put(db, 'watchlist', assetId, asset);
          await syncCorrelationAsset(db, asset);
          imported++;
        } catch (error) {
          importErrors.push(`Failed to import assetTag ${item.assetTag}: ${(error as Error).message}`);
        }
      }
      
      if (importErrors.length > 0) {
        await appendAudit(
          db,
          'Assets import partially completed',
          `${imported} successful, ${importErrors.length} failures - Details: ${importErrors.join('; ')}`,
          actor,
          'WATCHLIST',
          'WARNING',
          ipAddress,
        );
      } else {
        await appendAudit(
          db,
          'Assets imported',
          `${unique.size} unique assets upserted successfully`,
          actor,
          'WATCHLIST',
          'INFO',
          ipAddress,
        );
      }
      
      return { success: importErrors.length === 0, imported, errors: importErrors.length > 0 ? importErrors : [] };
    } catch (error) {
      // The identity lock is transaction-scoped, so an escape from a failed
      // import does not leak it; only record the failure for the operator.
      await appendAudit(
        db,
        'Assets import failed',
        `Error: ${(error as Error).message}`,
        actor,
        'WATCHLIST',
        'ERROR',
        ipAddress,
      );
      throw error;
    }
  } else if (action === 'watchlist.import') {
    // ATOMIC: acquire the identity lock before validation so the
    // check-lock-act sequence is atomic.
    if (!(await acquireAdvisoryLock(db, 'watchlist-identity'))) {
      return { success: false, imported: 0, errors: ['Resource temporarily unavailable - retry later'] };
    }
    
    try {
      // Shape check before the advisory lock (see asset.save).
      if (!Array.isArray(data)) throw new HttpError(400, 'Expected an array of assets');
      // Pre-validate all rows before inserting any, collecting per-row errors with line numbers.
      const validItems: { id: string; [key: string]: unknown }[] = [];
      const rowErrors: string[] = [];
      for (let i = 0; i < data.length; i++) {
        const row = data[i];
        const rowNumber = i + 1;
        try {
          const validated = watchlistImportSchema.element.parse(row);
          assertSpecificInventoryCpes(validated.cpes);
          validItems.push(row as { id: string; [key: string]: unknown });
        } catch (e: any) {
          rowErrors.push(
            `Row ${rowNumber}: ${e instanceof z.ZodError ? e.issues.map((issue) => `${issue.path?.join('.') || 'root'}: ${issue.message}`).join('; ') : e.message}`,
          );
        }
      }
      if (rowErrors.length) {
        await appendAudit(
          db,
          'Watchlist import validation failed',
          `${rowErrors.length} row validation errors - First error: ${rowErrors[0]}...`,
          actor,
          'WATCHLIST',
          'WARNING',
          ipAddress,
        );
        return { success: false, imported: 0, errors: rowErrors };
      }
      
      const duplicateErrors = watchlistDuplicateErrors(
        validItems as unknown as WatchListItem[],
        await list<any>(db, 'watchlist'),
      );
      if (duplicateErrors.length) {
        await appendAudit(
          db,
          'Watchlist import validation failed',
          `${duplicateErrors.length} duplicate assets found - IDs: ${duplicateErrors.join(', ')}`,
          actor,
          'WATCHLIST',
          'WARNING',
          ipAddress,
        );
        return { success: false, imported: 0, errors: duplicateErrors };
      }
      
      let imported = 0;
      const importErrors: string[] = [];
      for (const item of validItems) {
        try {
          const old = await getForUpdate<any>(db, 'watchlist', item.id);
          const merged = {
            ...old,
            ...item,
            id: item.id,
            createdAt: item.createdAt || old?.createdAt || now,
            exposure: item.exposure ?? old?.exposure,
          };
          await put(db, 'watchlist', item.id, merged);
          await syncCorrelationAsset(db, merged as WatchListItem);
          imported++;
        } catch (error) {
          importErrors.push(`Failed to import watchlist item ${item.id}: ${(error as Error).message}`);
        }
      }
      
      if (importErrors.length > 0) {
        await appendAudit(
          db,
          'Watchlist import partially completed',
          `${imported} successful, ${importErrors.length} failures - Details: ${importErrors.join('; ')}`,
          actor,
          'WATCHLIST',
          'WARNING',
          ipAddress,
        );
      } else {
        await appendAudit(
          db,
          'Watchlist imported',
          `${validItems.length} assets imported successfully`,
          actor,
          'WATCHLIST',
          'INFO',
          ipAddress,
        );
      }
      
      return { success: importErrors.length === 0, imported, errors: importErrors.length > 0 ? importErrors : [] };
    } catch (error) {
      await appendAudit(
        db,
        'Watchlist import failed',
        `Error: ${(error as Error).message}`,
        actor,
        'WATCHLIST',
        'ERROR',
        ipAddress,
      );
      throw error;
    }
  } else if (action === 'alias.save') {
    const input = aliasSchema.parse(data),
      old = await checkExisting('aliases');
    await put(db, 'aliases', newId, {
      ...input,
      id: newId,
      createdAt: old?.createdAt || now,
      source: 'MANUAL',
    });
  } else if (action === 'alias.delete') {
    if (!id) throw new HttpError(400, 'Record ID required');
    if (!(await getForUpdate<any>(db, 'aliases', id))) throw new HttpError(404, 'Record not found');
    await remove(db, 'aliases', id);
  } else if (action === 'alias.promote') {
    // Promoting turns a learned relation into a permanent operator alias. It
    // keeps the row id but stops the automatic lifecycle from expiring it.
    if (!id) throw new HttpError(400, 'Record ID required');
    const row = await getForUpdate<AliasEntry>(db, 'aliases', id);
    if (!row) throw new HttpError(404, 'Record not found');
    if (row.source !== 'AUTO')
      throw new HttpError(400, 'Only an automatically learned alias can be promoted');
    await put(db, 'aliases', id, {
      ...row,
      source: 'MANUAL',
      provenance: 'OPERATOR',
      aliases: [...row.aliases].sort(),
      createdAt: row.createdAt || now,
      firstSeenAt: row.firstSeenAt || row.createdAt || now,
      lastSeenAt: now,
      expiresAt: undefined,
      revokedAliases: undefined,
      revokedAt: undefined,
      notes: row.notes
        ? `${row.notes} Promoted to a permanent operator alias.`
        : 'Promoted to a permanent operator alias.',
    });
    await appendAudit(
      db,
      'Alias promoted',
      `${row.scope} ${row.canonical} -> ${row.aliases.join(', ')}`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
    );
  } else if (action === 'alias.revoke') {
    // Revocation is a tombstone, not a deletion: the relation must not be
    // re-learned on the next pipeline run just because the same evidence is
    // still present. The pairs move to `revokedAliases`, which is never used
    // for matching.
    if (!id) throw new HttpError(400, 'Record ID required');
    const row = await getForUpdate<AliasEntry>(db, 'aliases', id);
    if (!row) throw new HttpError(404, 'Record not found');
    if (row.source !== 'AUTO') throw new HttpError(400, 'Only an automatically learned alias can be revoked');
    // The tombstone gets its own id so a *different* spelling of the same
    // canonical name can still be learned later. It carries the rejected pairs
    // in `revokedAliases`, which is never used for matching.
    await remove(db, 'aliases', id);
    await put(db, 'aliases', `revoked:${id}`, {
      ...row,
      id: `revoked:${id}`,
      source: 'REVOKED',
      provenance: undefined,
      aliases: [],
      revokedAliases: [...row.aliases].sort(),
      expiresAt: undefined,
      revokedAt: now,
      notes: 'Revoked by an operator. This naming relation will not be learned again automatically.',
    });
    await appendAudit(
      db,
      'Alias revoked',
      `${row.scope} ${row.canonical} -/-> ${row.aliases.join(', ')}`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
    );
  } else if (action === 'recipient.save') {
    // The uniqueness lock waits for contention (see acquireAdvisoryLock); by
    // the time it is granted the other writer has committed, so the duplicate
    // check below rejects with a 409 as the operator-facing outcome.
    if (!(await acquireAdvisoryLock(db, 'recipients-unique'))) {
      throw new HttpError(423, 'Resource temporarily unavailable - retry later');
    }
    
    try {
      const input = recipientSchema.parse(data);
      const old = await checkExisting('recipients');
      const exists = (await list<any>(db, 'recipients')).some((r) => r.email === input.email && r.id !== id);
      if (exists) {
        await appendAudit(
          db,
          'Recipient save validation failed',
          `Duplicate recipient: ${input.email}`,
          actor,
          'SECURITY',
          'WARNING',
          ipAddress,
        );
        throw new HttpError(409, 'Recipient already exists');
      }
      await put(db, 'recipients', newId, {
        ...input,
        id: newId,
        deliverySuccessRate: old?.deliverySuccessRate ?? 0,
      });
      
      await appendAudit(
        db,
        'Recipient saved',
        `ID: ${newId}, email: ${input.email}`,
        actor,
        'SECURITY',
        'INFO',
        ipAddress,
      );
      
      return { success: true, recipientId: newId };
    } catch (error) {
      await appendAudit(
        db,
        'Recipient save failed',
        `Error: ${(error as Error).message}, email: ${(data as any)?.email}`,
        actor,
        'SECURITY',
        'ERROR',
        ipAddress,
      );
      throw error;
    }
  } else if (action === 'webhook.save') {
    const input = webhookSchema.parse(data);
    const old = await checkExisting('webhooks');
    // Blank-keeps applies only when there is something to keep. A new Generic
    // HMAC endpoint (or a provider switched to GENERIC_HMAC) without a secret
    // would otherwise be stored unsigned and every delivery would fail at the
    // receiver while creation reported success.
    if (input.provider === 'GENERIC_HMAC' && !input.secretToken && !old?.secretToken)
      throw new HttpError(
        400,
        'Generic HMAC webhooks require a shared secret of at least 32 characters',
      );
    await put(db, 'webhooks', newId, {
      ...input,
      id: newId,
      url: encrypt(input.url, encryptionKeys(config), `webhook-url:${newId}`),
      // An edit with a blank secret keeps the stored credential. Rotating it
      // silently would break the receiver without an explicit operator action.
      secretToken: input.secretToken
        ? encrypt(input.secretToken, encryptionKeys(config), `webhook:${newId}`)
        : old?.secretToken || encrypt(randomToken(), encryptionKeys(config), `webhook:${newId}`),
      deliveryCount: old?.deliveryCount ?? 0,
    });
    
    await appendAudit(
      db,
      'Webhook saved',
      `ID: ${newId}, url: ${input.url}, hasSecret: ${!!input.secretToken}`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
    );
    
    return { success: true, webhookId: newId };
  } else if (action === 'cve.save') {
    const input = cveSchema.parse(data);
    const withdrawn = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', input.cveId);
    if (withdrawn && Date.parse(input.modifiedDate) <= Date.parse(withdrawn.modifiedDate))
      throw new HttpError(409, 'CVE revision has been withdrawn; a newer authoritative revision is required');
    await put(db, 'cveData', input.cveId, {
      ...input,
      vex: undefined,
      sourceFeeds: ['operator-import'],
    });
    
    await appendAudit(
      db,
      'CVE saved',
      `ID: ${input.cveId}, modifiedDate: ${input.modifiedDate}, publishedDate: ${input.publishedDate}`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
    );
    
    return { success: true, cveId: input.cveId };
  } else if (action === 'email.configure') {
    const input = emailConfigSchema.parse(data);
    const old = (await getForUpdate<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
    const smtpProvider = isSmtpEmailProvider(input.provider);
    // A stored credential is only reusable when it still belongs to the same
    // destination. Changing a custom API endpoint, SMTP host, or SMTP username
    // must require the operator to enter the secret again instead of silently
    // sending the previous credential to a different service or account.
    const sameApiDestination =
      old.provider === input.provider &&
      (input.provider !== 'API' ||
        (old.apiEndpoint === input.apiEndpoint && old.apiSourceDomain === input.apiSourceDomain));
    const sameSmtpIdentity =
      old.provider === input.provider &&
      old.smtpHost === input.smtpHost &&
      old.smtpUsername === input.smtpUsername;
    const apiKey = smtpProvider
      ? ''
      : input.apiKey
        ? encrypt(input.apiKey, encryptionKeys(config), `email-provider:${input.provider}`)
        : sameApiDestination
          ? old.apiKey
          : '';
    const smtpPassword =
      smtpProvider && (input.provider !== 'SMTP' || !!input.smtpHost)
        ? input.smtpPassword
          ? encrypt(input.smtpPassword, encryptionKeys(config), `email-smtp:${input.provider}`)
          : sameSmtpIdentity
            ? old.smtpPassword
            : ''
        : '';
    const mailjetApiSecret =
      input.provider === 'MAILJET_API' && input.mailjetApiSecret
        ? encrypt(input.mailjetApiSecret, encryptionKeys(config), `email-mailjet:${input.provider}`)
        : old.provider === input.provider
          ? old.mailjetApiSecret
          : '';
    if (!smtpProvider && !apiKey) throw new HttpError(400, 'Enter an API token for the selected provider');
    if (input.provider === 'MAILJET_API' && !input.mailjetApiSecret && !mailjetApiSecret)
      throw new HttpError(400, 'Enter your Mailjet API secret');
    if (smtpProvider && input.smtpHost) {
      const allowedHosts = config.EGRESS_ALLOWED_HOSTS.split(',').map((host) => host.trim().toLowerCase());
      if (!allowedHosts.includes(input.smtpHost.toLowerCase().trim()))
        throw new HttpError(
          400,
          `Add ${input.smtpHost} to EGRESS_ALLOWED_HOSTS before configuring this SMTP host`,
        );
      const presetRequiresAuth = input.provider !== 'SMTP_CUSTOM' && input.provider !== 'SMTP';
      if (presetRequiresAuth && (!input.smtpUsername || !smtpPassword))
        throw new HttpError(400, 'SMTP username and password or API secret are required');
      if (!presetRequiresAuth && Boolean(input.smtpUsername) !== Boolean(smtpPassword))
        throw new HttpError(400, 'Provide both SMTP username and password, or leave both blank');
    }
    const endpoint = emailEndpoint(input);
    if (
      endpoint &&
      !config.EGRESS_ALLOWED_HOSTS.split(',')
        .map((host) => host.trim().toLowerCase())
        .includes(new URL(endpoint).hostname)
    )
      throw new HttpError(
        400,
        `Allow ${new URL(endpoint).hostname} in EGRESS_ALLOWED_HOSTS before configuring this provider`,
      );
    await put(db, 'emailConfig', 'main', { ...input, apiKey, smtpPassword, mailjetApiSecret });
  } else if (action === 'settings.save') {
    // Validate the payload shape before touching the database. `{}` and `null`
    // both spread to nothing, so the previous order produced a no-op write that
    // still took the row lock and re-serialised the settings — and an empty
    // change is a client error, not a successful save. Requiring at least one
    // key also keeps the merge from silently accepting array/scalar payloads.
    const patch = z.record(z.string(), z.unknown()).parse(data);
    if (Object.keys(patch).length === 0) throw new HttpError(400, 'No settings were supplied');
    const old = (await getForUpdate<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    await put(db, 'settings', 'main', settingsSchema.parse({ ...old, ...patch }));
  } else if (action === 'template.save') {
    const input = z.object({
      templateCustomization: templateSchema,
      customAdvisoryTemplate: z.string().max(200_000).nullable().optional(),
    }).parse(data);
    const existing = (await getForUpdate<any>(db, 'template', 'main')) || {};
    const customAdvisoryTemplate = input.customAdvisoryTemplate === undefined
      ? existing.customAdvisoryTemplate ?? null
      : input.customAdvisoryTemplate?.trim()
        ? input.customAdvisoryTemplate
        : null;
    await put(db, 'template', 'main', {
      ...existing,
      templateCustomization: input.templateCustomization,
      customAdvisoryTemplate,
      advisoryTemplate: customAdvisoryTemplate || compileCustomizedTemplate(input.templateCustomization),
    });
  } else if (action === 'dailyDigestTemplate.save') {
    const input = z
      .object({
        dailyDigestCustomization: templateSchema,
        dailyDigestCustomTemplate: z.string().nullish(),
      })
      .parse(data);
    const existing = (await getForUpdate<any>(db, 'template', 'main')) || {};
    await put(db, 'template', 'main', {
      ...existing,
      dailyDigestCustomization: input.dailyDigestCustomization,
      dailyDigestCustomTemplate: input.dailyDigestCustomTemplate ?? null,
      dailyDigestTemplate:
        input.dailyDigestCustomTemplate || compileDailyDigestTemplate(input.dailyDigestCustomization),
    });
  } else if (action === 'finding.status') {
    const input = z
      .object({
        status: z.enum(['MONITORED', 'REMEDIATION_AVAILABLE', 'PATCH_APPLIED', 'RESOLVED', 'FALSE_POSITIVE']),
        note: z.string().max(2000).optional(),
      })
      .parse(data);
    const f = await getForUpdate<Finding>(db, 'findings', newId);
    if (!f) throw new HttpError(404, 'Finding not found');
    await put(db, 'findings', newId, {
      ...f,
      status: input.status,
      timeline: [
        ...(f.timeline ?? []),
        { timestamp: now, action: input.status, system: actor, details: input.note || '' },
      ],
    });
  } else if (action === 'finding.delete') {
    if (!id) throw new HttpError(400, 'Record ID required');
    const old = await getForUpdate<any>(db, 'findings', id);
    if (!old) throw new HttpError(404, 'Finding not found');
    await remove(db, 'findings', id);
    // A deleted finding may have been referenced by an open advisory; clear
    // the link so the advisory does not resurrect the record on its next write.
    await db.query(
      "UPDATE records SET data = jsonb_set(data, '{findingIds}', (data->'findingIds') - $1::text) WHERE kind='advisories' AND data ? 'findingIds'",
      [id],
    );
  } else if (/^(feed|asset|recipient|webhook)\.(delete|toggle)$/.test(action)) {
    const [entity, operation] = action.split('.'),
      kind = (
        { feed: 'feeds', asset: 'watchlist', recipient: 'recipients', webhook: 'webhooks' } as Record<
          string,
          string
        >
      )[entity];
    if (!id) throw new HttpError(400, 'Record ID required');
    const old = await getForUpdate<any>(db, kind, id);
    if (!old) throw new HttpError(404, 'Record not found');
    if (entity === 'feed' && operation === 'delete' && (old.vendorSeed || old.type === 'NVD_API'))
      throw new HttpError(403, 'Vendor-seeded feeds and NVD sources cannot be deleted');
    if (entity === 'asset')
      await syncCorrelationAsset(db, { ...old, active: operation === 'delete' ? false : !old.active });
    if (operation === 'delete') {
      await remove(db, kind, id);
      // Source checkpoints are internal state keyed by feed id; deleting the
      // feed must not leave a stale cursor/snapshot that a later feed with the
      // same id could accidentally resume from.
      if (entity === 'feed') {
        await remove(db, 'feedCursors', id);
        await remove(db, 'feedSnapshots', id);
      }
    } else
      await put(db, kind, id, {
        ...old,
        [entity === 'asset' ? 'active' : 'enabled']: !old[entity === 'asset' ? 'active' : 'enabled'],
      });
  } else throw new HttpError(400, 'Unknown command');
  const audit = commandAudit(action, ['settings', 'email', 'template', 'dailyDigestTemplate'].includes(action.split('.')[0]) ? 'main' : id || newId, data);
  await appendAudit(
    db,
    audit.event,
    audit.details,
    actor,
    audit.category,
    'INFO',
    ipAddress,
    audit.context,
  );
  return { success: true };
}
