import { createHash } from 'node:crypto';
import type pg from 'pg';
import type {
  EmailRecipient,
  IntelligenceArticle,
  IntelligenceMatch,
} from '../src/types/index.ts';
import type { Db } from './db.ts';
import { get, list, put, transaction } from './db.ts';
import { writeEvent } from './events.ts';
import { stableJson } from '../src/utils/deduplicator.ts';
import {
  consolidateNewsMatches,
  newsArticleIdentity,
  newsNotifiedKey,
  renderConsolidatedNewsEmailWithin,
  selectUnnotifiedArticles,
  type ConsolidatedNewsItem,
} from './newsEmail.ts';
import { activeClaims, attachClaimsToJob, claimItems, claimsForJob, reconcileDuplicateOutboxClaims } from './deliveryClaims.ts';
import { uniqueEnabledEmailRecipients } from './emailRecipients.ts';

/**
 * True when `db` is a pool (no transaction open) rather than a checked-out
 * client. `transaction()` must only be opened on a pool: a client is already
 * inside one, and reusing it would fail with "Client has already been
 * connected".
 */
const isPool = (db: Db): db is pg.Pool =>
  typeof (db as pg.Pool).connect === 'function' &&
  typeof (db as unknown as { release?: unknown }).release !== 'function';

/**
 * Per-article news delivery ledger.
 *
 * The article is the unit of delivery, not the match. One record per
 * `(recipient, article)` is written when an email carrying that article is
 * queued, which is what makes "never send the same news twice" survive:
 *
 *  - re-correlation (the matcher re-keys matches on `hash(cveId || articleId)`,
 *    so the same article yields new match rows over time);
 *  - an article arriving through a second feed (same URL, new article id);
 *  - a pipeline run whose outbox row has since been cleaned up.
 *
 * The record is keyed by the content identity of the article — the normalised
 * URL when one is available, otherwise the article id — so the same story is
 * recognised across feeds. It is not a delivery receipt: `outbox` still owns
 * transport state. It answers exactly one question, "has this recipient already
 * been told about this article?".
 */
const NEWS_LEDGER_KIND = 'newsNotifications';

/** Canonical content identity for an article: URL first, then the id. */
export { newsArticleIdentity } from './newsEmail.ts';

export function newsLedgerRecordId(recipientId: string, article: Pick<IntelligenceArticle, 'id' | 'url'>): string {
  return createHash('sha256')
    .update(newsNotifiedKey(recipientId, newsArticleIdentity(article)))
    .digest('hex');
}

interface NewsLedgerEntry {
  id: string;
  recipientId: string;
  articleId: string;
  identity: string;
  firstNotifiedAt: string;
  lastNotifiedAt: string;
  /** Number of consolidated emails that carried this article. */
  deliveries: number;
  /** Most recent delivery that carried it. */
  advisoryId: string;
}

export interface NewsQueueResult {
  /** Consolidated emails queued (one per recipient). */
  emailsQueued: number;
  /** Articles included in at least one email. */
  articlesIncluded: number;
  /** Articles skipped because the recipient already received them. */
  articlesSuppressed: number;
}

export interface NewsQueueDeps {
  /** Enqueue one consolidated email; injectable so the pipeline owns delivery. */
  enqueue: (input: {
    db: Db;
    recipient: EmailRecipient;
    articles: ConsolidatedNewsItem[];
    subject: string;
    text: string;
    html: string;
    cveIds: string[];
    contentRevision: string;
    identity: string;
    advisoryId: string;
  }) => Promise<string | null>;
}

/**
 * Reads the articles already delivered to a recipient.
 *
 * Two sources are consulted because either alone is insufficient: the ledger
 * survives outbox retention, and the outbox catches emails queued before the
 * ledger existed (or by a build that predates it).
 */
export async function alreadyNotified(
  db: Db,
  recipientIds: readonly string[],
  articles: ReadonlyMap<string, Pick<IntelligenceArticle, 'id' | 'url'>>,
): Promise<Map<string, Set<string>>> {
  const notified = new Map<string, Set<string>>(recipientIds.map((id) => [id, new Set<string>()]));
  if (!recipientIds.length || !articles.size) return notified;
  const articleIds = [...articles.keys()];
  const identities = [...new Set([...articles.values()].map(newsArticleIdentity))];
  const ledger = await db.query<{ recipient_id: string; article_id: string; identity: string }>(
    `SELECT data->>'recipientId' AS recipient_id, data->>'articleId' AS article_id,
            data->>'identity' AS identity FROM records
      WHERE kind=$1 AND data->>'recipientId'=ANY($2::text[])
        AND (data->>'articleId'=ANY($3::text[]) OR data->>'identity'=ANY($4::text[]))`,
    [NEWS_LEDGER_KIND, [...recipientIds], articleIds, identities],
  );
  for (const row of ledger.rows) {
    const set = notified.get(row.recipient_id);
    if (row.article_id) set?.add(newsNotifiedKey(row.recipient_id, row.article_id));
    if (row.identity) set?.add(newsNotifiedKey(row.recipient_id, row.identity));
  }
  const queued = await db.query<{ target_id: string; article_id: string; identity: string; url: string }>(
    `SELECT o.target_id, entry->>'id' AS article_id,
            entry->>'identity' AS identity, entry->>'url' AS url
       FROM outbox o
       CROSS JOIN LATERAL jsonb_array_elements(CASE
         WHEN jsonb_typeof(o.payload->'newsEvidence'->'articles')='array'
           THEN o.payload->'newsEvidence'->'articles'
         WHEN jsonb_typeof(o.payload->'newsEvidence'->'article')='object'
           THEN jsonb_build_array(o.payload->'newsEvidence'->'article')
         ELSE '[]'::jsonb END) entry
     WHERE o.channel='email' AND o.status=ANY($1::text[])
       AND o.target_id=ANY($2::text[]) AND o.payload ? 'newsEvidence'`,
    [['QUEUED', 'SENDING', 'ACCEPTED'], [...recipientIds]],
  );
  const currentIds = new Set(articleIds);
  const currentIdentities = new Set(identities);
  for (const row of queued.rows) {
    // AUD-008: historical payloads carry identities produced by an older
    // `newsArticleIdentity` (URL without its query string). When the original
    // URL survives in the payload, recompute the identity with the CURRENT
    // algorithm instead of trusting the stored one — otherwise an old
    // hostname-and-path identity would never match a new identity that keeps
    // meaningful query parameters, and the article would be re-sent.
    const identity = row.url
      ? newsArticleIdentity({ id: row.article_id || '', url: row.url })
      : row.identity || newsArticleIdentity({ id: row.article_id || '', url: '' });
    if (!currentIds.has(row.article_id) && !currentIdentities.has(identity)) continue;
    const set = notified.get(row.target_id);
    if (row.article_id) set?.add(newsNotifiedKey(row.target_id, row.article_id));
    set?.add(newsNotifiedKey(row.target_id, identity));
  }
  return notified;
}

/**
 * Writes the per-article ledger rows for one consolidated email.
 *
 * Idempotent: a replayed queue pass updates the delivery count instead of
 * creating a second record, so the ledger cannot grow on retries.
 */
export async function recordNewsDeliveries(
  db: Db,
  recipientId: string,
  advisoryId: string,
  articles: ReadonlyArray<Pick<IntelligenceArticle, 'id' | 'url'>>,
  /** Shared across the batch so one delivery cannot look like several. */
  deliveredAt: string = new Date().toISOString(),
): Promise<void> {
  if (!articles.length) return;
  const now = deliveredAt;
  for (const article of articles) {
    const id = newsLedgerRecordId(recipientId, article);
    const existing = await get<NewsLedgerEntry>(db, NEWS_LEDGER_KIND, id);
    await put(db, NEWS_LEDGER_KIND, id, {
      id,
      recipientId,
      articleId: article.id,
      identity: newsArticleIdentity(article),
      firstNotifiedAt: existing?.firstNotifiedAt || now,
      lastNotifiedAt: now,
      deliveries: existing?.lastNotifiedAt === now ? existing.deliveries : (existing?.deliveries || 0) + 1,
      advisoryId,
    } satisfies NewsLedgerEntry);
  }
}

/**
 * Queues ONE consolidated news email per eligible Security-team recipient for
 * every article that is (a) new to that recipient and (b) still new in this run.
 *
 * Consolidation and de-duplication are per recipient. Content revision is
 * derived from the *article set*, not the match ids, so:
 *  - the same articles re-derived on a later run produce the same dedupe key
 *    and cannot be queued twice;
 *  - a changed article set (a genuinely new story) is a different email.
 */
export async function queueConsolidatedNews(
  db: Db,
  matches: readonly IntelligenceMatch[],
  articles: ReadonlyMap<string, IntelligenceArticle>,
  recipients: readonly EmailRecipient[],
  deps: NewsQueueDeps,
): Promise<NewsQueueResult> {
  const result: NewsQueueResult = { emailsQueued: 0, articlesIncluded: 0, articlesSuppressed: 0 };
  const selected = uniqueEnabledEmailRecipients(recipients.filter(
    (recipient) =>
      recipient.enabled && (recipient.deliveryGroup === 'SECURITY_TEAM' || recipient.deliveryGroup === undefined),
  ));
  if (!selected.length || !matches.length) return result;
  const assetNameFor = (assetId: string) =>
    matches.find((match) => match.assetId === assetId)?.assetName || assetId;
  const items = consolidateNewsMatches(matches, articles, assetNameFor).filter(
    // A news email must reference at least one asset the recipient monitors and
    // carry a real article; empty items would produce a meaningless email.
    (item) => item.assets.length > 0 && item.article.url,
  );
  if (!items.length) return result;
  const articleRecord = new Map(items.map((item) => [item.article.id, item.article] as const));
  const recipientIds = recipients.map((recipient) => recipient.id);
  const notified = await alreadyNotified(db, recipientIds, articleRecord);
  // Durable per-recipient claims (AUD-002). `alreadyNotified` is the read side;
  // the claim written in the enqueue transaction is what makes two concurrent
  // runs unable to queue the same article for the same recipient.
  const claimed = await activeClaims(
    db,
    recipientIds,
    'article',
    items.map((item) => newsArticleIdentity(item.article)),
  );
  // A recipient receives one consolidated news email per pipeline run.
  for (const recipient of selected) {
    // Existing claims may belong to another recipient record for the same
    // physical mailbox; union them before deciding an article is new.
    const aliases = recipients.filter((candidate) =>
      candidate.email.trim().toLowerCase() === recipient.email.trim().toLowerCase());
    const notifiedForMailbox = new Set<string>();
    const claimedForMailbox = new Set<string>();
    for (const alias of aliases) {
      for (const key of notified.get(alias.id) ?? [])
        notifiedForMailbox.add(newsNotifiedKey(recipient.id, key.slice(alias.id.length + 1)));
      for (const key of claimed.get(alias.id) ?? []) claimedForMailbox.add(key);
    }
    const own = selectUnnotifiedArticles(items, recipient.id, notifiedForMailbox).filter(
      (item) => !claimedForMailbox.has(newsArticleIdentity(item.article)),
    );
    if (!own.length) {
      result.articlesSuppressed += items.length;
      continue;
    }
    // One consolidated message per recipient, not one message per 100 articles.
    // The renderer keeps the styled HTML within an explicit size budget and
    // lists any article that does not fit in a styled overflow summary, so the
    // body is never replaced by the plain-text document (AUD-004).
    const document = renderConsolidatedNewsEmailWithin(own);
    const batch = own.filter((item) => !document.overflow.includes(item));
    const overflow = document.overflow;
    const cveIds = [...new Set(own.flatMap((item) => item.cveIds))].sort();
    const articleIds = own.map((item) => item.article.id).sort();
    const contentRevision = createHash('sha256')
      .update(stableJson({ recipientId: recipient.id, articleIds, articleIdentities: own.map((item) => newsArticleIdentity(item.article)).sort() }))
      .digest('hex')
      .slice(0, 20);
    const advisoryId = `NEWS:${articleIds.join(',')}`.slice(0, 512);
    const identity = `news:${recipient.id}:${articleSetFingerprint(articleIds)}`;
    const claimRequests = claimsForJob(
      recipient.id,
      'article',
      own.map((item) => newsArticleIdentity(item.article)),
    );
    // Claim and enqueue atomically: a concurrent run that claimed any of these
    // articles first makes this transaction roll back, so only one run queues
    // the message. The claim is released if the enqueue dedupes.
    //
    // The caller may already be inside a transaction (the pipeline runs the
    // whole queue pass in one), in which case `db` is a client and the claim and
    // the enqueue share that transaction. Otherwise a transaction is opened here.
    const enqueueWithClaim = async (tx: Db) => {
      const claim = await claimItems(tx, claimRequests);
      if (!claim.granted.length) return null;
      // A denied claim never blocks the granted ones (audit follow-up, Finding
      // 3): the message carries only the articles this run actually won, so
      // unrelated new articles are still delivered. Denied items were never
      // claimed by this run, so there is nothing to roll back for them.
      const grantedIdentities = new Set(claim.granted.map((request) => request.itemId));
      const owned = own.filter((item) => grantedIdentities.has(newsArticleIdentity(item.article)));
      const ownedRequests = claim.granted;
      const ownedDocument = renderConsolidatedNewsEmailWithin(owned);
      const ownedCveIds = [...new Set(owned.flatMap((item) => item.cveIds))].sort();
      const ownedArticleIds = owned.map((item) => item.article.id).sort();
      const ownedRevision = createHash('sha256')
        .update(
          stableJson({
            recipientId: recipient.id,
            articleIds: ownedArticleIds,
            articleIdentities: owned.map((item) => newsArticleIdentity(item.article)).sort(),
          }),
        )
        .digest('hex')
        .slice(0, 20);
      const id = await deps.enqueue({
        db: tx,
        recipient,
        articles: owned,
        subject: ownedDocument.subject,
        text: ownedDocument.text,
        // The HTML is always the styled document; the size budget guarantees it
        // is attachable, and the plain text is only ever the alternative part.
        html: ownedDocument.html,
        cveIds: ownedCveIds,
        contentRevision: ownedRevision,
        identity: `news:${recipient.id}:${articleSetFingerprint(ownedArticleIds)}`,
        advisoryId: `NEWS:${ownedArticleIds.join(',')}`.slice(0, 512),
      });
      if (!id) {
        await reconcileDuplicateOutboxClaims(
          tx,
          `news:${recipient.id}:${articleSetFingerprint(ownedArticleIds)}:email:${recipient.id}`,
          ownedRequests,
        );
        return null;
      }
      await attachClaimsToJob(tx, id, ownedRequests);
      return id;
    };
    const queuedId = isPool(db) ? await transaction(db, enqueueWithClaim) : await enqueueWithClaim(db);
    if (!queuedId) {
      // An identical message is already queued (dedupe key matched) or another
      // run claimed these articles first. Treat them as already told so the
      // next run does not retry the same content.
      result.articlesSuppressed += own.length;
      continue;
    }
    result.emailsQueued++;
    result.articlesIncluded += own.length;
    result.articlesSuppressed += overflow.length;
    // Do not mark news delivered on enqueue. The delivery worker records a
    // durable receipt only after the mail provider accepts the message.
    await writeEvent(db, {
      category: 'MATCHING',
      level: 'INFO',
      code: 'matching.news_email_queued',
      message: 'Consolidated security-news email queued for the Security team',
      context: {
        recipientId: recipient.id,
        articles: own.length,
        fullCards: batch.length,
        overflowSummary: overflow.length,
        matches: [...new Set(own.flatMap((item) => item.matchIds))].length,
        advisoryId,
        suppressAlreadySent: own.length - batch.length,
      },
    });
  }
  return result;
}

/** Short, stable article-set fingerprint for the dedupe identity. */
const articleSetFingerprint = (articleIds: readonly string[]) =>
  createHash('sha256').update(articleIds.join(',')).digest('hex').slice(0, 24);

/**
 * Recipients eligible for consolidated news. Kept here so the pipeline and any
 * caller share one definition of "the Security team".
 */
export const newsRecipients = (recipients: readonly EmailRecipient[]) =>
  recipients.filter(
    (recipient) =>
      recipient.enabled && (recipient.deliveryGroup === 'SECURITY_TEAM' || recipient.deliveryGroup === undefined),
  );

/** Loads enabled recipients once; small table, single query. */
export const loadNewsRecipients = async (db: Db) => newsRecipients(await list<EmailRecipient>(db, 'recipients'));

interface NewsLedgerEntryWithFlag extends NewsLedgerEntry {
  /** Set during reconciliation when the original URL is no longer recoverable. */
  identityLegacy?: boolean;
}

/**
 * One-time reconciliation of historical news receipts (AUD-008 / audit
 * follow-up).
 *
 * Older builds wrote ledger identities with the pre-query-string algorithm, and
 * migration 039 deliberately does NOT backfill news claims — a stored identity
 * cannot be trusted to match the current format, and guessing would suppress
 * distinct articles.
 *
 * For every ACCEPTED news job still retained in the outbox the original article
 * URLs survive in the payload. This writes the ledger identity from that
 * evidence using the CURRENT algorithm and promotes a DELIVERED article claim,
 * so historical deliveries stay recognised under the new scheme.
 *
 * Ledger rows whose original URL is gone (and that do not already match the
 * current format) are flagged with `identityLegacy` rather than guessed at: they
 * keep suppressing by article id, and an operator reconciling archives can
 * resolve the flag once the original URL is known.
 *
 * Safe to run repeatedly: ledger updates are idempotent and claims are only
 * promoted (CLAIMED → DELIVERED), never created over a DELIVERED receipt.
 */
export async function reconcileHistoricalNewsDeliveries(
  db: Db,
): Promise<{ ledger: number; claims: number; flagged: number }> {
  const jobs = await db.query<
    { job_id: string; target_id: string; accepted_at: string | null; article_id: string; url: string }
  >(
    `SELECT o.id AS job_id, o.target_id,
            o.updated_at::text AS accepted_at,
            entry->>'id' AS article_id, entry->>'url' AS url
       FROM outbox o
       CROSS JOIN LATERAL jsonb_array_elements(CASE
         WHEN jsonb_typeof(o.payload->'newsEvidence'->'articles')='array'
           THEN o.payload->'newsEvidence'->'articles'
         WHEN jsonb_typeof(o.payload->'newsEvidence'->'article')='object'
           THEN jsonb_build_array(o.payload->'newsEvidence'->'article')
         ELSE '[]'::jsonb END) entry
      WHERE o.channel='email' AND o.status='ACCEPTED' AND o.payload ? 'newsEvidence'
        AND COALESCE(entry->>'url','') <> ''`,
  );
  let ledger = 0;
  let claims = 0;
  let flagged = 0;
  for (const row of jobs.rows) {
    const article = { id: row.article_id || '', url: row.url };
    const canonicalIdentity = newsArticleIdentity(article);
    const acceptedAt = row.accepted_at || new Date().toISOString();
    // Write/refresh the ledger row so its identity matches the current format.
    const ledgerId = newsLedgerRecordId(row.target_id, article);
    const existing = await get<NewsLedgerEntryWithFlag>(db, NEWS_LEDGER_KIND, ledgerId);
    if (!existing) {
      await put(db, NEWS_LEDGER_KIND, ledgerId, {
        id: ledgerId,
        recipientId: row.target_id,
        articleId: article.id,
        identity: canonicalIdentity,
        firstNotifiedAt: acceptedAt,
        lastNotifiedAt: acceptedAt,
        deliveries: 1,
        advisoryId: row.job_id,
      } satisfies NewsLedgerEntryWithFlag);
      ledger++;
    } else if (existing.identity !== canonicalIdentity) {
      await put(db, NEWS_LEDGER_KIND, ledgerId, { ...existing, identity: canonicalIdentity });
      ledger++;
    }
    // DELIVERED article claim. Upsert: insert a receipt when no row exists
    // (migration 039 excludes news, so this is the common historical case),
    // promote an existing CLAIMED row held by the accepted job, and never
    // overwrite an existing DELIVERED receipt.
    const upserted = await db.query(
      `INSERT INTO delivery_claims(recipient_id,kind,item_id,state,job_id,claimed_at,delivered_at)
       VALUES($1,'article',$2,'DELIVERED',$3::uuid,$4::timestamptz,$4::timestamptz)
       ON CONFLICT (recipient_id,kind,item_id) DO UPDATE SET
         state='DELIVERED', job_id=EXCLUDED.job_id, delivered_at=EXCLUDED.delivered_at, expires_at=NULL
        WHERE delivery_claims.state='CLAIMED'
      RETURNING xmin::text::bigint > 0 AS inserted_new`,
      [row.target_id, canonicalIdentity, row.job_id, acceptedAt],
    );
    claims += upserted.rowCount ?? 0;
  }
  // Flag rows this build cannot re-derive: no retained URL and an identity that
  // predates the query-string change. Reconciling them needs archived evidence.
  const stale = await db.query<{ id: string; identity: string }>(
    `SELECT id, data->>'identity' AS identity FROM records
      WHERE kind=$1
        AND data->>'identity' LIKE 'url:%'
        AND data->>'identity' NOT LIKE 'url:%?%'
        AND COALESCE(data->>'identityLegacy','false') <> 'true'`,
    [NEWS_LEDGER_KIND],
  );
  for (const row of stale.rows) {
    const existing = await get<NewsLedgerEntryWithFlag>(db, NEWS_LEDGER_KIND, row.id);
    if (existing) {
      await put(db, NEWS_LEDGER_KIND, row.id, { ...existing, identityLegacy: true });
      flagged++;
    }
  }
  if (ledger || claims || flagged)
    await writeEvent(db, {
      category: 'EMAIL',
      level: 'INFO',
      code: 'delivery.news_history_reconciled',
      message: 'Historical news receipts reconciled to the current article identity format',
      context: { ledgerRowsWritten: ledger, claimsPromoted: claims, rowsFlaggedForReconciliation: flagged },
    });
  return { ledger, claims, flagged };
}
