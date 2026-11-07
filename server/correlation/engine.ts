import type { AdvisoryInput, ExtractedText } from './validation.ts';
import type { CorrelationMatch } from '../../shared/correlation.ts';
import { evaluateVersionDetailed } from './version.ts';
import type { QueryResult, QueryResultRow } from 'pg';

interface Asset {
  id: string;
  vendor: string;
  product: string;
  version: string | null;
  revision: string;
}
interface Entity {
  vendor: string;
  product: string;
  affectedRange?: string;
}
export type TimedQuery = <T extends QueryResultRow>(
  sql: string,
  values?: unknown[],
) => Promise<QueryResult<T>>;

/** Upper bound on distinct canonical entities one advisory may resolve to. */
export const MAX_ENTITY_FANOUT = 100;
/** Upper bound on matched assets per advisory. */
export const MAX_MATCH_FANOUT = 1000;
/** Upper bound on distinct CPE/PURL identities accepted from one advisory. */
export const MAX_STRUCTURED_IDENTITIES = 4096;
/** Rows read per keyset page while walking the inventory for one entity. */
const INVENTORY_PAGE_SIZE = 500;
/** How far from an alias name its version bound may appear, in tokens. */
const BOUND_WINDOW = 3;
/** Alias rows fetched per advisory: bounds query cost, never correctness. */
const ALIAS_ROW_CEILING = MAX_ENTITY_FANOUT * 8;
/** Prose tokens examined. Beyond this the tail of a document is not trusted. */
const MAX_TOKENS = 8_192;

/**
 * Tokens that can never be product identity. Grammatical words and generic
 * security vocabulary: an article saying "critical flaw in enterprise servers"
 * must not nominate "enterprise servers" as an alias candidate.
 */
const STOPWORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'of', 'in', 'for', 'to', 'on', 'with', 'by', 'from', 'at', 'is', 'are',
  'was', 'were', 'this', 'that', 'it', 'as', 'be', 'has', 'have', 'had', 'not', 'no', 'but', 'its',
  'their', 'our', 'new', 'other', 'after', 'before', 'between', 'through', 'over', 'under', 'about',
  'into', 'more', 'most', 'than', 'then', 'exploit', 'exploits', 'vulnerability', 'vulnerabilities',
  'security', 'attack', 'attacker', 'attackers', 'flaw', 'flaws', 'bug', 'bugs', 'patch', 'patched',
  'update', 'updates', 'zero', 'day', 'critical', 'remote', 'code', 'execution', 'affected', 'versions',
  'version', 'software', 'servers', 'server', 'systems', 'system', 'users', 'user', 'researchers',
  'researcher', 'reported', 'disclosed', 'fixed', 'issued', 'using', 'used', 'which', 'while', 'when',
  'who', 'also', 'been', 'being', 'could', 'would', 'should', 'may', 'might', 'will',
]);

/**
 * Applicability operators. A version number next to a product name is not
 * evidence; one of these words next to it is.
 */
const APPLICABILITY_OPERATOR =
  /^(?:patched|fixed|resolved|remediated|addressed|corrected|hardened|before|prior|below|earlier|affected|vulnerable|susceptible|exposed|impacted)$/;

/** Token split used for identity, shared with the extraction worker. */
const TOKEN_SPLIT = /[^a-z0-9_.+-]+/;

/**
 * Identity tokens of a normalized text.
 *
 * A whitespace split is not enough: the extraction worker rewrites the article
 * as `' ' + tokens.join(' ') + ' '`, which preserves sentence punctuation on the
 * final token ('fortios.'). Splitting on the same boundary the normalizer uses
 * removes that trailing punctuation, so a product name at the end of a sentence
 * is still an alias candidate.
 */
export function identityTokens(text: string): string[] {
  return text
    .toLowerCase()
    .split(TOKEN_SPLIT)
    .map((token) => token.replace(/^\.+|\.+$/g, ''))
    .filter(Boolean);
}

/** Canonical form of an alias or phrase for comparison with extractor output. */
const normalized = (value: string) => value.toLowerCase().replace(/[^a-z0-9_.+-]+/g, ' ').trim();

/**
 * Drop leading words that describe a position in the sentence, not the
 * product. The extractor's product phrase is whatever words precede the
 * operator, so "… and fortios before 7.2.4" yields "and fortios". Treating
 * that as a product name makes the phrase match nothing and silently discards
 * a real bound.
 */
const LEADING_WORDS = new Set([
  'and', 'or', 'but', 'also', 'then', 'plus', 'while', 'when', 'where', 'which', 'that', 'with',
  'for', 'from', 'to', 'of', 'in', 'on', 'at', 'by', 'as', 'is', 'are', 'was', 'were', 'the', 'a', 'an',
]);
const canonicalPhrase = (value: string): string => {
  const words = normalized(value).split(' ').filter(Boolean);
  while (words.length > 1 && LEADING_WORDS.has(words[0])) words.shift();
  return words.join(' ');
};

/**
 * Two product phrases name the same product when one is a complete suffix or
 * prefix of the other: the extractor captures "enterprise kubernetes" while the
 * thesaurus holds "kubernetes". Neither may be a strict substring in the middle
 * of an unrelated name.
 */
const phraseMatches = (left: string, right: string): boolean => {
  if (!left || !right) return false;
  if (left === right) return true;
  return (
    left.endsWith(` ${right}`) ||
    right.endsWith(` ${left}`) ||
    left.startsWith(`${right} `) ||
    right.startsWith(`${left} `)
  );
};

const entityKey = (vendor: string, product: string) => `${vendor.toLowerCase()}:${product.toLowerCase()}`;

/**
 * Two-stage correlation.
 *
 * Tier 1 is an indexed identity intersection on CPE/PURL, which is the only
 * evidence strong enough to bypass version logic. Tier 2 resolves vendor and
 * product from prose through the alias thesaurus, then evaluates the affected
 * version range against every asset of that entity. Nothing is decided by
 * substring containment: every match names the evidence that produced it.
 */
export class TextCorrelationEngine {
  async correlate(
    input: AdvisoryInput,
    extracted: ExtractedText,
    query: TimedQuery,
  ): Promise<CorrelationMatch[]> {
    const matches = new Map<string, CorrelationMatch>();
    const add = (asset: Asset, confidence: CorrelationMatch['confidence'], reason: string) => {
      const existing = matches.get(asset.id);
      // Confidence only ever rises for one asset within one advisory.
      if (existing) {
        const rank = { LOW: 0, MEDIUM: 1, HIGH: 2 } as const;
        if (rank[existing.confidence] >= rank[confidence]) return;
      } else if (matches.size >= MAX_MATCH_FANOUT) {
        throw new Error('MATCH_FANOUT_LIMIT');
      }
      // A negated advisory ("not affected", "false positive") asserts the
      // opposite of exposure. Its findings are demoted to review evidence and
      // never reported as an asset match, whatever tier produced them.
      if (extracted.negated) {
        matches.set(asset.id, {
          assetId: asset.id,
          vendor: asset.vendor,
          product: asset.product,
          confidence: 'LOW',
          reason: 'Applicability negation or conflicting evidence requires review',
          assetRevision: asset.revision,
        });
        return;
      }
      matches.set(asset.id, {
        assetId: asset.id,
        vendor: asset.vendor,
        product: asset.product,
        confidence,
        reason,
        assetRevision: asset.revision,
      });
    };

    // ---- Tier 1: structured identity -------------------------------------
    const cpes = [...new Set(input.cpes)].slice(0, MAX_STRUCTURED_IDENTITIES);
    const purls = [...new Set(input.purls)].slice(0, MAX_STRUCTURED_IDENTITIES);
    if (cpes.length || purls.length) {
      const exact = await query<Asset>(
        `SELECT id,vendor,product,version,revision FROM correlation_asset_inventory
         WHERE (cpe_23 IS NOT NULL AND cpe_23=ANY($1::text[]))
            OR (purl IS NOT NULL AND purl=ANY($2::text[]))
            OR id IN (
              SELECT native_id FROM correlation_managed_assets
              WHERE active AND (cpes && $1::text[] OR purls && $2::text[])
            )
         ORDER BY id
         LIMIT ${MAX_MATCH_FANOUT + 1}`,
        [cpes, purls],
      );
      if (exact.rows.length > MAX_MATCH_FANOUT) throw new Error('MATCH_FANOUT_LIMIT');
      for (const asset of exact.rows)
        add(asset, 'HIGH', 'Explicit structured CPE/PURL identity intersection');
    }

    // ---- Tier 2: entities from prose -------------------------------------
    const tokens = identityTokens(extracted.text).slice(0, MAX_TOKENS);
    const entityByKey = new Map<string, Entity>();
    for (const entity of input.entities) {
      entityByKey.set(entityKey(entity.vendor, entity.product), { ...entity });
    }
    const explicitKeys = new Set(entityByKey.keys());

    const grams = new Set<string>();
    for (let start = 0; start < tokens.length; start++) {
      for (let length = 1; length <= 4 && start + length <= tokens.length; length++) {
        const span = tokens.slice(start, start + length);
        if (span.some((token) => STOPWORDS.has(token) || token.length < 2)) continue;
        grams.add(span.join(' '));
      }
    }

    // Position index of every prose token, so a bound can be tied to the alias
    // it belongs to instead of to whichever clause happens to be first.
    const proseTokens = extracted.text
      .toLowerCase()
      .split(TOKEN_SPLIT)
      .filter(Boolean);
    const positionsByToken = new Map<string, number[]>();
    for (const [position, token] of proseTokens.entries()) {
      const list = positionsByToken.get(token);
      if (list) list.push(position);
      else positionsByToken.set(token, [position]);
    }
    // An extracted range whose product phrase names a *different* product can
    // never describe this article's single entity; such a range is not evidence
    // for it. Ranges with no phrase, or with a phrase contained in the prose,
    // remain candidates for proximity attribution.
    const aliases = await query<Entity & { alias: string }>(
      `SELECT alias,vendor,product FROM vendor_product_aliases
       WHERE lower(alias) IN (SELECT jsonb_array_elements_text($1::jsonb))
       ORDER BY length(alias) DESC, lower(alias), vendor, product
       LIMIT ${ALIAS_ROW_CEILING}`,
      [JSON.stringify([...grams])],
    );
    const namedEntities = new Set(
      aliases.rows.map((row) => entityKey(row.vendor, row.product)),
    );
    for (const key of explicitKeys) namedEntities.add(key);

    for (const alias of aliases.rows) {
      const key = entityKey(alias.vendor, alias.product);
      // An explicit entity wins, and the longest alias already claimed this
      // identity: a shorter synonym cannot add a different range.
      if (entityByKey.has(key)) continue;
      const phrase = canonicalPhrase(alias.alias);
      let affectedRange: string | undefined;
      if (namedEntities.size === 1 && extracted.ranges.length === 1) {
        const candidate = extracted.ranges[0];
        const candidatePhrase = canonicalPhrase(candidate.productPhrase);
        // Evidence phrased against this product name...
        if (phraseMatches(candidatePhrase, phrase)) affectedRange = candidate.range;
        // ...or a bound adjacent to the name with an applicability operator
        // beside it, for prose the extractor could not attach to a product. The
        // captured phrase is often the word *before* the operator ("affected"),
        // so any non-matching phrase falls through to the proximity test.
        else {
          const phraseTokens = phrase.split(' ');
          const last = phraseTokens[phraseTokens.length - 1];
          const adjacent = (positionsByToken.get(last) ?? []).some((position) =>
            proseTokens
              .slice(
                Math.max(0, position - BOUND_WINDOW),
                position + phraseTokens.length + BOUND_WINDOW,
              )
              .some((token) => APPLICABILITY_OPERATOR.test(token)),
          );
          if (adjacent) affectedRange = candidate.range;
        }
      }
      entityByKey.set(key, { vendor: alias.vendor, product: alias.product, affectedRange });
      if (entityByKey.size > MAX_ENTITY_FANOUT) break;
    }

    // Tier 2b: no alias resolved, but the prose names an inventoried product
    // directly. This is deliberately the weakest tier and produces review
    // evidence only — an advisory naming a product is not evidence that an
    // installed version is exposed.
    if (!entityByKey.size && extracted.securitySignal) {
      const names = await query<Asset>(
        `SELECT id,vendor,product,version,revision FROM correlation_asset_inventory
         WHERE lower(vendor) IN (SELECT jsonb_array_elements_text($1::jsonb))
           AND lower(product) IN (SELECT jsonb_array_elements_text($1::jsonb))
         ORDER BY id
         LIMIT ${MAX_MATCH_FANOUT + 1}`,
        [JSON.stringify(tokens.slice(0, 2000))],
      );
      if (names.rows.length > MAX_MATCH_FANOUT) throw new Error('MATCH_FANOUT_LIMIT');
      for (const asset of names.rows)
        add(asset, 'LOW', 'Vendor/product tokens present; contextual applicability requires review');
    }

    // Deterministic keyset walk of each entity's inventory. A bare LIMIT over
    // the UNION view (no ORDER BY) returned an arbitrary slice: assets past the
    // first page were never evaluated, and the subset changed between runs.
    for (const entity of entityByKey.values()) {
      const vendor = entity.vendor.toLowerCase();
      const product = entity.product.toLowerCase();
      let cursor: string | null = null;
      let examined = 0;
      while (true) {
        const page: QueryResult<Asset> = await query<Asset>(
          `SELECT id,vendor,product,version,revision FROM correlation_asset_inventory i
           WHERE lower(i.vendor)=$1 AND lower(i.product)=$2 AND ($3::uuid IS NULL OR i.id>$3::uuid)
           ORDER BY i.id LIMIT ${INVENTORY_PAGE_SIZE}`,
          [vendor, product, cursor],
        );
        for (const asset of page.rows) {
          examined++;
          if (examined > MAX_MATCH_FANOUT) throw new Error('MATCH_FANOUT_LIMIT');
          if (!entity.affectedRange) {
            add(
              asset,
              extracted.securitySignal ? 'MEDIUM' : 'LOW',
              'Exact canonical vendor/product; affected versions unspecified',
            );
            continue;
          }
          const verdict = evaluateVersionDetailed(asset.version, entity.affectedRange);
          if (verdict.verdict === 'AFFECTED')
            add(
              asset,
              'HIGH',
              `Canonical entity and explicit affected version range satisfied (${verdict.provenance}:${verdict.comparator})`,
            );
          else if (verdict.verdict === 'REVIEW')
            add(
              asset,
              'LOW',
              `Version/backport ordering uncertain (${verdict.provenance}:${verdict.comparator}); vendor evidence required`,
            );
        }
        if (page.rows.length < INVENTORY_PAGE_SIZE) break;
        cursor = page.rows[page.rows.length - 1].id;
      }
    }

    // Nothing matched, but the article is dense with exploitation language and
    // carries no CVE: it is real evidence with no asset attribution. Returned
    // with an empty assetId so ingest routes it to the unassigned review queue.
    if (matches.size === 0 && (extracted.zeroDay || (extracted.negated && extracted.securitySignal)))
      return [
        {
          assetId: '',
          vendor: '',
          product: '',
          confidence: 'LOW',
          reason: extracted.negated
            ? 'Applicability negation or conflicting evidence requires review'
            : 'Security keyword density without published CVE; unverified early intelligence',
        },
      ];
    return [...matches.values()];
  }
}
