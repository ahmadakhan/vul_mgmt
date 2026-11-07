import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { loadConfig } from '../server/config.ts';
import { createPool, get, transaction } from '../server/db.ts';
import { applyCommand } from '../server/commands.ts';
import { RECOMMENDED_FEEDS } from '../server/recommendedFeeds.ts';
import { INITIAL_WATCHLIST } from '../tests/fixtures/seedData.ts';

// Load .env file if environment variables are not already set, so the seed
// script works from a plain `npm run seed` invocation without manual export.
const envPath = join(process.cwd(), '.env');
if (existsSync(envPath)) {
  const envContent = readFileSync(envPath, 'utf8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const value = trimmed
      .slice(eqIdx + 1)
      .trim()
      .replace(/^['"]|['"]$/g, '');
    if (!(key in process.env)) process.env[key] = value;
  }
}

const config = loadConfig();
const pool = createPool(config.DATABASE_URL);

// Seeding is two-gated: an operator must BOTH set BOOTSTRAP_RECOMMENDED_FEEDS=true
// in the environment AND invoke the command (`npm run seed`). Neither alone
// seeds external feeds, so the server never opens egress to threat sources
// automatically in dev or prod.
const shouldSeed = config.BOOTSTRAP_RECOMMENDED_FEEDS === 'true';

/* Contract-verified primary feeds plus legacy rows that must be disabled.
 * NVD and the canonical CVE sources now come from RECOMMENDED_FEEDS (spread
 * below) so the threat-feed catalog has a single source of truth. */
const feedPayload = [
  {
    id: 'feed-cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities Catalog',
    type: 'CISA_KEV' as const,
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    authType: 'NONE' as const,
    rateLimitPerMin: 120,
    enabled: true,
    vendorSeed: true,
  },
  {
    id: 'feed-epss',
    name: 'FIRST Exploit Prediction Scoring System',
    type: 'EPSS_API' as const,
    url: 'https://api.first.org/data/v1/epss',
    authType: 'NONE' as const,
    rateLimitPerMin: 240,
    enabled: true,
    vendorSeed: true,
  },
  {
    id: 'feed-msrc',
    name: 'Microsoft Security Response Center (MSRC)',
    type: 'JSON_SEARCH_API' as const,
    url: 'https://api.msrc.microsoft.com/cvrf/v2.0/updates',
    authType: 'NONE' as const,
    rateLimitPerMin: 120,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-paloalto',
    name: 'Palo Alto Networks Unit 42 Advisory Feed',
    type: 'JSON_SEARCH_API' as const,
    url: 'https://security.paloaltonetworks.com/api/v1/advisories',
    authType: 'NONE' as const,
    rateLimitPerMin: 100,
    enabled: false,
    vendorSeed: true,
  },
  ...RECOMMENDED_FEEDS,
];

if (!shouldSeed) {
  // No BOOTSTRAP_RECOMMENDED_FEEDS=true — report current database contents and exit.
  // Seeding only happens when explicitly requested:
  //   BOOTSTRAP_RECOMMENDED_FEEDS=true npm run seed
  const feeds = await get<any[]>(pool, 'feeds', '*');
  const feedRows = (await pool.query('SELECT id FROM records WHERE kind=$1', ['feeds'])).rows;
  const watchlistRows = (await pool.query('SELECT id FROM records WHERE kind=$1', ['watchlist'])).rows;
  console.log(`Database has ${feedRows.length} feeds and ${watchlistRows.length} monitored products.`);
  console.log('Set BOOTSTRAP_RECOMMENDED_FEEDS=true and re-run `npm run seed` to apply seed fixtures.');
  await pool.end();
  process.exit(0);
}

try {
  await transaction(pool, async (db) => {
    // These legacy seed URLs return vendor-specific advisory documents, not the
    // normalized-CVE array required by JSON_SEARCH_API. Disable them until a
    // source-specific, schema-validated adapter is configured.
    for (const id of ['feed-msrc', 'feed-paloalto']) {
      const legacy = await get<{ enabled: boolean }>(db, 'feeds', id);
      if (legacy?.enabled)
        await applyCommand(db, config, { action: 'feed.toggle', id, actor: 'seed-script' });
    }
    // Feeds go through the same validated command path the API uses, so a
    // misconfigured feed fails loudly here instead of landing in the database.
    await applyCommand(db, config, {
      action: 'feed.import',
      data: feedPayload,
      actor: 'seed-script',
    });

    // The watchlist is upserted by its stable fixture id so that repeated
    // seeding refreshes existing rows instead of failing with "not found"
    // or orphaning the findings that reference those asset ids.
    await applyCommand(db, config, {
      action: 'watchlist.import',
      data: INITIAL_WATCHLIST.map((item) => ({
        id: item.id,
        vendor: item.vendor,
        product: item.product,
        version: item.version,
        cpes: item.cpes,
        purls: item.purls,
        targetHw: item.targetHw,
        assetTag: item.assetTag,
        ownerGroup: item.ownerGroup,
        active: item.active,
        notes: item.notes,
        exposure: item.exposure,
        createdAt: item.createdAt,
      })),
      actor: 'seed-script',
    });
  });

  console.log('Seed data applied: Threat Feed Sources and Monitored Product Inventory only.');
} catch (e) {
  if (e instanceof z.ZodError) {
    console.error('Seed failed: feed configuration is invalid.');
    for (const issue of e.issues) console.error(`  - ${issue.path.join('.') || '(root)'}: ${issue.message}`);
    process.exitCode = 1;
  } else {
    console.error('Seed failed:', e);
    process.exitCode = 1;
  }
} finally {
  await pool.end();
}
