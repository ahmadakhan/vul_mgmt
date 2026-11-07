import type { MatchingCase } from '../../src/utils/matchingMetrics.ts';

interface CpeParts {
  part?: string;
  vendor: string;
  product: string;
  version?: string;
  update?: string;
  edition?: string;
  language?: string;
  swEdition?: string;
  targetSw?: string;
  targetHw?: string;
  other?: string;
}

const cpe = (parts: CpeParts): string =>
  [
    'cpe:2.3',
    parts.part ?? 'a',
    parts.vendor,
    parts.product,
    parts.version ?? '*',
    parts.update ?? '*',
    parts.edition ?? '*',
    parts.language ?? '*',
    parts.swEdition ?? '*',
    parts.targetSw ?? '*',
    parts.targetHw ?? '*',
    parts.other ?? '*',
  ].join(':');

const benignText = {
  vulnTitle: 'Quarterly security bulletin',
  vulnDescription: 'Routine maintenance information published by the vendor.',
};

/**
 * Labelled correlation corpus used by `npm run matching:evaluate` and
 * `tests/matching-quality.test.ts`.
 *
 * Every case names the evidence class it expects, not just match/no-match.
 * That is deliberate: a matcher can be "right" for the wrong reason (an alias
 * match where strict CPE was expected), and that would hide a confidence or
 * review-gating regression. Add real-world cases here when a production
 * mismatch is investigated; the harness turns them into a permanent gate.
 */
export const MATCHING_CORPUS: MatchingCase[] = [
  {
    id: 'strict-exact',
    description: 'Identical structured CPE tokens match at the strict tier',
    tags: ['strict', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      ...benignText,
    },
    expected: { matched: true, methods: ['STRICT_CPE'], confidence: 90, requiresReview: false },
  },
  {
    id: 'strict-interval',
    description: 'Strict CPE plus a verified version interval reaches 100% dispatch confidence',
    tags: ['strict', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.5' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.5' })],
      versionRange: { versionStartIncluding: '1.0', versionEndExcluding: '2.0' },
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['STRICT_CPE_INTERVAL'],
      confidence: 100,
      requiresReview: false,
    },
  },
  {
    id: 'strict-case-insensitive',
    description: 'CPE components are compared case-insensitively',
    tags: ['strict', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'Example', product: 'Widget', version: '1.0' })],
      assetVendor: 'Example',
      assetProduct: 'Widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      ...benignText,
    },
    expected: { matched: true, methods: ['STRICT_CPE'], confidence: 90 },
  },
  {
    id: 'registered-all-versions',
    description: 'A registered all-version product intentionally covers concrete vulnerable versions',
    tags: ['strict', 'wildcard', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '*' })],
      assetVendor: 'example', assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.5' })],
      versionRange: { versionEndExcluding: '2.0' },
      ...benignText,
    },
    expected: { matched: true, methods: ['STRICT_CPE_INTERVAL'], confidence: 100, requiresReview: false },
  },
  {
    id: 'generic-cpe-resolved',
    description: 'A wildcard inventory CPE is anchored to the inventory product and stays review-only',
    tags: ['generic', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: '*', product: '*', version: '1.5' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme', product: 'widget', version: '1.5' })],
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['STRICT_CPE'],
      confidence: 70,
      requiresReview: true,
    },
  },
  {
    id: 'purl-exact',
    description: 'Identical package identities with concrete versions match at the PURL tier',
    tags: ['purl', 'positive'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetPurls: ['pkg:npm/widget@1.2.3'],
      vulnPurls: ['pkg:npm/widget@1.2.3'],
      ...benignText,
    },
    expected: { matched: true, methods: ['PURL_EXACT'], confidence: 95, requiresReview: false },
  },
  {
    id: 'purl-name-only-review',
    description: 'A version-less package identity is review-only, never auto-dispatchable',
    tags: ['purl', 'positive'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetPurls: ['pkg:npm/widget'],
      vulnPurls: ['pkg:npm/widget'],
      ...benignText,
    },
    expected: { matched: true, methods: ['PURL_EXACT'], confidence: 70, requiresReview: true },
  },
  {
    id: 'alias-built-in-vendor',
    description: 'Built-in vendor aliases resolve a structured spelling difference at 85%',
    tags: ['alias', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'microsoft', product: 'exchange_server', version: '15' })],
      assetVendor: 'microsoft',
      assetProduct: 'exchange_server',
      vulnCpes: [cpe({ vendor: 'msft', product: 'exchange_server', version: '15' })],
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_ALIAS'],
      confidence: 85,
      requiresReview: false,
    },
  },
  {
    id: 'alias-built-in-product',
    description: 'Punctuation-only product differences resolve through normalization at 85%',
    tags: ['alias', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget_pro', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget_pro',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget-pro', version: '1.0' })],
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_ALIAS'],
      confidence: 85,
    },
  },
  {
    id: 'alias-operator-custom',
    description: 'Operator aliases broaden vendor identity without changing the confidence tier',
    tags: ['alias', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'acme', product: 'widget', version: '1.0' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme_corp', product: 'widget', version: '1.0' })],
      customVendorAliases: { acme: ['acme_corp'] },
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_ALIAS'],
      confidence: 85,
    },
  },
  {
    id: 'fallback-text',
    description: 'Whole-word vendor and product prose is the last-resort review-only match',
    tags: ['fallback', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'asset_vendor', product: 'asset_widget', version: '1.5' })],
      assetVendor: 'asset_vendor',
      assetProduct: 'asset_widget',
      vulnCpes: [cpe({ vendor: 'nvd_vendor', product: 'nvd_widget', version: '*' })],
      vulnTitle: 'Asset Vendor Asset Widget security advisory',
      vulnDescription: 'A flaw was found in the Asset Widget product family.',
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_FALLBACK'],
      confidence: 70,
    },
  },
  {
    id: 'fallback-in-range',
    description: 'Prose fallback still verifies a comparable version range before matching',
    tags: ['fallback', 'positive'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'widget',
      assetVersion: '1.5',
      vulnTitle: 'Acme Widget vulnerability',
      vulnDescription: 'Versions before 2.0 are affected.',
      versionRange: { versionEndExcluding: '2.0' },
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_FALLBACK'],
      confidence: 70,
    },
  },
  {
    id: 'unknown-update-requires-review',
    description: 'An unconstrained inventory update field cannot prove a service-pack criterion',
    tags: ['strict', 'positive', 'review'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [
        cpe({ vendor: 'example', product: 'widget', version: '1.0', update: 'sp1' }),
      ],
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['STRICT_CPE'],
      confidence: 70,
      requiresReview: true,
    },
  },

  // Negative cases: these are the errors that matter operationally.
  {
    id: 'negative-purl-version',
    description: 'A concrete PURL version mismatch is authoritative',
    tags: ['purl', 'negative'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetPurls: ['pkg:npm/widget@1.0.0'],
      vulnPurls: ['pkg:npm/widget@2.0.0'],
      ...benignText,
    },
    expected: { matched: false },
  },
  {
    id: 'negative-purl-identity',
    description: 'Different package identities never correlate through prose',
    tags: ['purl', 'negative'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetPurls: ['pkg:npm/widget@1.0.0'],
      vulnPurls: ['pkg:npm/gadget@1.0.0'],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-version-token',
    description: 'Identical product identity with a different explicit CPE version is an exclusion',
    tags: ['version', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '3.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-range-exclusion',
    description: 'A comparable version outside the advisory interval cannot fall through to prose',
    tags: ['version', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'acme', product: 'widget', version: '3.0' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme', product: 'widget', version: '*' })],
      versionRange: { versionEndExcluding: '2.0' },
      vulnTitle: 'Acme Widget vulnerability',
      vulnDescription: 'Acme Widget before 2.0 is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-platform-same-names',
    description: 'A target-OS conflict is authoritative when the product names match',
    tags: ['platform', 'negative'],
    input: {
      assetCpes: [
        cpe({ vendor: 'microsoft', product: 'exchange', version: '15', targetSw: 'linux' }),
      ],
      assetVendor: 'microsoft',
      assetProduct: 'exchange',
      vulnCpes: [
        cpe({ vendor: 'microsoft', product: 'exchange', version: '15', targetSw: 'windows' }),
      ],
      vulnTitle: 'Microsoft Exchange vulnerability',
      vulnDescription: 'Microsoft Exchange is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-platform-alias-names',
    description: 'Alias resolution does not erase a target-OS exclusion',
    tags: ['platform', 'alias', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'msft', product: 'exchange', version: '15', targetSw: 'linux' })],
      assetVendor: 'microsoft',
      assetProduct: 'exchange',
      vulnCpes: [
        cpe({ vendor: 'microsoft', product: 'exchange', version: '15', targetSw: 'windows' }),
      ],
      vulnTitle: 'Microsoft Exchange vulnerability',
      vulnDescription: 'Microsoft Exchange is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-part',
    description: 'Application and hardware CPE parts never correlate',
    tags: ['platform', 'negative'],
    input: {
      assetCpes: [cpe({ part: 'a', vendor: 'example', product: 'widget', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ part: 'h', vendor: 'example', product: 'widget', version: '1.0' })],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-edition',
    description: 'An explicit edition conflict is authoritative',
    tags: ['platform', 'negative'],
    input: {
      assetCpes: [
        cpe({ vendor: 'example', product: 'widget', version: '1.0', edition: 'enterprise' }),
      ],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [
        cpe({ vendor: 'example', product: 'widget', version: '1.0', edition: 'community' }),
      ],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-architecture',
    description: 'A target-architecture conflict is authoritative',
    tags: ['platform', 'negative'],
    input: {
      assetCpes: [
        cpe({ vendor: 'example', product: 'widget', version: '1.0', targetHw: 'x86_64' }),
      ],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0', targetHw: 'arm64' })],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-architecture-argument',
    description: 'The explicit architecture de-noising argument also rejects a mismatch',
    tags: ['platform', 'negative'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetTargetHw: 'x86_64',
      vulnTargetHw: 'arm64',
      ...benignText,
    },
    expected: { matched: false },
  },
  {
    id: 'negative-short-vendor-substring',
    description: 'A two-letter vendor such as `os` is not prose evidence inside `most`',
    tags: ['fallback', 'token-boundary', 'negative'],
    input: {
      assetVendor: 'os',
      assetProduct: 'widget',
      vulnTitle: 'Most widgets are patched',
      vulnDescription: 'Almost every widget ships with the fix.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-short-token-identity',
    description: 'An all-short identity is too ambiguous for prose matching',
    tags: ['fallback', 'token-boundary', 'negative'],
    input: {
      assetVendor: 'ai',
      assetProduct: 'go',
      vulnTitle: 'Maintain good practices',
      vulnDescription: 'Teams should maintain good operational practices.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-glued-words',
    description: 'Identity words must be whole tokens, not substrings of a longer word',
    tags: ['fallback', 'token-boundary', 'negative'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnTitle: 'Acmewidgetgadget release notes',
      vulnDescription: 'Unrelated product documentation.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-wrong-product-same-vendor',
    description: 'A shared vendor alone cannot correlate a different product',
    tags: ['strict', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'acme', product: 'widget', version: '1.0' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme', product: 'gadget', version: '*' })],
      vulnTitle: 'Acme Gadget vulnerability',
      vulnDescription: 'Acme Gadget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-generic-cpe-other-product',
    description: 'A generic inventory CPE cannot match an unrelated advisory product',
    tags: ['generic', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: '*', product: '*', version: '1.5' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'other', product: 'thing', version: '1.5' })],
      vulnTitle: 'Other Thing vulnerability',
      vulnDescription: 'Other Thing is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-wildcard-version-intersection',
    description: 'Non-overlapping wildcard version patterns do not intersect',
    tags: ['version', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '2.*' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.*' })],
      ...benignText,
    },
    expected: { matched: false },
  },
  {
    id: 'negative-unrelated-prose',
    description: 'Unrelated prose with no identity words never correlates',
    tags: ['fallback', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'other', product: 'thing', version: '*' })],
      vulnTitle: 'Quarterly newsletter',
      vulnDescription: 'Office hours and travel announcements.',
    },
    expected: { matched: false },
  },
];
