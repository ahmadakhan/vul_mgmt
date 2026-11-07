/**
 * CPE 2.3 Match Simulation Engine for the CPE Matcher View.
 *
 * This utility provides a single entry point — `runCpeSimulation` — that
 * parses an asset CPE and a vulnerability CPE, runs the strict matching
 * pipeline (alias expansion, version interval checks, false-positive
 * elimination), and returns a structured result suitable for display in the
 * Threat Analytics UI.
 *
 * All functions reuse the battle-tested primitives from `cpeMatcher.ts`
 * (parseCPE23, matchCPE, alias tables) and `versionComparator.ts`
 * (canCompareRange, isVersionInNvdRange).
 */

import {
  parseCPE23,
  matchCPE,
  matchVendorWithAliases,
  matchProductWithAliases,
  aliasGroupKeys,
  DEFAULT_VENDOR_ALIASES,
  DEFAULT_PRODUCT_ALIASES,
  generateCPE23,
  type ParsedCPE,
} from './cpeMatcher.ts';

import {
  canCompareRange,
  evaluateVersionInRange,
  type NvdVersionRange,
} from './versionComparator.ts';

import type {
  CpeMatchSimulation,
  CpeParseResult,
  CpeParseComponent,
  AliasExpansion,
  FalsePositiveCheck,
  SeverityClassification,
  SeverityTier,
} from '../types/index.ts';

/**
 * Splits a CPE 2.3 string into labelled components for display.
 * Returns the parsed CPE and any structural errors detected.
 */
export function buildCpeParseResult(cpeString: string): CpeParseResult {
  const parsed = parseCPE23(cpeString);
  const components: CpeParseComponent[] = [];
  const errors: string[] = [];

  if (!parsed.isValid) {
    errors.push('Invalid CPE 2.3 syntax');
    return {
      cpe: cpeString,
      parsed: null,
      components: [],
      errors,
    };
  }

  const componentFields = [
    { key: 'part', label: 'Part' },
    { key: 'vendor', label: 'Vendor' },
    { key: 'product', label: 'Product' },
    { key: 'version', label: 'Version' },
    { key: 'update', label: 'Update' },
    { key: 'edition', label: 'Edition' },
    { key: 'language', label: 'Language' },
    { key: 'swEdition', label: 'Sw Edition' },
    { key: 'targetSw', label: 'Target SW' },
    { key: 'targetHw', label: 'Target Hw' },
    { key: 'other', label: 'Other' },
  ] as const;

  for (const { key, label } of componentFields) {
    const value = parsed[key];
    const isWildcard = value === '*';
    const isAmbiguous = value === '-';
    components.push({
      field: label,
      value,
      isWildcard,
      isAmbiguous,
    });
  }

  return {
    cpe: parsed.raw,
    parsed: {
      prefix: parsed.prefix,
      part: parsed.part,
      vendor: parsed.vendor,
      product: parsed.product,
      version: parsed.version,
      update: parsed.update,
      edition: parsed.edition,
      language: parsed.language,
      swEdition: parsed.swEdition,
      targetSw: parsed.targetSw,
      targetHw: parsed.targetHw,
      other: parsed.other,
      raw: parsed.raw,
      isValid: true,
    },
    components,
    errors,
  };
}

/**
 * Builds alias expansion context for a vendor or product identity,
 * checking both built-in defaults and operator-managed custom aliases.
 */
function buildAliasExpansion(
  value: string,
  scope: 'VENDOR' | 'PRODUCT',
  customAliases: Record<string, string[]>,
): AliasExpansion | null {
  if (!value) return null;

  const base = scope === 'VENDOR' ? DEFAULT_VENDOR_ALIASES : DEFAULT_PRODUCT_ALIASES;
  const matchedAliases = aliasGroupKeys(value, base, customAliases);

  if (matchedAliases.length === 0) return null;

  return {
    canonical: matchedAliases[0] || value,
    scope,
    matchedAliases,
    builtInMatches: matchedAliases.some((alias) =>
      Object.keys(base).includes(alias) || base[alias.toLowerCase()]?.includes(value.toLowerCase()),
    ),
    customMatches: matchedAliases.some(
      (alias) =>
        Object.keys(customAliases).includes(alias.toLowerCase()) ||
        customAliases[alias.toLowerCase()]?.includes(value.toLowerCase()),
    ),
  };
}

/**
 * Determines whether the asset version falls within the vulnerability's
 * NVD version interval. Returns a structured check result.
 */
function checkVersionRange(
  assetVersion: string | undefined,
  versionRange: NvdVersionRange | undefined,
): { inRange: boolean; reason: string } | null {
  if (!versionRange || (!versionRange.versionStartIncluding && !versionRange.versionStartExcluding && !versionRange.versionEndIncluding && !versionRange.versionEndExcluding)) {
    return null;
  }

  if (!assetVersion || assetVersion === '*' || assetVersion === '-') {
    return {
      inRange: true,
      reason: 'Asset version is a wildcard — range check is inconclusive, requires review',
    };
  }

  if (!canCompareRange(assetVersion, versionRange)) {
    return {
      inRange: true,
      reason: `Version ordering is unsupported or vendor-ambiguous for "${assetVersion}"; applicability requires review`,
    };
  }

  const result = evaluateVersionInRange(assetVersion, versionRange);
  if (result.verdict === 'INCONCLUSIVE')
    return { inRange: true, reason: result.reason };
  return {
    inRange: result.verdict === 'IN_RANGE',
    reason: result.reason,
  };
}

/**
 * Runs a battery of false-positive elimination checks against the asset
 * and vulnerability CPEs. These checks implement the enterprise
 * false-positive rules that narrow a broad CPE match down to something
 * an operator can trust.
 */
function runFalsePositiveChecks(
  assetCpe: ParsedCPE,
  vulnCpe: ParsedCPE,
  versionInRange: boolean | null,
  versionRange: NvdVersionRange | undefined,
): FalsePositiveCheck[] {
  const checks: FalsePositiveCheck[] = [];

  if (!assetCpe.isValid || !vulnCpe.isValid) {
    checks.push({
      name: 'CPE Validity',
      passed: false,
      severity: 'BLOCK',
      detail: 'One or both CPE strings are invalid',
    });
    return checks;
  }

  // Check 1: Part must match (a=application, o=os, h=hardware)
  if (assetCpe.part !== '*' && vulnCpe.part !== '*' && assetCpe.part !== vulnCpe.part) {
    checks.push({
      name: 'Part Conflict',
      passed: false,
      severity: 'BLOCK',
      detail: `Asset part "${assetCpe.part}" conflicts with vulnerability part "${vulnCpe.part}"`,
    });
  } else {
    checks.push({
      name: 'Part Compatibility',
      passed: true,
      severity: 'WARN',
      detail: `Part "${assetCpe.part}" is compatible with "${vulnCpe.part}"`,
    });
  }

  // Check 2: Target OS / SW platform conflict
  if (
    assetCpe.targetSw !== '*' &&
    vulnCpe.targetSw !== '*' &&
    assetCpe.targetSw !== '-' &&
    vulnCpe.targetSw !== '-'
  ) {
    const match = assetCpe.targetSw === vulnCpe.targetSw;
    checks.push({
      name: 'Target OS/SW',
      passed: match,
      severity: 'BLOCK',
      detail: match
        ? `Target software "${assetCpe.targetSw}" matches`
        : `Target software "${assetCpe.targetSw}" does not match vulnerability "${vulnCpe.targetSw}"`,
    });
  } else {
    checks.push({
      name: 'Target OS/SW',
      passed: true,
      severity: 'WARN',
      detail: 'No platform constraint to evaluate',
    });
  }

  // Check 3: Architecture conflict
  if (
    assetCpe.targetHw !== '*' &&
    vulnCpe.targetHw !== '*' &&
    assetCpe.targetHw !== '-' &&
    vulnCpe.targetHw !== '-'
  ) {
    const match = assetCpe.targetHw === vulnCpe.targetHw;
    checks.push({
      name: 'Target Architecture',
      passed: match,
      severity: 'BLOCK',
      detail: match
        ? `Architecture "${assetCpe.targetHw}" matches`
        : `Architecture "${assetCpe.targetHw}" does not match vulnerability "${vulnCpe.targetHw}"`,
    });
  } else {
    checks.push({
      name: 'Target Architecture',
      passed: true,
      severity: 'WARN',
      detail: 'No architecture constraint to evaluate',
    });
  }

  // Check 4: Update / language conflict
  if (assetCpe.update !== '*' && vulnCpe.update !== '*' && assetCpe.update !== '-') {
    const match = assetCpe.update === vulnCpe.update;
    checks.push({
      name: 'Update Version',
      passed: match,
      severity: 'WARN',
      detail: match
        ? `Update "${assetCpe.update}" matches`
        : `Update "${assetCpe.update}" does not match "${vulnCpe.update}"`,
    });
  } else {
    checks.push({
      name: 'Update Version',
      passed: true,
      severity: 'WARN',
      detail: 'No update constraint to evaluate',
    });
  }

  if (assetCpe.language !== '*' && vulnCpe.language !== '*' && assetCpe.language !== '-') {
    const match = assetCpe.language === vulnCpe.language;
    checks.push({
      name: 'Language',
      passed: match,
      severity: 'WARN',
      detail: match ? `Language "${assetCpe.language}" matches` : `Language mismatch`,
    });
  }

  // Check 5: Version range evaluation
  if (versionRange && versionInRange === false) {
    checks.push({
      name: 'Version Range',
      passed: false,
      severity: 'BLOCK',
      detail: 'Asset version is outside the vulnerability range — exploit is patched',
    });
  } else if (versionRange) {
    checks.push({
      name: 'Version Range',
      passed: true,
      severity: 'WARN',
      detail: 'Asset version is within the vulnerability range or cannot be compared',
    });
  }

  // Check 6: Generic vendor/product is suspicious
  if (assetCpe.vendor === '*' || assetCpe.product === '*') {
    checks.push({
      name: 'Generic Identity',
      passed: false,
      severity: 'WARN',
      detail: 'Asset CPE has a wildcard vendor or product — match may be overly broad',
    });
  }

  return checks;
}

/**
 * Produces a severity classification from CPE-level heuristics when no
 * CVSS score is available. When the match is exact and confident, the
 * severity is elevated; when it relies on aliases or has review flags,
 * the severity is dampened.
 */
function classifySeverity(
  matchResult: { matched: boolean; viaAlias?: boolean; reason?: string },
  versionRange: NvdVersionRange | undefined,
  versionCheck: { inRange: boolean; reason: string } | null,
  falsePositiveChecks: FalsePositiveCheck[],
  confidence: number,
): SeverityClassification | null {
  if (!matchResult.matched) {
    return {
      tier: 'INFORMATIONAL',
      score: 0,
      vector: '',
      source: 'CPE_SIMULATION',
      rationale: ['No match was found between the asset and vulnerability CPEs'],
    };
  }

  const hasBlock = falsePositiveChecks.some((c) => !c.passed && c.severity === 'BLOCK');

  if (hasBlock) {
    return {
      tier: 'INFORMATIONAL',
      score: 0,
      vector: '',
      source: 'CPE_SIMULATION',
      rationale: [
        'A blocking false-positive check failed — the vulnerability does not apply to this asset',
      ],
    };
  }

  let tier: SeverityTier = 'INFORMATIONAL';
  if (confidence >= 95) tier = 'HIGH';
  else if (confidence >= 85) tier = 'MEDIUM';
  else if (confidence >= 75) tier = 'LOW';
  else tier = 'INFORMATIONAL';

  const rationale: string[] = [];

  if (matchResult.viaAlias) rationale.push('Matched through the enterprise alias thesaurus');
  else rationale.push('Exact vendor/product component match');

  if (versionRange && versionCheck) {
    if (versionCheck.inRange) {
      rationale.push(`Asset version is within the advisory range: ${versionCheck.reason}`);
    } else {
      rationale.push(`Asset version is outside the advisory range: ${versionCheck.reason}`);
    }
  }

  const reviewFlags = falsePositiveChecks.filter((c) => c.severity === 'WARN');
  if (reviewFlags.length > 0 && !reviewFlags.every((c) => c.passed)) {
    tier = downgradeTier(tier);
    rationale.push(
      `${reviewFlags.filter((c) => !c.passed).length} warning check(s) require manual review`,
    );
  }

  const score = tierToScore(tier);
  return {
    tier,
    score,
    vector: '',
    source: 'CPE_SIMULATION',
    rationale,
  };
}

function downgradeTier(tier: SeverityTier): SeverityTier {
  const order: SeverityTier[] = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const idx = order.indexOf(tier);
  return idx > 0 ? order[idx - 1] : tier;
}

function tierToScore(tier: SeverityTier): number {
  const scores: Record<SeverityTier, number> = {
    CRITICAL: 9.5,
    HIGH: 8.0,
    MEDIUM: 6.0,
    LOW: 3.0,
    INFORMATIONAL: 0.5,
  };
  return scores[tier];
}

/**
 * Runs the full CPE 2.3 match simulation for display in the
 * CPE Matcher View.
 *
 * This performs the same structural matching the correlation engine uses
 * (parse → resolve generic identity → match components → alias thesaurus
 * → version interval) but without any CVSS/EPSS/KEV enrichment, since the
 * simulation works from the two CPEs only.
 *
 * @param assetCpeStr    - The asset's CPE 2.3 string.
 * @param vulnCpeStr     - The vulnerability's CPE 2.3 target string.
 * @param assetVendor    - The inventory's vendor field (used to resolve generic CPEs).
 * @param assetProduct   - The inventory's product field (used to resolve generic CPEs).
 * @param customVendorAliases - Operator-managed vendor aliases from the DB.
 * @param customProductAliases - Operator-managed product aliases from the DB.
 * @param versionRange   - Optional NVD version interval from the vulnerability.
 * @param assetVersion   - The asset's deployed version string.
 */
export function runCpeSimulation(
  assetCpeStr: string,
  vulnCpeStr: string,
  assetVendor: string,
  assetProduct: string,
  customVendorAliases: Record<string, string[]> = {},
  customProductAliases: Record<string, string[]> = {},
  versionRange?: NvdVersionRange,
  assetVersion?: string,
): CpeMatchSimulation {
  const aliases = {
    vendorAliases: customVendorAliases,
    productAliases: customProductAliases,
  };

  const assetParsed = parseCPE23(assetCpeStr);
  const vulnParsed = parseCPE23(vulnCpeStr);

  const assetCpeResult = buildCpeParseResult(assetCpeStr);
  const vulnerabilityCpeResult = buildCpeParseResult(vulnCpeStr);

  let errors: string[] = [];

  if (!assetParsed.isValid) errors.push('Asset CPE is not valid CPE 2.3');
  if (!vulnParsed.isValid) errors.push('Vulnerability CPE is not valid CPE 2.3');

  // Build alias expansion context from the inventory's vendor/product
  const assetVendorAlias = buildAliasExpansion(assetVendor, 'VENDOR', customVendorAliases);
  const assetProductAlias = buildAliasExpansion(assetProduct, 'PRODUCT', customProductAliases);

  // Version range check
  const versionCheck = checkVersionRange(assetVersion, versionRange);
  const versionInRange = versionCheck ? versionCheck.inRange : null;

  // Run the match
  let matchResult: { matched: boolean; viaAlias?: boolean; reason?: string };
  if (assetParsed.isValid && vulnParsed.isValid) {
    matchResult = matchCPE(assetCpeStr, vulnCpeStr, versionRange, aliases);
  } else {
    matchResult = {
      matched: false,
      reason: 'Invalid CPE syntax prevents matching',
    };
  }

  // Compute confidence
  let confidence = 50; // base for a structural match
  if (matchResult.matched) {
    if (matchResult.viaAlias) {
      confidence = 85;
    } else {
      // Check if any component uses wildcards
      const hasWildcards =
        assetParsed.vendor === '*' ||
        assetParsed.product === '*' ||
        vulnParsed.vendor === '*' ||
        vulnParsed.product === '*';
      if (hasWildcards) {
        confidence = 70;
      } else {
        confidence = 90;
      }
      if (versionRange && versionInRange === true) confidence = Math.min(100, confidence + 5);
    }
  } else {
    confidence = 0;
  }
  confidence = Math.max(-9, Math.min(100, confidence));

  const fpChecks: FalsePositiveCheck[] = [];
  if (!assetParsed.isValid || !vulnParsed.isValid) {
    fpChecks.push({
      name: 'CPE Validity',
      passed: false,
      severity: 'BLOCK',
      detail: 'One or both CPE strings are not valid CPE 2.3',
    });
  } else {
    fpChecks.push(...runFalsePositiveChecks(assetParsed, vulnParsed, versionInRange, versionRange));
  }

  const hasBlock = fpChecks.some((c) => !c.passed && c.severity === 'BLOCK');
  if (hasBlock && matchResult.matched) {
    matchResult = {
      matched: false,
      reason: 'False-positive elimination blocked the match',
    };
    confidence = 0;
  }

  // Severity classification
  const severity = classifySeverity(
    matchResult,
    versionRange,
    versionCheck,
    fpChecks,
    confidence,
  );

  // Build the match result for display
  const matchEvidence = matchResult.matched
    ? matchResult.viaAlias
      ? `Matched structured CPE through the symmetric alias thesaurus (${assetParsed.vendor}/${assetParsed.product} -> ${vulnParsed.vendor}/${vulnParsed.product})`
      : `Matched strict CPE 2.3 component tokens (${assetParsed.vendor}/${assetParsed.product} vs ${vulnParsed.vendor}/${vulnParsed.product})`
    : matchResult.reason || 'No component or keyword correlation';

  return {
    assetCpe: assetCpeResult,
    vulnerabilityCpe: vulnerabilityCpeResult,
    assetVendorAlias,
    assetProductAlias,
    match: {
      matched: matchResult.matched,
      method: matchResult.matched ? (matchResult.viaAlias ? 'VENDOR_PRODUCT_ALIAS' : 'STRICT_CPE') : 'NONE',
      confidence,
      viaAlias: !!matchResult.viaAlias,
      evidence: matchEvidence,
      reason: matchResult.reason,
    },
    versionRangeCheck: versionCheck,
    falsePositiveChecks: fpChecks,
    severity,
  };
}

/**
 * Generates CPE 2.3 prefixes for a vendor/product pair across all parts (a, o, h).
 * Used by the threat intelligence search to construct NVD `cpeName` queries.
 */
export function generateCpePrefixes(vendor: string, product: string): string[] {
  return (['a', 'o', 'h'] as const).map((part) =>
    generateCPE23(part, vendor, product),
  );
}
