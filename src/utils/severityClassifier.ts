import type { SeverityClassification, SeverityTier, NormalizedCVE } from '../types/index.ts';
import type { NvdVersionRange } from './versionComparator.ts';

const EXPLOIT_STATUS_WEIGHT: Record<string, number> = {
  'Active Weaponized': 40,
  'Reported In Wild': 30,
  'POC Available': 20,
  None: 0,
};

const CISA_KEV_WEIGHT = 15;
const EPSS_HIGH_THRESHOLD = 0.4;
const EPSS_HIGH_WEIGHT = 10;
const CWE_INJECTION_WEIGHT = 12;
const CWE_OVERFLOW_WEIGHT = 10;
const CWE_PRIVESC_WEIGHT = 8;

const CWE_HIGH_RISK: Record<string, string[]> = {
  'CWE-77': ['CWE-78', 'CWE-77'],
  'CWE-78': ['CWE-78'],
  'CWE-787': ['CWE-787'],
  'CWE-125': ['CWE-125', 'CWE-787'],
  'CWE-862': ['CWE-862', 'CWE-269'],
  'CWE-269': ['CWE-269'],
  'CWE-352': ['CWE-352'],
  'CWE-89': ['CWE-89'],
  'CWE-22': ['CWE-22'],
  'CWE-502': ['CWE-915', 'CWE-502'],
  'CWE-416': ['CWE-416'],
};

const CWE_MEDIUM_RISK = [
  'CWE-74', 'CWE-20', 'CWE-120', 'CWE-119', 'CWE-121', 'CWE-122',
  'CWE-400', 'CWE-611', 'CWE-284', 'CWE-287', 'CWE-384', 'CWE-835',
];

export function classifySeverity(cve: Partial<NormalizedCVE>): SeverityClassification {
  const rationale: string[] = [];
  let score = 0;
  let source = 'CVSS';

  const cvssScore = cve.cvss?.score ?? 0;
  const cvssSeverity = cve.cvss?.severity ?? 'UNKNOWN';
  const vector = cve.cvss?.vector ?? '';

  score += cvssScore * 0.6;
  if (cvssScore > 0) {
    rationale.push(`CVSS base score ${cvssScore.toFixed(1)} (${cvssSeverity})`);
  }

  const exploitWeight = EXPLOIT_STATUS_WEIGHT[cve.exploitStatus || 'None'] || 0;
  score += exploitWeight;
  if (exploitWeight > 0) {
    rationale.push(`Exploit status "${cve.exploitStatus}" adds ${exploitWeight} points`);
    source = 'CVSS + exploit status';
  }

  if (cve.cisaKev?.isKev) {
    score += CISA_KEV_WEIGHT;
    rationale.push('CISA KEV catalog adds 15 points');
    source = 'CVSS + exploit + CISA KEV';
  }

  if (cve.epss && cve.epss.score >= EPSS_HIGH_THRESHOLD) {
    score += EPSS_HIGH_WEIGHT;
    rationale.push(`EPSS score ${(cve.epss.score * 100).toFixed(1)}% adds 10 points`);
    source = 'CVSS + exploit + CISA KEV + EPSS';
  }

  const cweList = cve.cwe || [];
  let maxCweWeight = 0;
  const highRiskCwes = cweList.filter((cwe) => (CWE_HIGH_RISK[cwe] || CWE_MEDIUM_RISK.includes(cwe)));
  for (const cwe of cweList) {
    if (CWE_HIGH_RISK[cwe]) {
      const weight = cwe === 'CWE-787' || cwe === 'CWE-125' ? CWE_INJECTION_WEIGHT : CWE_OVERFLOW_WEIGHT;
      score += weight;
      maxCweWeight = Math.max(maxCweWeight, weight);
      rationale.push(`CWE ${cwe} adds ${weight} points`);
    } else if (CWE_MEDIUM_RISK.includes(cwe)) {
      score += 5;
      maxCweWeight = Math.max(maxCweWeight, 5);
      rationale.push(`CWE ${cwe} adds 5 points`);
    }
  }

  if (maxCweWeight >= CWE_INJECTION_WEIGHT) {
    source = 'CVSS + exploit + CISA KEV + CWE';
  }

  const tier = classifyTier(score, cvssSeverity);

  if (vector) {
    rationale.push(`CVSS vector: ${vector}`);
  }

  return {
    tier,
    score: Math.round(score * 10) / 10,
    vector,
    source,
    rationale,
  };
}

function classifyTier(score: number, cvssSeverity: string): SeverityTier {
  if (score >= 90 || cvssSeverity === 'CRITICAL') return 'CRITICAL';
  if (score >= 70 || cvssSeverity === 'HIGH') return 'HIGH';
  if (score >= 40 || cvssSeverity === 'MEDIUM') return 'MEDIUM';
  if (score >= 10 || cvssSeverity === 'LOW') return 'LOW';
  return 'INFORMATIONAL';
}

export function checkVersionRangeCompatibility(
  assetVersion: string | undefined,
  range: NvdVersionRange | undefined,
): { inRange: boolean; reason: string } | null {
  if (!range || !Object.values(range).some(Boolean)) {
    return null;
  }

  const startIncl = range.versionStartIncluding;
  const startExcl = range.versionStartExcluding;
  const endIncl = range.versionEndIncluding;
  const endExcl = range.versionEndExcluding;

  if (!assetVersion) {
    return {
      inRange: false,
      reason: 'No asset version available; version range applicability requires review',
    };
  }

  const assetParts = assetVersion.toLowerCase().split('.');
  const versionCompare = (v1: string, v2: string): number => {
    const p1 = v1.toLowerCase().split('.');
    const p2 = v2.toLowerCase().split('.');
    const maxLen = Math.max(p1.length, p2.length);
    for (let i = 0; i < maxLen; i++) {
      const a = parseInt(p1[i] || '0', 10);
      const b = parseInt(p2[i] || '0', 10);
      if (a !== b) return a - b;
    }
    return 0;
  };

  if (startIncl && versionCompare(assetVersion, startIncl) < 0) {
    return {
      inRange: false,
      reason: `Asset version ${assetVersion} is below the vulnerability range start (>= ${startIncl})`,
    };
  }

  if (startExcl && versionCompare(assetVersion, startExcl) <= 0) {
    return {
      inRange: false,
      reason: `Asset version ${assetVersion} is at or below the exclusive range start (> ${startExcl})`,
    };
  }

  if (endExcl && versionCompare(assetVersion, endExcl) >= 0) {
    return {
      inRange: false,
      reason: `Asset version ${assetVersion} is at or above the exclusive range end (< ${endExcl})`,
    };
  }

  if (endIncl && versionCompare(assetVersion, endIncl) > 0) {
    return {
      inRange: false,
      reason: `Asset version ${assetVersion} is above the inclusive range end (<= ${endIncl})`,
    };
  }

  const bounds = [startIncl, startExcl, endIncl, endExcl].filter(Boolean);
  return {
    inRange: true,
    reason: `Asset version ${assetVersion} is within the vulnerability range (${bounds.join(', ')})`,
  };
}
