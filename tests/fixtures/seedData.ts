import {
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  AlertedCVE,
  EmailRecipient,
  EmailDeliveryLog,
  AuditLog,
  AppSettings,
  WebhookEndpoint,
  WebhookDeliveryLog,
} from '../../src/types/index.ts';
import { quickHash } from '../../src/utils/cryptoChain.ts';
import { RECOMMENDED_FEEDS } from '../../server/recommendedFeeds.ts';

const SEEDED_FEEDS: ThreatFeed[] = [
  {
    id: 'feed-msrc',
    name: 'Microsoft Security Response Center (MSRC)',
    type: 'JSON_SEARCH_API',
    url: 'https://api.msrc.microsoft.com/cvrf/v2.0/updates',
    authType: 'NONE',
    rateLimitPerMin: 120,
    enabled: false,
    healthStatus: 'HEALTHY',
    lastSync: '2026-10-19T22:30:00.000Z',
    latencyMs: 142,
    vendorSeed: true,
    itemCountLastRun: 28,
    ssrfValidated: true,
  },
  {
    id: 'feed-paloalto',
    name: 'Palo Alto Networks Unit 42 Advisory Feed',
    type: 'JSON_SEARCH_API',
    url: 'https://security.paloaltonetworks.com/api/v1/advisories',
    authType: 'NONE',
    rateLimitPerMin: 100,
    enabled: false,
    healthStatus: 'HEALTHY',
    lastSync: '2026-10-19T22:45:00.000Z',
    latencyMs: 115,
    vendorSeed: true,
    itemCountLastRun: 16,
    ssrfValidated: true,
  },
  {
    id: 'feed-cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities (KEV) Catalog',
    type: 'CISA_KEV',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    authType: 'NONE',
    rateLimitPerMin: 120,
    enabled: true,
    healthStatus: 'HEALTHY',
    lastSync: '2026-10-19T23:00:00.000Z',
    latencyMs: 82,
    vendorSeed: true,
    itemCountLastRun: 45,
    ssrfValidated: true,
  },
  {
    id: 'feed-nvd',
    name: 'NVD CVE 2.0 Batch Enrichment API',
    type: 'NVD_API',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    authType: 'NONE',
    rateLimitPerMin: 10,
    enabled: true,
    healthStatus: 'HEALTHY',
    lastSync: '2026-10-19T23:10:00.000Z',
    latencyMs: 190,
    vendorSeed: true,
    itemCountLastRun: 120,
    ssrfValidated: true,
  },
  {
    id: 'feed-epss',
    name: 'FIRST.org Exploit Prediction Scoring System (EPSS)',
    type: 'EPSS_API',
    url: 'https://api.first.org/data/v1/epss',
    authType: 'NONE',
    rateLimitPerMin: 240,
    enabled: true,
    healthStatus: 'HEALTHY',
    lastSync: '2026-10-19T23:12:00.000Z',
    latencyMs: 110,
    vendorSeed: true,
    itemCountLastRun: 250,
    ssrfValidated: true,
  },
  {
    id: 'feed-wordpress-security',
    name: 'WordPress Security Advisories',
    type: 'RSS_ATOM',
    url: 'https://wordpress.org/security/feed/',
    authType: 'NONE',
    rateLimitPerMin: 5,
    enabled: false,
    healthStatus: 'HEALTHY',
    lastSync: '2026-10-20T01:30:00.000Z',
    latencyMs: 88,
    vendorSeed: true,
    itemCountLastRun: 7,
    ssrfValidated: true,
  },
];

/**
 * Fixture feeds plus the recommended catalog, exactly as `scripts/seed.ts`
 * receives it. Spreading RECOMMENDED_FEEDS here keeps the fixture from
 * carrying a second, silently stale copy of the default feed URLs: when a
 * publisher moves its feed, only recommendedFeeds.ts changes.
 *
 * The runtime catalog is deliberately not imported by any server module (the
 * seed imports it at build time), and the production build does not resolve a
 * file imported only through a type re-export in seedData.ts. So the fixture
 * cannot be the thing that keeps this list out of the shipped image.
 */
export const INITIAL_FEEDS: ThreatFeed[] = [
  ...SEEDED_FEEDS,
  ...RECOMMENDED_FEEDS.map((feed): ThreatFeed => ({
    ...feed,
    healthStatus: 'UNTESTED',
    lastSync: null,
    latencyMs: 0,
    itemCountLastRun: 0,
    ssrfValidated: false,
  })),
];

export const INITIAL_WATCHLIST: WatchListItem[] = [
  {
    id: 'asset-fw-01',
    vendor: 'paloaltonetworks',
    product: 'pan-os',
    version: '10.2.8',
    targetHw: 'x86_64',
    cpes: [
      'cpe:2.3:o:paloaltonetworks:pan-os:10.2.8:*:*:*:*:*:x86_64:*',
      'cpe:2.3:o:paloaltonetworks:pan-os:10.2:*:*:*:*:*:*:*',
    ],
    exposure: 'INTERNET_FACING',
    assetTag: 'EDGE-FW-HQ-PRIMARY',
    ownerGroup: 'SecOps-Perimeter',
    active: true,
    notes: 'Primary corporate edge gateway and GlobalProtect portal (Deployed: v10.2.8)',
    createdAt: '2026-09-01T08:00:00Z',
  },
  {
    id: 'asset-vpn-01',
    vendor: 'fortinet',
    product: 'fortios',
    version: '7.2.4',
    targetHw: 'x86_64',
    cpes: [
      'cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:x86_64:*',
    ],
    exposure: 'INTERNET_FACING',
    assetTag: 'VPN-GATEWAY-EAST',
    ownerGroup: 'NetOps-Infra',
    active: true,
    notes: 'Secondary SSL-VPN concentrator for remote engineering',
    createdAt: '2026-09-05T09:30:00Z',
  },
  {
    id: 'asset-win-dc',
    vendor: 'microsoft',
    product: 'windows_server_2022',
    version: '21H2',
    targetHw: 'x86_64',
    cpes: [
      'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:x86_64:*',
      'cpe:2.3:a:microsoft:remote_desktop_services:*:*:*:*:*:*:*:*',
    ],
    exposure: 'INTERNAL_CRITICAL',
    assetTag: 'DC-CORP-PDC01',
    ownerGroup: 'SysOps-Identity',
    active: true,
    notes: 'Active Directory Root Controller and RDS licensing host',
    createdAt: '2026-08-15T10:00:00Z',
  },
  {
    id: 'asset-cisco-core',
    vendor: 'cisco',
    product: 'adaptive_security_appliance_software',
    version: '9.18.2',
    cpes: [
      'cpe:2.3:a:cisco:adaptive_security_appliance_software:9.18.2:*:*:*:*:*:*:*',
    ],
    exposure: 'DMZ',
    assetTag: 'DMZ-ASA-CLUSTER-A',
    ownerGroup: 'SecOps-Perimeter',
    active: true,
    notes: 'DMZ routing and security inspection cluster',
    createdAt: '2026-08-20T11:00:00Z',
  },
  {
    id: 'asset-vmw-esxi',
    vendor: 'vmware',
    product: 'esxi',
    version: '8.0.2',
    cpes: [
      'cpe:2.3:o:vmware:esxi:8.0.2:*:*:*:*:*:*:*',
    ],
    exposure: 'INTERNAL_CRITICAL',
    assetTag: 'HV-CLUSTER-PROD-01',
    ownerGroup: 'CloudOps-Virtualization',
    active: true,
    notes: 'Production VMware vSphere compute hypervisors',
    createdAt: '2026-07-10T14:00:00Z',
  },
  {
    id: 'asset-ssh-bastion',
    vendor: 'openbsd',
    product: 'openssh',
    version: '9.2p1',
    purls: ['pkg:deb/debian/openssh-server@1:9.2p1-2+deb12u2?arch=amd64'],
    cpes: [
      'cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*',
    ],
    exposure: 'INTERNET_FACING',
    assetTag: 'BASTION-JUMP-PUBLIC',
    ownerGroup: 'DevSecOps',
    active: true,
    notes: 'Public SSH jump host protected by Duo MFA',
    createdAt: '2026-08-01T12:00:00Z',
  },
  {
    id: 'asset-wp-01',
    vendor: 'wordpress',
    product: 'wordpress',
    version: '6.4.3',
    purls: ['pkg:composer/wordpress/wordpress@6.4.3'],
    cpes: [
      'cpe:2.3:a:wordpress:wordpress:6.4.3:*:*:*:*:*:*:*',
    ],
    exposure: 'INTERNET_FACING',
    assetTag: 'CMS-WP-CORP-BLOG',
    ownerGroup: 'Digital-Experience',
    active: true,
    notes: 'Corporate WordPress blog and content management system running on PHP 8.2',
    createdAt: '2026-09-10T09:15:00Z',
  },
  {
    id: 'asset-debian-web',
    vendor: 'debian',
    product: 'debian_linux',
    version: '12.5',
    purls: ['pkg:deb/debian/openssh-server@1:9.2p1-2+deb12u2?arch=amd64'],
    cpes: [
      'cpe:2.3:o:debian:debian_linux:12.5:*:*:*:*:*:*:*',
    ],
    exposure: 'DMZ',
    assetTag: 'WEB-APP-01',
    ownerGroup: 'AppOps-Web',
    active: true,
    notes: 'Debian 12 bookworm web application server hosting internal customer portal',
    createdAt: '2026-07-22T10:45:00Z',
  },
];

export const INITIAL_NORMALIZED_CVES: NormalizedCVE[] = [
  {
    cveId: 'CVE-2024-3400',
    title: 'Palo Alto Networks PAN-OS GlobalProtect Command Injection Vulnerability',
    description: 'A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.',
    publishedDate: '2026-10-18T14:30:00Z',
    modifiedDate: '2026-10-19T21:45:00Z',
    cvss: {
      version: '3.1',
      score: 10.0,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      severity: 'CRITICAL',
    },
    cwe: ['CWE-77', 'CWE-78'],
    cpeMatches: [
      'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*',
    ],
    versionRange: {
      versionStartIncluding: '10.2.0',
      versionEndExcluding: '10.2.9-h1', // Evaluates interval [10.2.0, 10.2.9-h1)
    },
    vex: {
      status: 'affected',
      impactStatement: 'Exploitable via unauthenticated GlobalProtect portal HTTP cookie',
    },
    sourceFeeds: ['CISA KEV', 'NVD', 'Palo Alto Networks Unit 42', 'CSAF VEX'],
    epss: {
      score: 0.97341,
      percentile: 99.9,
    },
    cisaKev: {
      isKev: true,
      dateAdded: '2026-10-18',
      dueDate: '2026-10-21',
      requiredAction: 'Apply vendor hotfixes immediately per PAN-SA-2024-0015 or disable device telemetry.',
      knownRansomwareCampaignUse: 'Known',
    },
    exploitStatus: 'Active Weaponized',
    remediation: {
      patchUrl: 'https://security.paloaltonetworks.com/CVE-2024-3400',
      vendorAdvisoryRef: 'PAN-SA-2024-0015',
      immediateActions: [
        'Disable Device Telemetry on all active PAN-OS firewalls (Device > Setup > Telemetry).',
        'Inspect session logs for outbound curl/bash requests originated from management plane.',
      ],
      workarounds: [
        'Restrict GlobalProtect portal access exclusively to sanctioned source IP ranges.',
      ],
      rollbackPlan: 'Restore configuration snapshot from pre-patch XML backup.',
      stepByStep: [
        'set deviceconfig system device-telemetry opt-out yes',
        'commit force',
        'request system software download version 10.2.9-h1',
        'request system software install version 10.2.9-h1',
      ],
    },
  },
  {
    cveId: 'CVE-2024-21762',
    title: 'Fortinet FortiOS Out-of-bounds Write in sslvpn Daemon',
    description: 'An out-of-bounds write vulnerability [CWE-787] in Fortinet FortiOS allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.',
    publishedDate: '2026-10-17T18:00:00Z',
    modifiedDate: '2026-10-19T20:15:00Z',
    cvss: {
      version: '3.1',
      score: 9.8,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      severity: 'CRITICAL',
    },
    cwe: ['CWE-787'],
    cpeMatches: [
      'cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*',
    ],
    versionRange: {
      versionStartIncluding: '7.2.0',
      versionEndExcluding: '7.2.7', // Target v7.2.4 is within range
    },
    vex: {
      status: 'affected',
      impactStatement: 'Unauthenticated RCE in sslvpnd daemon',
    },
    sourceFeeds: ['CISA KEV', 'NVD', 'Fortinet PSIRT', 'EPSS'],
    epss: {
      score: 0.96820,
      percentile: 99.8,
    },
    cisaKev: {
      isKev: true,
      dateAdded: '2026-10-17',
      dueDate: '2026-10-20',
      requiredAction: 'Upgrade to FortiOS 7.4.3+ or disable SSL-VPN interface immediately.',
      knownRansomwareCampaignUse: 'Known',
    },
    exploitStatus: 'Active Weaponized',
    remediation: {
      patchUrl: 'https://www.fortiguard.com/psirt/FG-IR-24-015',
      vendorAdvisoryRef: 'FG-IR-24-015',
      immediateActions: [
        'Disable SSL-VPN feature completely: config vpn ssl settings -> set status disable.',
      ],
      workarounds: [
        'Migrate remote users to IPsec VPN tunnels with certificate-based authentication.',
      ],
      rollbackPlan: 'Verify dual firmware partition and boot previous partition in BIOS menu.',
      stepByStep: [
        'execute backup config tftp backup-pre-patch.conf <TFTP_IP>',
        'execute restore image tftp FGT_VM64-v7.2.7.F-build2573.out <TFTP_IP>',
      ],
    },
  },
  {
    cveId: 'CVE-2024-6387',
    title: 'regreSSHion: Remote Unauthenticated Code Execution in OpenSSH server (sshd)',
    description: 'A signal handler race condition vulnerability in OpenSSH sshd allows unauthenticated remote code execution as root on glibc-based Linux systems.',
    publishedDate: '2026-10-15T06:00:00Z',
    modifiedDate: '2026-10-19T14:20:00Z',
    cvss: {
      version: '3.1',
      score: 8.1,
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      severity: 'HIGH',
    },
    cwe: ['CWE-362', 'CWE-364'],
    cpeMatches: [
      'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*',
    ],
    purls: ['pkg:deb/debian/openssh-server'],
    versionRange: {
      versionStartIncluding: '8.5p1',
      versionEndExcluding: '9.8p1', // Target 9.2p1 is vulnerable
    },
    vex: {
      status: 'affected',
      impactStatement: 'glibc SIGALRM race condition vulnerability',
    },
    sourceFeeds: ['GHSA', 'NVD', 'Red Hat Security Data', 'CSAF VEX'],
    epss: {
      score: 0.74100,
      percentile: 97.2,
    },
    cisaKev: {
      isKev: false,
    },
    exploitStatus: 'POC Available',
    remediation: {
      patchUrl: 'https://www.openssh.com/txt/release-9.8',
      vendorAdvisoryRef: 'OSSH-ADV-9.8P1',
      immediateActions: [
        'Set LoginGraceTime 0 in /etc/ssh/sshd_config.',
        'Reload daemon: systemctl reload sshd',
      ],
      workarounds: [
        'Enforce IP allowlisting on port 22 at perimeter firewall.',
      ],
      rollbackPlan: 'Revert LoginGraceTime back to 120 and reload sshd.',
      stepByStep: [
        'sed -i "s/#LoginGraceTime.*/LoginGraceTime 0/" /etc/ssh/sshd_config',
        'systemctl reload sshd.service',
      ],
    },
  },
  {
    cveId: 'CVE-2024-99999',
    title: 'Suppressed Demo: Linux Kernel BPF Subsystem VEX Non-Affected Statement',
    description: 'Demonstrates automated CSAF 2.0 VEX suppression: Vendor confirmed BPF subsystem disabled in production profile.',
    publishedDate: '2026-10-18T10:00:00Z',
    modifiedDate: '2026-10-19T10:00:00Z',
    cvss: {
      version: '3.1',
      score: 7.8,
      vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
      severity: 'HIGH',
    },
    cwe: ['CWE-20'],
    cpeMatches: ['cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*'],
    vex: {
      status: 'not_affected',
      justification: 'component_not_present',
      impactStatement: 'Kernel built with CONFIG_BPF_SYSCALL=n in enterprise profile. Zero impact.',
    },
    sourceFeeds: ['CSAF VEX', 'Red Hat PSIRT'],
    epss: { score: 0.02, percentile: 20 },
    cisaKev: { isKev: false },
    exploitStatus: 'None',
    remediation: {
      patchUrl: 'https://access.redhat.com/security/cve/CVE-2024-99999',
      vendorAdvisoryRef: 'RHSA-VEX-999',
      immediateActions: ['No action required. Confirmed suppressed by vendor VEX statement.'],
      workarounds: [],
      rollbackPlan: 'N/A',
      stepByStep: [],
    },
  },
];

export const INITIAL_FINDINGS: Finding[] = [
  {
    id: 'fnd-001',
    cveId: 'CVE-2024-3400',
    cve: INITIAL_NORMALIZED_CVES[0],
    matchedAssetId: 'asset-fw-01',
    matchedAssetName: 'EDGE-FW-HQ-PRIMARY (PAN-OS GlobalProtect)',
    matchedCpe: 'cpe:2.3:o:paloaltonetworks:pan-os:10.2.8:*:*:*:*:*:x86_64:*',
    matchingMethod: 'STRICT_CPE_INTERVAL',
    matchingEvidence: 'Asset v10.2.8 is within interval [10.2.0, 10.2.9-h1)',
    exposure: 'INTERNET_FACING',
    exploitRisk: 'CISA_KEV_EXPLOITED',
    notificationStatus: 'AUTO_DISPATCHED',
    status: 'REMEDIATION_AVAILABLE',
    autoDispatchedAt: '2026-10-19T21:00:00Z',
    advisoryId: 'ADV-2026-0841',
    reviewNotifiedAt: null,
    timeline: [
      {
        timestamp: '2026-10-19T20:45:00Z',
        action: 'Ingested & Correlated via SemVer Interval',
        system: 'Autonomous Ingestion Engine',
        details: 'Evaluated asset version 10.2.8 strictly within vulnerable interval [< 10.2.9-h1].',
      },
      {
        timestamp: '2026-10-19T21:00:00Z',
        action: 'Autonomous Notification Dispatched',
        system: 'Zero-Human Outbox',
        details: 'Dispatched to Email distribution list and signed Webhook channels with HMAC signature.',
      },
    ],
  },
  {
    id: 'fnd-002',
    cveId: 'CVE-2024-21762',
    cve: INITIAL_NORMALIZED_CVES[1],
    matchedAssetId: 'asset-vpn-01',
    matchedAssetName: 'VPN-GATEWAY-EAST (FortiOS SSL-VPN)',
    matchedCpe: 'cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:x86_64:*',
    matchingMethod: 'STRICT_CPE_INTERVAL',
    matchingEvidence: 'Asset v7.2.4 is within interval [7.2.0, 7.2.7)',
    exposure: 'INTERNET_FACING',
    exploitRisk: 'CISA_KEV_EXPLOITED',
    notificationStatus: 'AUTO_DISPATCHED',
    status: 'REMEDIATION_AVAILABLE',
    autoDispatchedAt: '2026-10-19T17:00:00Z',
    advisoryId: 'ADV-2026-0839',
    reviewNotifiedAt: null,
    timeline: [
      {
        timestamp: '2026-10-19T17:00:00Z',
        action: 'Autonomous Notification Dispatched',
        system: 'Zero-Human Outbox',
        details: 'CISA KEV active exploit detected. Notification transmitted without human gate.',
      },
    ],
  },
  {
    id: 'fnd-004',
    cveId: 'CVE-2024-6387',
    cve: INITIAL_NORMALIZED_CVES[2],
    matchedAssetId: 'asset-ssh-bastion',
    matchedAssetName: 'BASTION-JUMP-PUBLIC (OpenSSH Linux)',
    matchedCpe: 'cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*',
    matchingMethod: 'PURL_EXACT',
    matchingEvidence: 'Matched Debian package pkg:deb/debian/openssh-server and version 9.2p1 in range [< 9.8p1]',
    exposure: 'INTERNET_FACING',
    exploitRisk: 'HIGH_EPSS_PROBABILITY',
    notificationStatus: 'AUTO_DISPATCHED',
    status: 'RESOLVED',
    autoDispatchedAt: '2026-10-19T18:00:00Z',
    advisoryId: 'ADV-2026-0840',
    reviewNotifiedAt: null,
    timeline: [
      {
        timestamp: '2026-10-19T18:00:00Z',
        action: 'Autonomous Notification Dispatched',
        system: 'Zero-Human Outbox',
        details: 'Delivered via SendGrid and Slack webhook #sec-devops.',
      },
    ],
  },
];

export const INITIAL_ADVISORIES: Advisory[] = [
  {
    id: 'ADV-2026-0841',
    title: 'Palo Alto Networks PAN-OS GlobalProtect Command Injection',
    severity: 'CRITICAL',
    cveIds: ['CVE-2024-3400'],
    findingIds: ['fnd-001'],
    createdDate: '2026-10-19T21:00:00Z',
    deliveryStatus: 'DELIVERED',
    recipientCount: 18,
    executiveSummary: 'Critical exploitation confirmed against perimeter firewalls. Unauthenticated threat actors are executing arbitrary root commands via GlobalProtect portals.',
    remediationInstructions: 'Apply PAN-OS hotfix 10.2.9-h1 or disable Device Telemetry immediately.',
    affectedSystems: ['EDGE-FW-HQ-PRIMARY (PAN-OS 10.2.8)'],
  },
  {
    id: 'ADV-2026-0840',
    title: 'OpenSSH regreSSHion Signal Handler RCE',
    severity: 'HIGH',
    cveIds: ['CVE-2024-6387'],
    findingIds: ['fnd-004'],
    createdDate: '2026-10-19T18:00:00Z',
    deliveryStatus: 'DELIVERED',
    recipientCount: 22,
    executiveSummary: 'Signal race condition in OpenSSH sshd enables unauthenticated root execution on glibc systems.',
    remediationInstructions: 'Set LoginGraceTime 0 in sshd_config and restart daemon, or upgrade openssh-server package to 9.8p1.',
    affectedSystems: ['BASTION-JUMP-PUBLIC (OpenSSH 9.2p1)'],
  },
  {
    id: 'ADV-2026-0839',
    title: 'Fortinet FortiOS SSL-VPN Out-of-bounds Write Exploitation',
    severity: 'CRITICAL',
    cveIds: ['CVE-2024-21762'],
    findingIds: ['fnd-002'],
    createdDate: '2026-10-19T17:00:00Z',
    deliveryStatus: 'DELIVERED',
    recipientCount: 18,
    executiveSummary: 'Active weaponized exploitation targeting perimeter SSL-VPN appliances.',
    remediationInstructions: 'Upgrade FortiOS to 7.2.7+ or disable SSL-VPN web portal interface.',
    affectedSystems: ['VPN-GATEWAY-EAST (FortiOS 7.2.4)'],
  },
];

export const INITIAL_WEBHOOKS: WebhookEndpoint[] = [
  {
    id: 'wh-slack-01',
    name: 'SecOps Critical Alerts (Slack)',
    url: 'https://hooks.slack.com/services/T00/B00/secops-channel-mock',
    provider: 'SLACK',
    secretToken: 'whsec_slack_token_99x418a',
    enabled: true,
    events: ['CRITICAL', 'CISA_KEV'],
    deliveryCount: 38,
  },
  {
    id: 'wh-teams-01',
    name: 'Network Infrastructure Ops (MS Teams)',
    url: 'https://outlook.office.com/webhook/netops-security-feed',
    provider: 'TEAMS',
    secretToken: 'whsec_teams_token_4819a',
    enabled: true,
    events: ['ALL'],
    deliveryCount: 24,
  },
  {
    id: 'wh-soar-01',
    name: 'Enterprise SOAR / Splunk Ingress (HMAC Signed)',
    url: 'https://soar.internal.enterprise.org/api/v1/cve-ingress',
    provider: 'GENERIC_HMAC',
    secretToken: 'whsec_hmac_prod_e88a91b2c4...',
    enabled: true,
    events: ['ALL'],
    deliveryCount: 42,
  },
];

export const INITIAL_WEBHOOK_LOGS: WebhookDeliveryLog[] = [
  {
    id: 'whl-001',
    endpointId: 'wh-slack-01',
    endpointName: 'SecOps Critical Alerts (Slack)',
    provider: 'SLACK',
    advisoryId: 'ADV-2026-0841',
    cveId: 'CVE-2024-3400',
    status: 'SUCCESS',
    statusCode: 200,
    hmacSignature: 'sha256=d89e41b27f8a1042c88491e0a8b92c4d119842a1bc7e8901f42a6c810934ef01',
    sentAt: '2026-10-19T21:00:05Z',
  },
  {
    id: 'whl-002',
    endpointId: 'wh-soar-01',
    endpointName: 'Enterprise SOAR / Splunk Ingress (HMAC Signed)',
    provider: 'GENERIC_HMAC',
    advisoryId: 'ADV-2026-0841',
    cveId: 'CVE-2024-3400',
    status: 'SUCCESS',
    statusCode: 200,
    hmacSignature: 'sha256=94a1082c4f1e09a823b1c8f00192e478201a9bf10928a47ce981023a8b417e99',
    sentAt: '2026-10-19T21:00:06Z',
  },
];

export const INITIAL_ALERTED_CVES: AlertedCVE[] = [
  {
    cveId: 'CVE-2024-3400',
    firstAlertedAt: '2026-10-19T21:00:00Z',
    lastAlertedAt: '2026-10-19T21:00:00Z',
    advisoryId: 'ADV-2026-0841',
    recipientEmails: ['secops-team@enterprise.org', 'ciso-alerts@enterprise.org'],
    status: 'DISPATCHED',
    dispatchCount: 1,
  },
  {
    cveId: 'CVE-2024-21762',
    firstAlertedAt: '2026-10-19T17:00:00Z',
    lastAlertedAt: '2026-10-19T23:05:00Z',
    advisoryId: 'ADV-2026-0839',
    recipientEmails: ['secops-team@enterprise.org', 'netops@enterprise.org'],
    status: 'DISPATCHED',
    dispatchCount: 2,
    lastDispatchReason: 'Updated patch advisory release',
  },
  {
    cveId: 'CVE-2024-6387',
    firstAlertedAt: '2026-10-19T18:00:00Z',
    lastAlertedAt: '2026-10-19T18:00:00Z',
    advisoryId: 'ADV-2026-0840',
    recipientEmails: ['devsecops@enterprise.org', 'secops-team@enterprise.org'],
    status: 'DISPATCHED',
    dispatchCount: 1,
  },
];

export const INITIAL_RECIPIENTS: EmailRecipient[] = [
  {
    id: 'rec-01',
    name: 'Security Operations Team',
    email: 'secops-team@enterprise.org',
    role: 'Security Analysts',
    subscriptionTier: 'ALL_SEVERITIES',
    enabled: true,
    deliverySuccessRate: 99.8,
  },
  {
    id: 'rec-02',
    name: 'Network Infrastructure Operations',
    email: 'netops-alerts@enterprise.org',
    role: 'Firewall & Network Team',
    subscriptionTier: 'CRITICAL_HIGH_ONLY',
    enabled: true,
    deliverySuccessRate: 100.0,
  },
  {
    id: 'rec-03',
    name: 'Identity & Directory Services',
    email: 'sysops-identity@enterprise.org',
    role: 'Domain Infrastructure',
    subscriptionTier: 'CRITICAL_HIGH_ONLY',
    enabled: true,
    deliverySuccessRate: 99.4,
  },
];

export const INITIAL_EMAIL_LOGS: EmailDeliveryLog[] = [
  {
    id: 'eml-001',
    recipientEmail: 'secops-team@enterprise.org',
    advisoryId: 'ADV-2026-0841',
    subject: '[AUTONOMOUS NOTICE] PAN-OS GlobalProtect RCE (CVE-2024-3400)',
    provider: 'SendGrid',
    status: 'DELIVERED',
    attemptCount: 1,
    retrySchedule: ['5m', '15m', '1h', '3h', '12h'],
    nextRetryTime: null,
    sentAt: '2026-10-19T21:00:04Z',
  },
];

// Cryptographically chained audit logs with rolling SHA-256 hashes
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const h1 = quickHash(`${GENESIS_HASH}:2026-10-19T21:00:00Z:Pipeline Started`);
const h2 = quickHash(`${h1}:2026-10-19T21:00:04Z:Advisory Dispatched`);
const h3 = quickHash(`${h2}:2026-10-19T21:00:05Z:Webhook Fired`);
const h4 = quickHash(`${h3}:2026-10-19T22:15:22Z:SSRF Validated`);

export const INITIAL_AUDIT_LOGS: AuditLog[] = [
  {
    id: 'log-004',
    timestamp: '2026-10-19T22:15:22Z',
    category: 'FEED',
    level: 'INFO',
    event: 'SSRF Pre-Flight Check Passed',
    details: 'Validated feed URL https://api.msrc.microsoft.com/cvrf/v2.0/updates. Blocked private ranges: PASS.',
    actor: 'Autonomous Ingestion Engine',
    ipAddress: '127.0.0.1',
    prevHash: h3,
    hash: h4,
  },
  {
    id: 'log-003',
    timestamp: '2026-10-19T21:00:05Z',
    category: 'WEBHOOK',
    level: 'INFO',
    event: 'Signed Webhook Dispatched',
    details: 'Transmitted HMAC-SHA256 signed payload for ADV-2026-0841 to Slack and Enterprise SOAR endpoints.',
    actor: 'Zero-Human Outbox',
    ipAddress: '127.0.0.1',
    prevHash: h2,
    hash: h3,
  },
  {
    id: 'log-002',
    timestamp: '2026-10-19T21:00:04Z',
    category: 'EMAIL',
    level: 'INFO',
    event: 'Automated Advisory Dispatched',
    details: 'Dispatched ADV-2026-0841 to 18 recipients via SendGrid TLS 1.3 gateway without human intervention.',
    actor: 'Autonomous Dispatcher',
    ipAddress: '127.0.0.1',
    prevHash: h1,
    hash: h2,
  },
  {
    id: 'log-001',
    timestamp: '2026-10-19T21:00:00Z',
    category: 'PIPELINE',
    level: 'INFO',
    event: 'Autonomous Ingestion Execution',
    details: 'Correlated PAN-OS v10.2.8 within interval [< 10.2.9-h1]. Genesis block anchored.',
    actor: 'APScheduler-Worker-1',
    ipAddress: '127.0.0.1',
    prevHash: GENESIS_HASH,
    hash: h1,
  },
];

export const INITIAL_SETTINGS: AppSettings = {
  scopeHours: 24,
  schedulerIntervalMinutes: 60,
  schedulerEnabled: true,
  advisoryPrefix: 'ADV-2026-',
  emailEnabled: true,
   autoDispatchEnabled: true,
  autoDispatchConfidenceThreshold: 0,
  autoDispatchUnverifiableMatches: false,
  autoDispatchNewsToSecurityTeam: false,
  // Matches the schema default (server/validation.ts).
  reviewUnverifiableMatches: false,
  // Seed fixtures use standard alert flow: EVERYONE recipients receive the email
  // at the same time as the Security team for immediate distribution.
  deferEveryoneUntilSecurityDelivered: false,
  // Fixtures use standard detail: verbose telemetry is a deliberate forensic
  // choice an operator makes against a live installation.
  logVerbosity: 'standard',
  digestBatchingEnabled: true,
  digestWindowMinutes: 3,
  emailRetryEnabled: true,
  emailRetryMaxAttempts: 6,
  emailRetryInitialDelayMinutes: 1,
  emailRetryMaxDelayMinutes: 60,
  webhookSigningSecret: 'whsec_enterprise_hmac_prod_99x8...',
  authorityPrecedence: ['VENDOR_PSIRT', 'CISA_KEV', 'FIRST_EPSS', 'NVD_BATCH'],
  ssrfProtection: {
    blockPrivateIps: true,
    blockLoopback: true,
    allowRedirects: true,
  },
  securityPolicy: {
    sessionTimeoutMins: 30,
    csrfProtection: true,
    minPasswordLen: 12,
    maxLoginAttempts: 5,
    lockoutMins: 15,
    autoAliasTtlDays: 30,
  },
  selfHealing: {
    enabled: true,
    cooldownMinutes: 30,
    emailNotifications: true,
  },
  ntpConfig: {
    enabled: true,
    server: 'time.cloudflare.com',
    driftToleranceMs: 50,
  },
  retentionConfig: {
    enabled: false,
    retentionHours: 24,
    cleanupIntervalMinutes: 60,
    maxArchivedRecords: 10000,
    autoCleanup: true,
    retentionMode: 'rolling',
  },
  timezone: 'America/New_York',
  dailyDigest: {
    enabled: true,
    time: '09:00',
    includeHealthReport: true,
  },
};

export const INITIAL_ADVISORY_TEMPLATE = `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #09090b; color: #f4f4f5; margin: 0; padding: 24px; }
    .card { background-color: #18181b; border: 1px solid #27272a; border-radius: 12px; padding: 24px; max-width: 640px; margin: 0 auto; }
    .header { border-bottom: 1px solid #27272a; padding-bottom: 16px; margin-bottom: 20px; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-weight: 600; font-size: 11px; background: #27272a; color: #e4e4e7; border: 1px solid #3f3f46; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: #09090b; padding: 2px 6px; border-radius: 4px; font-size: 12px; border: 1px solid #27272a; }
    .notice { background: #18181b; border-left: 3px solid #3b82f6; padding: 12px; margin: 16px 0; border-radius: 4px; font-size: 13px; color: #d4d4d8; }
    .footer { margin-top: 24px; font-size: 11px; color: #71717a; border-top: 1px solid #27272a; padding-top: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <span class="badge">{{severity}}</span>
      <h2 style="color: #ffffff; margin: 10px 0 4px 0; font-size: 18px;">{{advisory_id}}: {{advisory_title}}</h2>
      <p style="color: #a1a1aa; font-size: 12px; margin: 0;">Dispatched automatically on {{dispatch_date}}</p>
    </div>

    <div class="notice">
      This notification was generated and dispatched automatically upon matching monitored product inventory. No manual approval required.
    </div>

    <h3 style="color: #f4f4f5; font-size: 14px; margin-top: 18px;">1. Summary</h3>
    <p style="color: #d4d4d8; line-height: 1.5; font-size: 13px;">{{executive_summary}}</p>

    <h3 style="color: #f4f4f5; font-size: 14px; margin-top: 18px;">2. Affected Products &amp; Assets</h3>
    <p style="font-size: 13px;"><strong>CVE Identifier:</strong> <span class="mono">{{cve_ids}}</span></p>
    <p style="font-size: 13px;"><strong>Monitored System(s):</strong> {{affected_systems}}</p>

    <h3 style="color: #f4f4f5; font-size: 14px; margin-top: 18px;">3. Technical Remediation</h3>
    <div style="background: #09090b; border: 1px solid #27272a; border-radius: 6px; padding: 12px; color: #a1a1aa; font-family: ui-monospace, monospace; font-size: 12px; line-height: 1.5;">
      {{remediation_steps}}
    </div>

    <p style="margin-top: 16px; font-size: 13px;"><strong>Vendor Advisory:</strong> <a href="{{vendor_link}}" style="color: #60a5fa; text-decoration: none;">{{vendor_link}}</a></p>

    <div class="footer">
      Autonomous Product Vulnerability Notification — BA Threat Intel Platform.
    </div>
  </div>
</body>
</html>`;
