/** Provider integrations shown on fresh and existing deployments. */
const recommendedFeedEntries = [
  { id: 'feed-nvd', name: 'NVD CVE API 2.0', type: 'NVD_API' as const,
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    authType: 'NONE' as const, rateLimitPerMin: 10, enabled: true, vendorSeed: true },
  { id: 'feed-mitre-cve', name: 'MITRE CVE — Official CVE List', type: 'MITRE_CVE' as const,
    url: 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json',
    authType: 'NONE' as const, rateLimitPerMin: 120, enabled: true, vendorSeed: true },
  { id: 'feed-cisa-kev', name: 'CISA Known Exploited Vulnerabilities', type: 'CISA_KEV' as const,
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    authType: 'NONE' as const, rateLimitPerMin: 5, enabled: true, vendorSeed: true },
  { id: 'feed-epss', name: 'FIRST EPSS Exploit Prediction Scores', type: 'EPSS_API' as const,
    url: 'https://api.first.org/data/v1/epss',
    authType: 'NONE' as const, rateLimitPerMin: 60, enabled: true, vendorSeed: true },
  { id: 'feed-osv', name: 'OSV Package Vulnerability Database', type: 'OSV_API' as const,
    url: 'https://api.osv.dev/v1/querybatch',
    authType: 'NONE' as const, rateLimitPerMin: 60, enabled: true, vendorSeed: true },
  { id: 'feed-github-advisories', name: 'GitHub Global Security Advisories', type: 'GITHUB_ADVISORIES' as const,
    url: 'https://api.github.com/advisories',
    authType: 'NONE' as const, rateLimitPerMin: 1, enabled: true, vendorSeed: true },
  { id:'feed-bleepingcomputer', name:'BleepingComputer Security News', type:'RSS_ATOM' as const,
    url:'https://www.bleepingcomputer.com/feed/', authType:'NONE' as const, rateLimitPerMin:5, enabled:false, vendorSeed:true },
  { id:'feed-sans-isc', name:'SANS Internet Storm Center Diary', type:'RSS_ATOM' as const,
    url:'https://isc.sans.edu/rssfeed.xml', authType:'NONE' as const, rateLimitPerMin:5, enabled:false, vendorSeed:true },
  { id:'feed-msrc-rss', name:'Microsoft Security Response Center Updates', type:'RSS_ATOM' as const,
    url:'https://api.msrc.microsoft.com/update-guide/rss', authType:'NONE' as const, rateLimitPerMin:5, enabled:false, vendorSeed:true },
  { id:'feed-fortiguard-psirt', name:'Fortinet FortiGuard PSIRT Security Advisories', type:'RSS_ATOM' as const,
    url:'https://filestore.fortinet.com/fortiguard/rss/ir.xml', authType:'NONE' as const, rateLimitPerMin:5, enabled:false, vendorSeed:true },
  {
    id: 'feed-opencve',
    name: 'OpenCVE CVE Enrichment',
    type: 'OPENCVE_API' as const,
    url: 'https://app.opencve.io/api/v2/cves',
    authType: 'BEARER' as const,
    rateLimitPerMin: 30,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-vulncheck-kev',
    name: 'VulnCheck Known Exploited Vulnerabilities',
    type: 'VULNCHECK_KEV' as const,
    url: 'https://api.vulncheck.com/v3/index/vulncheck-kev',
    authType: 'BEARER' as const,
    rateLimitPerMin: 60,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-alienvault-otx',
    name: 'AlienVault OTX Subscribed Pulses',
    type: 'OTX_API' as const,
    url: 'https://otx.alienvault.com/api/v1/pulses/subscribed/',
    authType: 'API_KEY' as const,
    rateLimitPerMin: 60,
    enabled: false,
    vendorSeed: true,
  },
  { id: 'feed-cisa-alerts', name: 'CISA Cybersecurity Advisories', type: 'RSS_ATOM' as const,
    // /news-events/cybersecurity-advisories/all.xml returns HTTP 404 (verified
    // 2026-11); the live feed moved to /cybersecurity-advisories/all.xml (200,
    // 5.8 MB XML).
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: true, vendorSeed: true },
  { id: 'feed-certcc-vulns', name: 'CERT/CC Vulnerability Notes', type: 'RSS_ATOM' as const,
    // Atom is the only syndication endpoint CERT/CC publishes; /vuls/rss 404s.
    // kb.cert.org/vuls/feed/ returns HTTP 404 (verified 2026-11). The live Atom
    // endpoint is /vuls/atomfeed/ (200, valid XML).
    url: 'https://www.kb.cert.org/vuls/atomfeed/', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: true, vendorSeed: true },
  { id: 'feed-hackernews', name: 'The Hacker News', type: 'RSS_ATOM' as const,
    url: 'https://thehackernews.com/feeds/posts/default', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: true },
  { id: 'feed-securityweek', name: 'SecurityWeek', type: 'RSS_ATOM' as const,
    url: 'https://www.securityweek.com/feed/', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: true },
  { id: 'feed-rapid7', name: 'Rapid7 Blog', type: 'RSS_ATOM' as const,
    url: 'https://www.rapid7.com/blog/rss/', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: true },
  { id: 'feed-google-p0', name: 'Google Project Zero', type: 'RSS_ATOM' as const,
    url: 'https://googleprojectzero.blogspot.com/feeds/posts/default', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: true },
  { id: 'feed-krebs', name: 'Krebs on Security', type: 'RSS_ATOM' as const,
    url: 'https://krebsonsecurity.com/feed/', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: true },
  { id: 'feed-cisco-psirt', name: 'Cisco Security Advisories', type: 'RSS_ATOM' as const,
    // Cisco PSIRT does not publish a valid RSS/Atom feed. The historical
    // endpoints are dead (tools.cisco.com 404) and sec.cloudapps.cisco.com/rss.xml
    // serves HTML, not XML (verified 2026-11). Cisco publishes advisories via
    // a REST API requiring authentication, not a public syndication feed.
    // Disabled; operators needing Cisco data should use NVD_API filtered to
    // vendor=cisco or configure a custom JSON_SEARCH_API feed.
    url: 'https://sec.cloudapps.cisco.com/security/center/rss.xml', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: false, healthStatus: 'DOWN' as const, errorLog: 'Cisco PSIRT does not provide a valid RSS/Atom feed; endpoint serves HTML. Use NVD_API with vendor filter or custom JSON feed.' },
  { id: 'feed-paloalto-psirt', name: 'Palo Alto Networks Security Advisories', type: 'RSS_ATOM' as const,
    url: 'https://security.paloaltonetworks.com/rss.xml', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: true },
  {
    id: 'feed-watchtowr',
    name: 'watchTowr Labs Vulnerability Research',
    type: 'RSS_ATOM' as const,
    url: 'https://labs.watchtowr.com/feed',
    authType: 'NONE' as const,
    rateLimitPerMin: 3,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-talos',
    name: 'Cisco Talos Intelligence Blog',
    type: 'RSS_ATOM' as const,
    // www.talosintelligence.com/vulnerability_reports/feed (and /rss/feed/)
    // return HTTP 404 HTML (verified 2026-11). The live syndication feed is the
    // blog host: blog.talosintelligence.com/rss/ (200, 1 MB valid XML, 15
    // articles) — the host was added to the default egress allowlist.
    url: 'https://blog.talosintelligence.com/rss/',
    authType: 'NONE' as const,
    rateLimitPerMin: 3,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-zdi',
    name: 'Zero Day Initiative Blog',
    type: 'RSS_ATOM' as const,
    url: 'https://www.thezdi.com/blog?format=rss',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-exploitdb',
    name: 'Exploit-DB Public Exploits',
    type: 'RSS_ATOM' as const,
    // Exploit-DB's RSS feed returns HTTP 403 Forbidden to automated user agents
    // (verified 2026-11). The feed works in browsers but blocks service-to-service
    // requests. Keep disabled until Exploit-DB changes their access policy.
    url: 'https://www.exploit-db.com/rss.xml', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: true, healthStatus: 'DOWN' as const, errorLog: 'Exploit-DB RSS returns 403 Forbidden to automated requests; blocks service user agents.' },
  {
    id: 'feed-debian-security',
    name: 'Debian Security Advisories',
    type: 'RSS_ATOM' as const,
    url: 'https://www.debian.org/security/dsa.rdf',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-cis-advisories',
    name: 'CIS Security Advisories',
    type: 'RSS_ATOM' as const,
    // cisecurity.com redirects every path to the www spelling on cisecurity.org.
    url: 'https://www.cisecurity.org/feed/advisories',
    authType: 'NONE' as const,
    rateLimitPerMin: 3,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-fulldisclosure',
    name: 'Full Disclosure Mailing List',
    type: 'RSS_ATOM' as const,
    url: 'https://seclists.org/rss/fulldisclosure.rss',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-sucuri',
    name: 'Sucuri Security Blog',
    type: 'RSS_ATOM' as const,
    url: 'https://blog.sucuri.net/feed/',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-welivesecurity',
    name: 'ESET WeLiveSecurity Research',
    type: 'RSS_ATOM' as const,
    url: 'https://www.welivesecurity.com/en/rss/feed/',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-wordpress-security',
    name: 'WordPress Security Advisories',
    type: 'RSS_ATOM' as const,
    url: 'https://wordpress.org/security/feed/',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-darkreading',
    name: 'Dark Reading',
    type: 'RSS_ATOM' as const,
    url: 'https://www.darkreading.com/rss.xml',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-google-security',
    name: 'Google Security Blog',
    type: 'RSS_ATOM' as const,
    url: 'https://blog.google/security/rss/',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-google-cse',
    name: 'Google Custom Search OSINT',
    type: 'GOOGLE_CSE' as const,
    url: 'https://www.googleapis.com/customsearch/v1',
    authType: 'API_KEY' as const,
    rateLimitPerMin: 100,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-google-cloud-security',
    name: 'Google Cloud Security Blog',
    type: 'RSS_ATOM' as const,
    // cloud.google.com/security/blog/feed returns an HTML shell instead of XML
    // (verified 2026-11). The Google Cloud Security Bulletins Atom feed at
    // docs.cloud.google.com serves the same security content (verified 200 +
    // text/xml + parse); docs.cloud.google.com is allowlisted in config.ts.
    url: 'https://docs.cloud.google.com/feeds/google-cloud-security-bulletins.xml',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-google-workspace-security',
    name: 'Google Workspace Security Updates',
    type: 'RSS_ATOM' as const,
    // workspace.google.com/blog/feed.xml serves the blog's HTML shell (HTTP
    // 200, not XML), which the syndication parser correctly rejects. The real
    // Workspace Updates feed is this FeedBurner mirror; the blog-hosted feed
    // (workspaceupdates.googleblog.com/feeds/posts/default) 302-redirects to
    // it, so seed the final hop directly and skip a redirect dependency.
    url: 'https://feeds.feedburner.com/GoogleAppsUpdates',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-twitter-security',
    name: 'X (Twitter) Security Announcements',
    type: 'RSS_ATOM' as const,
    // X (formerly Twitter) no longer publishes a public RSS/Atom feed for
    // security announcements. blog.twitter.com/engineering/en_us.atom redirects
    // to blog.x.com, which rejects automated requests. No usable public
    // security feed is currently available from X.
    url: 'https://blog.twitter.com/engineering/en_us.atom', authType: 'NONE' as const, rateLimitPerMin: 10, enabled: false, vendorSeed: true, healthStatus: 'DOWN' as const, errorLog: 'X/Twitter security feed is unavailable: blog.twitter.com redirects to blog.x.com, which rejects automated requests. Feed disabled.' },
  {
    id: 'feed-github-security-advisories',
    name: 'GitHub Security Blog',
    type: 'RSS_ATOM' as const,
    // github.com/advisories.atom returns HTTP 406 to non-browser user agents
    // (verified 2026-11). github.blog/feed/ serves the same security advisories
    // as valid RSS and accepts the service user agent; github.blog is allowlisted.
    // This feed provides advisory announcements, not the full GHSA database.
    // For programmatic GHSA access, use the GitHub REST/GraphQL API (requires token).
    url: 'https://github.blog/feed/', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: true, healthStatus: 'UNTESTED' as const, errorLog: 'Uses github.blog RSS (works); for full GHSA database, use GitHub API with authentication.' },
  {
    id: 'feed-forbes-cybersecurity',
    name: 'Forbes Cybersecurity News',
    type: 'RSS_ATOM' as const,
    // Forbes serves HTTP 403 to all non-interactive user agents including browsers
    // (verified 2026-11). No machine-readable feed is accessible. Disabled and
    // excluded from vendor seeding.
    url: 'https://www.forbes.com/sites/cybersecurity/feed/', authType: 'NONE' as const, rateLimitPerMin: 5, enabled: false, vendorSeed: false, healthStatus: 'DOWN' as const, errorLog: 'Forbes returns 403 Forbidden to all automated requests; no machine feed available.' },
  {
    id: 'feed-the-registrar-security',
    name: 'The Register Security',
    type: 'RSS_ATOM' as const,
    // api.theregister.com/security/headlines.atom returns HTTP 404 (verified
    // 2026-11). The live endpoint is the www host spelling (200, valid RSS).
    url: 'https://www.theregister.com/security/headlines.atom',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-greynoise',
    name: 'GreyNoise Labs',
    type: 'RSS_ATOM' as const,
    url: 'https://www.greynoise.io/blog/rss.xml',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-malwarebytes',
    name: 'Malwarebytes Labs',
    type: 'RSS_ATOM' as const,
    url: 'https://www.malwarebytes.com/blog/feed/index.xml',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-mandiant',
    name: 'Mandiant Blog',
    type: 'RSS_ATOM' as const,
    url: 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-sophos',
    name: 'Sophos Blog',
    type: 'RSS_ATOM' as const,
    url: 'https://www.sophos.com/en-us/blog/feed',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-therecord',
    name: 'The Record by Recorded Future',
    type: 'RSS_ATOM' as const,
    url: 'https://therecord.media/feed/',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-google-news-security',
    name: 'Google News - Security Vulnerabilities',
    type: 'RSS_ATOM' as const,
    url: 'https://news.google.com/rss/search?q=vulnerability+CVE&hl=en-US&gl=US&ceid=US:en',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-pentestpartners',
    name: 'Pentest Partners Research',
    type: 'RSS_ATOM' as const,
    url: 'https://www.pentestpartners.com/research/feed/',
    authType: 'NONE' as const,
    rateLimitPerMin: 3,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-cve-org',
    name: 'CVE.org — Official CVE Program',
    type: 'RSS_ATOM' as const,
    url: 'https://www.cve.org/verify/rss.xml',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-apple-security',
    name: 'Apple Security Advisories',
    type: 'RSS_ATOM' as const,
    url: 'https://support.apple.com/rss/security',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-adobe-security',
    name: 'Adobe Security Bulletins',
    type: 'RSS_ATOM' as const,
    url: 'https://helpx.adobe.com/security.html',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-redhat-security',
    name: 'Red Hat Security Advisories',
    type: 'RSS_ATOM' as const,
    url: 'https://access.redhat.com/security/updates/rss',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-ubuntu-security',
    name: 'Ubuntu Security Notices',
    type: 'RSS_ATOM' as const,
    url: 'https://usn.ubuntu.com/usn/usn.rss',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-crowdstrike-intel',
    name: 'CrowdStrike Falcon Intelligence',
    type: 'RSS_ATOM' as const,
    url: 'https://www.crowdstrike.com/blog/feed/',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-kaspersky-securelist',
    name: 'Kaspersky Securelist',
    type: 'RSS_ATOM' as const,
    url: 'https://www.securelist.com/feed/',
    authType: 'NONE' as const,
    rateLimitPerMin: 5,
    enabled: false,
    vendorSeed: true,
  },
] as const;

const feedsRequiringManualReview = new Set([
  'feed-twitter-security',
  'feed-exploitdb',
]);

export const RECOMMENDED_FEEDS = recommendedFeedEntries.map((feed) => ({
  ...feed,
  enabled:
    feed.enabled ||
    (feed.authType === 'NONE' && feed.vendorSeed && !feedsRequiringManualReview.has(feed.id)),
}));

/**
 * The catalog keyed by feed id.
 *
 * Existing installations only ever receive *new* seeded feeds — the bootstrap
 * skips an id that already exists — so a corrected URL in this file never
 * reached a database that had seeded the earlier, broken address. The feed then
 * failed on every run with an operator-visible error while the source said it
 * was fine. Exposing the catalog lets the bootstrap reconcile the URL (and only
 * the URL) of feeds it did not create this run.
 */
export const RECOMMENDED_FEED_URLS: ReadonlyMap<string, string> = new Map(
  RECOMMENDED_FEEDS.map((feed) => [feed.id, feed.url]),
);
