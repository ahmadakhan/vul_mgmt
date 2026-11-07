import ipaddr from 'ipaddr.js';

/**
 * Special-purpose and transition address space that must never be reachable
 * through outbound feed, webhook, or email-provider requests.
 *
 * `ipaddr.js`'s `range() === 'unicast'` check alone is insufficient: NAT64,
 * 6to4, and Teredo prefixes are globally routable IPv6 addresses that a host
 * network can translate into private IPv4 destinations.
 */
const FORBIDDEN_CIDRS: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
  ['255.255.255.255', 32],
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 32],
  ['2001:2::', 48],
  ['2001:10::', 28],
  ['2001:20::', 28],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
];

const FORBIDDEN = FORBIDDEN_CIDRS.map(([address, prefix]) =>
  ipaddr.parseCIDR(`${address}/${prefix}`),
);

/**
 * Returns true only for a globally routable unicast address that is not in a
 * special-purpose or transition prefix. IPv4-mapped IPv6 is normalised to its
 * IPv4 form before evaluation.
 */
export function isPublicAddress(address: string): boolean {
  try {
    const parsed = ipaddr.process(address);
    if (parsed.range() !== 'unicast') return false;
    for (const [network, prefix] of FORBIDDEN) {
      if (parsed.kind() === 'ipv4' && network.kind() === 'ipv4') {
        if ((parsed as ipaddr.IPv4).match(network as ipaddr.IPv4, prefix)) return false;
      } else if (parsed.kind() === 'ipv6' && network.kind() === 'ipv6') {
        if ((parsed as ipaddr.IPv6).match(network as ipaddr.IPv6, prefix)) return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}
