import dns from 'node:dns/promises';
import net from 'node:net';

const BLOCKED_IPV4 = [
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
  ['240.0.0.0', 4]
];

function ipv4Number(address) {
  const parts = address.split('.');
  if (parts.length !== 4) return null;

  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value * 256 + n) >>> 0;
  }
  return value >>> 0;
}

function ipv4Blocked(address) {
  const value = ipv4Number(address);
  if (value === null) return true;

  return BLOCKED_IPV4.some(([base, bits]) => {
    const start = ipv4Number(base);
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    return ((value & mask) >>> 0) === ((start & mask) >>> 0);
  });
}

function ipv6Blocked(address) {
  const value = address.toLowerCase().split('%')[0];

  if (!net.isIPv6(value)) return true;

  // Allow only global-unicast space 2000::/3.
  const first = parseInt(value.split(':')[0] || '0', 16);
  if (!Number.isFinite(first) || first < 0x2000 || first > 0x3fff) {
    return true;
  }

  // Special-purpose, transition and documentation ranges.
  if (/^2001:0*0:/i.test(value)) return true;
  if (/^2001:0*2:/i.test(value)) return true;
  if (/^2001:0*10:/i.test(value)) return true;
  if (/^2001:0*20:/i.test(value)) return true;
  if (/^2001:0*db8:/i.test(value)) return true;
  if (/^2002:/i.test(value)) return true;

  return false;
}

function publicAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return !ipv4Blocked(address);
  if (family === 6) return !ipv6Blocked(address);
  return false;
}

export async function resolvePublicDestination(hostname) {
  const host = String(hostname || '').trim().toLowerCase();

  if (!host || host.length > 253) {
    throw new Error('INVALID_DESTINATION_HOST');
  }

  const hostFamily = net.isIP(host);

  if (!hostFamily &&
      (host.startsWith('.') || host.endsWith('.') ||
       host.includes('..') ||
       !/^[a-z0-9.-]+$/.test(host))) {
    throw new Error('INVALID_DESTINATION_HOST');
  }

  if (hostFamily) {
    if (!publicAddress(host)) {
      throw new Error('BLOCKED_DESTINATION_ADDRESS');
    }
    return [{ address: host, family: net.isIP(host) }];
  }

  let records;
  try {
    records = await dns.lookup(host, { all: true, verbatim: true });
  } catch {
    throw new Error('DESTINATION_DNS_FAILED');
  }

  if (!records.length ||
      records.some(record => !publicAddress(record.address))) {
    throw new Error('BLOCKED_OR_MIXED_DNS_DESTINATION');
  }

  return records;
}
