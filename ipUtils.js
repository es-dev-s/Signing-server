'use strict';

/**
 * Convert a dotted-decimal IPv4 string to a 32-bit unsigned integer.
 */
function ipv4ToInt(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const octet of parts) {
    const n = parseInt(octet, 10);
    if (!Number.isFinite(n) || n < 0 || n > 255) return null;
    acc = ((acc << 8) | n) >>> 0;
  }
  return acc;
}

function expandIPv6Groups(ip) {
  const s = String(ip).trim();
  if (!s.includes(':')) return null;
  let head;
  let tail;
  if (s.includes('::')) {
    const [a, b] = s.split('::');
    head = a ? a.split(':').filter((x) => x !== '') : [];
    tail = b ? b.split(':').filter((x) => x !== '') : [];
  } else {
    head = s.split(':').filter((x) => x !== '');
    tail = [];
  }
  const miss = 8 - head.length - tail.length;
  if (miss < 0) return null;
  const mid = Array(miss).fill('0');
  const all = [...head, ...mid, ...tail];
  if (all.length !== 8) return null;
  const nums = all.map((g) => {
    const x = parseInt(g || '0', 16);
    return Number.isFinite(x) && x >= 0 && x <= 0xffff ? x : NaN;
  });
  if (nums.some((n) => Number.isNaN(n))) return null;
  return nums;
}

/**
 * @param {string} ip
 * @returns {bigint | null}
 */
function ipv6ToBigInt(ip) {
  const groups = expandIPv6Groups(ip);
  if (!groups) return null;
  return groups.reduce((acc, x) => (acc << 16n) + BigInt(x), 0n);
}

const OFFICE_IP_RANGES = [
  { name: 'HR_FINANCE', start: '10.60.60.2', end: '10.60.60.254', v6: false },
  { name: 'L1_WIFI', start: '10.110.110.20', end: '10.110.110.254', v6: false },
  { name: '2ND_FLOOR_A_V6', start: '2403:3800:3197:200::2', end: '2403:3800:3197:200::ff:ffff', v6: true },
  { name: '2ND_FLOOR_B_V6', start: '2403:3800:3197:201::2', end: '2403:3800:3197:201::ffff', v6: true },
  { name: '3RD_FLOOR_A_V6', start: '2403:3800:3197:206::2', end: '2403:3800:3197:206::ffff', v6: true },
  { name: '3RD_FLOOR_B_V6', start: '2403:3800:3197:205::2', end: '2403:3800:3197:205::ffff', v6: true },
  { name: '4TH_FLOOR_V6', start: '2403:3800:3197:203::2', end: '2403:3800:3197:203::ffff', v6: true },
  { name: '5TH_FLOOR_V6', start: '2403:3800:3197:207::2', end: '2403:3800:3197:207::ffff', v6: true },
  { name: 'IT_ADMIN', start: '10.85.85.2', end: '10.85.85.250', v6: false },
  { name: 'CCTV', start: '10.65.65.100', end: '10.65.65.200', v6: false },
  { name: '2ND_FLOOR_A', start: '10.20.20.10', end: '10.20.20.250', v6: false },
  { name: '2ND_FLOOR_B', start: '10.25.25.100', end: '10.25.25.253', v6: false },
  { name: '3RD_FLOOR_A', start: '10.30.30.10', end: '10.30.30.250', v6: false },
  { name: '3RD_FLOOR_B', start: '10.35.35.100', end: '10.35.35.249', v6: false },
  { name: '4TH_FLOOR', start: '10.40.40.35', end: '10.40.40.252', v6: false },
  { name: '5TH_FLOOR', start: '10.50.50.2', end: '10.50.50.250', v6: false },
];

/**
 * @param {string | undefined | null} ip
 * @returns {boolean}
 */
function isOfficeIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const cleanIp = ip.replace(/^::ffff:/i, '');
  const isV6 = cleanIp.includes(':');

  for (const range of OFFICE_IP_RANGES) {
    if (range.v6 !== isV6) continue;
    if (isV6) {
      const addr = ipv6ToBigInt(cleanIp);
      const lo = ipv6ToBigInt(range.start);
      const hi = ipv6ToBigInt(range.end);
      if (addr == null || lo == null || hi == null) continue;
      if (addr >= lo && addr <= hi) return true;
    } else {
      const addr = ipv4ToInt(cleanIp);
      const lo = ipv4ToInt(range.start);
      const hi = ipv4ToInt(range.end);
      if (addr == null || lo == null || hi == null) continue;
      if (addr >= lo && addr <= hi) return true;
    }
  }
  return false;
}

/**
 * @param {string | undefined | null} ip
 * @returns {string | null}
 */
function getOfficeName(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const cleanIp = ip.replace(/^::ffff:/i, '');
  const isV6 = cleanIp.includes(':');

  for (const range of OFFICE_IP_RANGES) {
    if (range.v6 !== isV6) continue;
    let ok = false;
    if (isV6) {
      const addr = ipv6ToBigInt(cleanIp);
      const lo = ipv6ToBigInt(range.start);
      const hi = ipv6ToBigInt(range.end);
      ok = addr != null && lo != null && hi != null && addr >= lo && addr <= hi;
    } else {
      const addr = ipv4ToInt(cleanIp);
      const lo = ipv4ToInt(range.start);
      const hi = ipv4ToInt(range.end);
      ok = addr != null && lo != null && hi != null && addr >= lo && addr <= hi;
    }
    if (ok) return range.name;
  }
  return null;
}

/**
 * Cloud-hosted signaling sees the client's public/WAN IP (e.g. from X-Forwarded-For), not LAN 10.x.
 * The admin app also sends workstation interface IPs; if any match the allowlist, treat as on-office.
 *
 * @param {string | undefined | null} serverSeenIp
 * @param {string[] | undefined | null} workstationIps
 */
function isOnOfficeNetwork(serverSeenIp, workstationIps) {
  const candidates = [];
  if (serverSeenIp && typeof serverSeenIp === 'string') {
    const t = serverSeenIp.trim();
    if (t && t !== 'unknown') candidates.push(t);
  }
  if (Array.isArray(workstationIps)) {
    for (const w of workstationIps) {
      if (typeof w === 'string' && w.trim()) candidates.push(w.trim());
    }
  }
  for (const ip of candidates) {
    if (isOfficeIp(ip)) return true;
  }
  return false;
}

/**
 * @param {string | undefined | null} serverSeenIp
 * @param {string[] | undefined | null} workstationIps
 * @returns {string | null}
 */
function getOfficeNetworkLabel(serverSeenIp, workstationIps) {
  const candidates = [];
  if (serverSeenIp && typeof serverSeenIp === 'string') {
    const t = serverSeenIp.trim();
    if (t && t !== 'unknown') candidates.push(t);
  }
  if (Array.isArray(workstationIps)) {
    for (const w of workstationIps) {
      if (typeof w === 'string' && w.trim()) candidates.push(w.trim());
    }
  }
  for (const ip of candidates) {
    const n = getOfficeName(ip);
    if (n) return n;
  }
  return null;
}

module.exports = {
  isOfficeIp,
  getOfficeName,
  isOnOfficeNetwork,
  getOfficeNetworkLabel,
  OFFICE_IP_RANGES,
  ipv4ToInt,
};
