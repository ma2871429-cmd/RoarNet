import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const relayDir = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.resolve(relayDir, '..', 'threat-intelligence');
const CACHE_FILE = path.join(DATA_DIR, 'spamhaus-drop.json');
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 12_000;
const MAX_FEED_BYTES = 2 * 1024 * 1024;
const FEEDS = {
  v4: 'https://www.spamhaus.org/drop/drop_v4.json',
  v6: 'https://www.spamhaus.org/drop/drop_v6.json'
};

let activeRanges = { 4: [], 6: [] };
let initialized = false;
let initializationPromise = null;
let refreshPromise = null;
let lastRefreshAt = 0;
let currentMetadata = null;

function parseIPv4(value) {
  if (net.isIP(value) !== 4) throw new Error('INVALID_IPV4');
  return value.split('.').reduce((n, part) => (n << 8n) | BigInt(part), 0n);
}

function parseIPv6(value) {
  if (net.isIP(value) !== 6) throw new Error('INVALID_IPV6');
  let input = value.toLowerCase().split('%')[0];
  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    const ipv4 = parseIPv4(input.slice(lastColon + 1));
    const high = Number((ipv4 >> 16n) & 0xffffn).toString(16);
    const low = Number(ipv4 & 0xffffn).toString(16);
    input = `${input.slice(0, lastColon)}:${high}:${low}`;
  }
  const halves = input.split('::');
  if (halves.length > 2) throw new Error('INVALID_IPV6');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    throw new Error('INVALID_IPV6');
  }
  const parts = [...left, ...Array(missing).fill('0'), ...right];
  if (parts.length !== 8 || parts.some(part => !/^[0-9a-f]{1,4}$/.test(part))) {
    throw new Error('INVALID_IPV6');
  }
  return parts.reduce((n, part) => (n << 16n) | BigInt(`0x${part}`), 0n);
}

function parseCidr(cidr, expectedFamily) {
  if (typeof cidr !== 'string') throw new Error('INVALID_CIDR');
  const match = cidr.match(/^(.+)\/(\d{1,3})$/);
  if (!match) throw new Error('INVALID_CIDR');
  const address = match[1];
  const family = net.isIP(address);
  if (family !== expectedFamily) throw new Error('WRONG_CIDR_FAMILY');
  const bits = family === 4 ? 32 : 128;
  const prefix = Number(match[2]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) throw new Error('INVALID_PREFIX');
  const value = family === 4 ? parseIPv4(address) : parseIPv6(address);
  const hostBits = BigInt(bits - prefix);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(bits)) - 1n) ^ ((1n << hostBits) - 1n);
  if ((value & mask) !== value) throw new Error('NON_CANONICAL_CIDR');
  const end = value | ((1n << hostBits) - 1n);
  return { start: value, end, prefix };
}

function validateFeedText(text, family) {
  if (typeof text !== 'string' || !text.length || Buffer.byteLength(text, 'utf8') > MAX_FEED_BYTES) {
    throw new Error('SPAMHAUS_FEED_SIZE_INVALID');
  }
  const lines = text.split(/\r?\n/).filter(line => line.trim());
  if (lines.length < 2) throw new Error('SPAMHAUS_FEED_TOO_SMALL');

  const parsed = lines.map((line, index) => {
    try { return JSON.parse(line); }
    catch { throw new Error(`SPAMHAUS_INVALID_JSON_LINE_${index + 1}`); }
  });
  const metadataRows = parsed.filter(item => item && item.type === 'metadata');
  if (metadataRows.length !== 1 || parsed[parsed.length - 1] !== metadataRows[0]) {
    throw new Error('SPAMHAUS_METADATA_INVALID');
  }
  const metadata = metadataRows[0];
  const records = parsed.slice(0, -1);
  if (!Number.isSafeInteger(metadata.timestamp) || metadata.timestamp <= 0 ||
      !Number.isSafeInteger(metadata.records) || metadata.records !== records.length ||
      !Number.isSafeInteger(metadata.size) || metadata.size <= 0 ||
      typeof metadata.copyright !== 'string' || !metadata.copyright.includes('Spamhaus') ||
      metadata.terms !== 'https://www.spamhaus.org/drop/terms/') {
    throw new Error('SPAMHAUS_METADATA_FIELDS_INVALID');
  }

  const merged = new Map();
  for (const item of records) {
    if (!item || typeof item !== 'object' || Array.isArray(item) ||
        typeof item.cidr !== 'string' ||
        typeof item.sblid !== 'string' || !item.sblid.trim() ||
        !(item.rir === null || (typeof item.rir === 'string' && item.rir.trim()))) {
      throw new Error('SPAMHAUS_RECORD_FIELDS_INVALID');
    }
    const range = parseCidr(item.cidr, family);
    let entry = merged.get(item.cidr);
    if (!entry) {
      entry = { cidr: item.cidr, sblids: [], rirs: [], start: range.start.toString(), end: range.end.toString() };
      merged.set(item.cidr, entry);
    }
    if (!entry.sblids.includes(item.sblid)) entry.sblids.push(item.sblid);
    if (typeof item.rir === 'string' && !entry.rirs.includes(item.rir)) entry.rirs.push(item.rir);
  }
  if (merged.size === 0) throw new Error('SPAMHAUS_EMPTY_BLOCKLIST');

  const uniqueRecords = [...merged.values()].sort((a, b) => {
    const x = BigInt(a.start), y = BigInt(b.start);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  return { metadata, rawRecordCount: records.length, uniqueRecords };
}

function buildRanges(snapshot) {
  const result = { 4: [], 6: [] };
  for (const [family, key] of [[4, 'v4'], [6, 'v6']]) {
    const feed = snapshot.feeds[key];
    if (!feed || !Array.isArray(feed.records) || feed.records.length === 0) {
      throw new Error(`SPAMHAUS_CACHE_${key.toUpperCase()}_MISSING`);
    }
    for (const record of feed.records) {
      const range = parseCidr(record.cidr, family);
      result[family].push({ start: range.start, end: range.end });
    }
    result[family].sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
    const merged = [];
    for (const range of result[family]) {
      const previous = merged[merged.length - 1];
      if (previous && range.start <= previous.end + 1n) {
        if (range.end > previous.end) previous.end = range.end;
      } else {
        merged.push({ ...range });
      }
    }
    result[family] = merged;
  }
  return result;
}

function validateCachedFeed(feed, family) {
  if (!feed || typeof feed !== 'object' || Array.isArray(feed) ||
      !Array.isArray(feed.records) || feed.records.length === 0 ||
      !Number.isSafeInteger(feed.rawRecordCount) ||
      feed.rawRecordCount < feed.records.length) {
    throw new Error('SPAMHAUS_CACHE_FEED_SCHEMA_INVALID');
  }

  const metadata = feed.metadata;
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata) ||
      metadata.type !== 'metadata' ||
      !Number.isSafeInteger(metadata.timestamp) || metadata.timestamp <= 0 ||
      !Number.isSafeInteger(metadata.size) || metadata.size <= 0 ||
      metadata.records !== feed.rawRecordCount ||
      typeof metadata.copyright !== 'string' ||
      !metadata.copyright.includes('Spamhaus') ||
      metadata.terms !== 'https://www.spamhaus.org/drop/terms/') {
    throw new Error('SPAMHAUS_CACHE_METADATA_INVALID');
  }

  const seen = new Set();

  for (const record of feed.records) {
    if (!record || typeof record !== 'object' || Array.isArray(record) ||
        typeof record.cidr !== 'string' ||
        !Array.isArray(record.sblids) || record.sblids.length === 0 ||
        record.sblids.some(id => typeof id !== 'string' || !id.trim()) ||
        new Set(record.sblids).size !== record.sblids.length ||
        !Array.isArray(record.rirs) ||
        record.rirs.some(rir => typeof rir !== 'string' || !rir.trim()) ||
        new Set(record.rirs).size !== record.rirs.length ||
        seen.has(record.cidr)) {
      throw new Error('SPAMHAUS_CACHE_RECORD_INVALID');
    }

    seen.add(record.cidr);

    const range = parseCidr(record.cidr, family);

    if (record.start !== range.start.toString() ||
        record.end !== range.end.toString()) {
      throw new Error('SPAMHAUS_CACHE_RANGE_MISMATCH');
    }
  }

  if (feed.rawRecordCount < feed.records.length) {
    throw new Error('SPAMHAUS_CACHE_RECORD_COUNT_INVALID');
  }
}

async function loadCache() {
  try {
    const raw = await fs.readFile(CACHE_FILE, 'utf8');
    const snapshot = JSON.parse(raw);

    if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot) ||
        snapshot.version !== 1 ||
        snapshot.source !== 'Spamhaus DROP' ||
        !Number.isSafeInteger(snapshot.fetchedAt) ||
        snapshot.fetchedAt <= 0 ||
        !snapshot.feeds || typeof snapshot.feeds !== 'object') {
      throw new Error('SPAMHAUS_CACHE_SCHEMA_INVALID');
    }

    validateCachedFeed(snapshot.feeds.v4, 4);
    validateCachedFeed(snapshot.feeds.v6, 6);

    if (typeof snapshot.attribution !== 'string' ||
        !snapshot.attribution.includes('Spamhaus') ||
        snapshot.terms !== 'https://www.spamhaus.org/drop/terms/') {
      throw new Error('SPAMHAUS_CACHE_ATTRIBUTION_INVALID');
    }

    const ranges = buildRanges(snapshot);

    activeRanges = ranges;
    lastRefreshAt = snapshot.fetchedAt;
    currentMetadata = {
      v4: snapshot.feeds.v4.metadata,
      v6: snapshot.feeds.v6.metadata
    };

    return snapshot;
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.error('[RoarNet Spamhaus] cache rejected:', error.message);
    }
    return null;
  }
}

async function downloadFeed(url, family) {
  const response = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), redirect: 'error' });
  if (!response.ok) throw new Error(`SPAMHAUS_HTTP_${response.status}`);
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null) {
    const declaredLength = Number(contentLength);
    if (!Number.isSafeInteger(declaredLength) || declaredLength < 0 ||
        declaredLength > MAX_FEED_BYTES) {
      throw new Error('SPAMHAUS_FEED_SIZE_INVALID');
    }
  }

  if (!response.body) throw new Error('SPAMHAUS_EMPTY_RESPONSE');

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      totalBytes += value.byteLength;
      if (totalBytes > MAX_FEED_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error('SPAMHAUS_FEED_TOO_LARGE');
      }

      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }

  const text = Buffer.concat(chunks, totalBytes).toString('utf8');
  return validateFeedText(text, family);
}

async function refreshFeeds() {
  const [v4, v6] = await Promise.all([
    downloadFeed(FEEDS.v4, 4),
    downloadFeed(FEEDS.v6, 6)
  ]);
  const snapshot = {
    version: 1,
    source: 'Spamhaus DROP',
    fetchedAt: Date.now(),
    attribution: '(c) 2026 The Spamhaus Project SLU',
    terms: 'https://www.spamhaus.org/drop/terms/',
    feeds: {
      v4: { metadata: v4.metadata, rawRecordCount: v4.rawRecordCount, records: v4.uniqueRecords },
      v6: { metadata: v6.metadata, rawRecordCount: v6.rawRecordCount, records: v6.uniqueRecords }
    }
  };
  const nextRanges = buildRanges(snapshot);
  await fs.mkdir(DATA_DIR, { recursive: true });
  const temporary = `${CACHE_FILE}.tmp-${process.pid}`;
  try {
    await fs.writeFile(temporary, JSON.stringify(snapshot), { encoding: 'utf8', mode: 0o600 });
    await fs.rename(temporary, CACHE_FILE);
  } catch (error) {
    await fs.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
  activeRanges = nextRanges;
  lastRefreshAt = snapshot.fetchedAt;
  currentMetadata = { v4: v4.metadata, v6: v6.metadata };
  console.log('[RoarNet Spamhaus] DROP lists refreshed:', {
    ipv4: v4.rawRecordCount,
    ipv6: v6.rawRecordCount,
    uniqueIPv4: v4.uniqueRecords.length,
    uniqueIPv6: v6.uniqueRecords.length
  });
}

export async function initializeThreatIntelligence() {
  if (initialized) return;
  if (initializationPromise) return initializationPromise;

  initializationPromise = (async () => {
    await loadCache();

    if (Date.now() - lastRefreshAt < REFRESH_INTERVAL_MS) {
      initialized = true;
      return;
    }

    try {
      await refreshFeeds();
    } catch (error) {
      console.error(
        '[RoarNet Spamhaus] refresh failed; retaining last-known-good cache:',
        error.message
      );
    }

    initialized = true;
  })();

  try {
    await initializationPromise;
  } finally {
    initializationPromise = null;
  }
}

export async function refreshThreatIntelligenceIfDue() {
  await initializeThreatIntelligence();

  if (Date.now() - lastRefreshAt < REFRESH_INTERVAL_MS) {
    return false;
  }

  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      await refreshFeeds();
      return true;
    } catch (error) {
      console.error(
        '[RoarNet Spamhaus] scheduled refresh failed; retaining last-known-good cache:',
        error.message
      );
      return false;
    }
  })();

  try {
    return await refreshPromise;
  } finally {
    refreshPromise = null;
  }
}

function contains(ranges, value) {
  let low = 0, high = ranges.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const range = ranges[middle];
    if (value < range.start) high = middle - 1;
    else if (value > range.end) low = middle + 1;
    else return true;
  }
  return false;
}

export function isSpamhausBlocked(address) {
  const family = net.isIP(address);
  if (family === 4) return contains(activeRanges[4], parseIPv4(address));
  if (family === 6) return contains(activeRanges[6], parseIPv6(address));
  return false;
}

export function getThreatIntelligenceStatus() {
  return {
    source: 'Spamhaus DROP',
    initialized,
    lastRefreshAt: lastRefreshAt ? new Date(lastRefreshAt).toISOString() : null,
    activeIPv4Ranges: activeRanges[4].length,
    activeIPv6Ranges: activeRanges[6].length,
    metadata: currentMetadata
  };
}
