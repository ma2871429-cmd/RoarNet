import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const relayDir = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.resolve(relayDir, '..', 'threat-intelligence');
const CACHE_FILE = path.join(DATA_DIR, 'feodo-c2-ip.json');

const FEED_URL =
  'https://feodotracker.abuse.ch/downloads/ipblocklist.txt';

const REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 12_000;
const MAX_FEED_BYTES = 2 * 1024 * 1024;
const MAX_INDICATORS = 100_000;

let indicators = new Set();
let initialized = false;
let initializationPromise = null;
let refreshPromise = null;
let lastRefreshAt = 0;

function parseFeed(text) {
  if (typeof text !== 'string' ||
      !text.length ||
      Buffer.byteLength(text, 'utf8') > MAX_FEED_BYTES) {
    throw new Error('C2_FEED_SIZE_INVALID');
  }

  const result = new Set();

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (!line || line.startsWith('#')) continue;

    const candidate = line.split(/\s+/)[0];

    // This feed is consumed as exact IPv4 indicators only.
    if (net.isIP(candidate) !== 4) continue;

    result.add(candidate);

    if (result.size > MAX_INDICATORS) {
      throw new Error('C2_FEED_INDICATOR_LIMIT');
    }
  }

  if (result.size === 0) {
    throw new Error('C2_FEED_EMPTY_OR_INVALID');
  }

  return result;
}

async function loadCache() {
  try {
    const raw = await fs.readFile(CACHE_FILE, 'utf8');
    const snapshot = JSON.parse(raw);

    if (!snapshot ||
        snapshot.version !== 1 ||
        snapshot.source !== 'Feodo Tracker' ||
        !Number.isSafeInteger(snapshot.fetchedAt) ||
        snapshot.fetchedAt <= 0 ||
        !Array.isArray(snapshot.addresses) ||
        snapshot.addresses.length === 0 ||
        snapshot.addresses.length > MAX_INDICATORS) {
      throw new Error('C2_CACHE_SCHEMA_INVALID');
    }

    const loaded = new Set();

    for (const address of snapshot.addresses) {
      if (typeof address !== 'string' || net.isIP(address) !== 4) {
        throw new Error('C2_CACHE_INDICATOR_INVALID');
      }
      loaded.add(address);
    }

    if (loaded.size !== snapshot.addresses.length) {
      throw new Error('C2_CACHE_DUPLICATE_INDICATOR');
    }

    indicators = loaded;
    lastRefreshAt = snapshot.fetchedAt;
    return true;
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.error('[RoarNet C2] cache rejected:', error.message);
    }
    return false;
  }
}

async function refresh() {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    const response = await fetch(FEED_URL, {
      headers: { Accept: 'text/plain' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)
    });

    if (!response.ok) {
      throw new Error(`C2_FEED_HTTP_${response.status}`);
    }

    const text = await response.text();
    const nextIndicators = parseFeed(text);
    const fetchedAt = Date.now();

    await fs.mkdir(DATA_DIR, { recursive: true });

    const snapshot = {
      version: 1,
      source: 'Feodo Tracker',
      fetchedAt,
      addresses: [...nextIndicators]
    };

    const temporaryFile = `${CACHE_FILE}.tmp`;

    await fs.writeFile(
      temporaryFile,
      JSON.stringify(snapshot),
      'utf8'
    );

    await fs.rename(temporaryFile, CACHE_FILE);

    indicators = nextIndicators;
    lastRefreshAt = fetchedAt;

    return true;
  })();

  try {
    return await refreshPromise;
  } finally {
    refreshPromise = null;
  }
}

export async function initializeC2Intelligence() {
  if (initialized) return getC2Status();
  if (initializationPromise) return initializationPromise;

  initializationPromise = (async () => {
    await loadCache();

    const stale =
      !lastRefreshAt ||
      Date.now() - lastRefreshAt >= REFRESH_INTERVAL_MS;

    if (stale) {
      try {
        await refresh();
      } catch (error) {
        console.error(
          '[RoarNet C2] refresh failed; retaining last-known-good cache:',
          error.message
        );
      }
    }

    initialized = true;

    const timer = setInterval(() => {
      refresh().catch(error => {
        console.error('[RoarNet C2] scheduled refresh failed:', error.message);
      });
    }, REFRESH_INTERVAL_MS);

    timer.unref?.();

    return getC2Status();
  })();

  try {
    return await initializationPromise;
  } finally {
    initializationPromise = null;
  }
}

export function isKnownC2Address(address) {
  return net.isIP(address) === 4 && indicators.has(address);
}

export function getC2Status() {
  return {
    source: 'Feodo Tracker',
    initialized,
    lastRefreshAt: lastRefreshAt
      ? new Date(lastRefreshAt).toISOString()
      : null,
    indicators: indicators.size
  };
}
