import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const relayDir = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.resolve(relayDir, '..', 'threat-intelligence');
const CACHE_FILE = path.join(DATA_DIR, 'phishtank-hosts.json');

const REFRESH_INTERVAL_MS = 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 30_000;
const MAX_COMPRESSED_BYTES = 25 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES = 150 * 1024 * 1024;

const USER_AGENT = 'RoarNet-PhishTank-Feed/1.0';

let blockedHosts = new Set();
let initialized = false;
let initializationPromise = null;
let refreshPromise = null;
let lastRefreshAt = 0;
let recordCount = 0;

function normalizeHost(hostname) {
  return String(hostname || '')
    .toLowerCase()
    .replace(/\.$/, '');
}

function extractHost(record) {
  if (!record || typeof record !== 'object') return null;
  if (record.verified !== 'yes' || record.online !== 'yes') return null;
  if (typeof record.url !== 'string') return null;

  try {
    const parsed = new URL(record.url);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }

    if (parsed.username || parsed.password) return null;

    const hostname = normalizeHost(parsed.hostname);

    if (!hostname || hostname.length > 253 || !hostname.includes('.')) {
      return null;
    }

    return hostname;
  } catch {
    return null;
  }
}

async function readResponseLimited(response) {
  if (!response.body) throw new Error('PHISHTANK_EMPTY_RESPONSE');

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      total += value.byteLength;

      if (total > MAX_COMPRESSED_BYTES) {
        await reader.cancel();
        throw new Error('PHISHTANK_COMPRESSED_SIZE_LIMIT');
      }

      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }

  return Buffer.concat(chunks, total);
}

function validateSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object' ||
      snapshot.source !== 'PhishTank' ||
      !Number.isSafeInteger(snapshot.updatedAt) ||
      snapshot.updatedAt <= 0 ||
      !Number.isSafeInteger(snapshot.recordCount) ||
      snapshot.recordCount < 1 ||
      !Array.isArray(snapshot.hosts) ||
      snapshot.hosts.length < 1) {
    throw new Error('PHISHTANK_CACHE_INVALID');
  }

  for (const host of snapshot.hosts) {
    if (typeof host !== 'string' ||
        normalizeHost(host) !== host ||
        host.length > 253 ||
        !host.includes('.') ||
        host.includes('/') ||
        host.includes(':')) {
      throw new Error('PHISHTANK_CACHE_HOST_INVALID');
    }
  }

  return snapshot;
}

async function loadCache() {
  try {
    const raw = await fs.readFile(CACHE_FILE, 'utf8');
    const snapshot = validateSnapshot(JSON.parse(raw));

    blockedHosts = new Set(snapshot.hosts);
    recordCount = snapshot.recordCount;
    lastRefreshAt = snapshot.updatedAt;

    console.log('[RoarNet PhishTank] Cache loaded:', {
      records: recordCount,
      hosts: blockedHosts.size
    });

    return true;
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.error(
        '[RoarNet PhishTank] Cache rejected:',
        error.message
      );
    }

    return false;
  }
}

async function refreshFeed() {
  const appKey = String(process.env.PHISHTANK_APP_KEY || '').trim();

  if (!appKey || !/^[a-zA-Z0-9]+$/.test(appKey)) {
    throw new Error('PHISHTANK_APP_KEY_NOT_CONFIGURED');
  }

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    FETCH_TIMEOUT_MS
  );

  try {
    const url =
      `https://data.phishtank.com/data/${appKey}/online-valid.json.gz`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'application/gzip'
      },
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`PHISHTANK_HTTP_${response.status}`);
    }

    const compressed = await readResponseLimited(response);

    let decompressed;

    try {
      decompressed = gunzipSync(compressed, {
        maxOutputLength: MAX_DECOMPRESSED_BYTES
      });
    } catch {
      throw new Error('PHISHTANK_GZIP_INVALID_OR_TOO_LARGE');
    }

    let records;

    try {
      records = JSON.parse(decompressed.toString('utf8'));
    } catch {
      throw new Error('PHISHTANK_JSON_INVALID');
    }

    if (!Array.isArray(records) || records.length < 1) {
      throw new Error('PHISHTANK_FEED_EMPTY_OR_INVALID');
    }

    const hosts = new Set();

    for (const record of records) {
      const host = extractHost(record);
      if (host) hosts.add(host);
    }

    if (hosts.size < 100) {
      throw new Error('PHISHTANK_FEED_VALIDATION_FAILED');
    }

    const snapshot = {
      version: 1,
      source: 'PhishTank',
      updatedAt: Date.now(),
      recordCount: records.length,
      hostCount: hosts.size,
      hosts: [...hosts].sort()
    };

    validateSnapshot(snapshot);

    await fs.mkdir(DATA_DIR, { recursive: true });

    const temporary = `${CACHE_FILE}.tmp`;

    await fs.writeFile(
      temporary,
      JSON.stringify(snapshot),
      { encoding: 'utf8', mode: 0o600 }
    );

    await fs.rename(temporary, CACHE_FILE);

    blockedHosts = hosts;
    recordCount = records.length;
    lastRefreshAt = snapshot.updatedAt;

    console.log('[RoarNet PhishTank] Feed refreshed:', {
      records: recordCount,
      blockedHosts: blockedHosts.size
    });

    return true;
  } finally {
    clearTimeout(timeout);
  }
}

export async function initializePhishTank() {
  if (initialized) return;
  if (initializationPromise) return initializationPromise;

  initializationPromise = (async () => {
    await loadCache();

    if (Date.now() - lastRefreshAt < REFRESH_INTERVAL_MS) {
      initialized = true;
      return;
    }

    try {
      await refreshFeed();
    } catch (error) {
      console.error(
        '[RoarNet PhishTank] Refresh failed; retaining last-known-good cache:',
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

export async function refreshPhishTankIfDue() {
  await initializePhishTank();

  if (Date.now() - lastRefreshAt < REFRESH_INTERVAL_MS) {
    return false;
  }

  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      await refreshFeed();
      return true;
    } catch (error) {
      console.error(
        '[RoarNet PhishTank] Scheduled refresh failed; retaining last-known-good cache:',
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

export function isPhishTankBlocked(hostname) {
  const host = normalizeHost(hostname);

  if (!host) return false;

  return blockedHosts.has(host);
}

export function getPhishTankStatus() {
  return {
    source: 'PhishTank',
    initialized,
    configured: Boolean(process.env.PHISHTANK_APP_KEY),
    lastRefreshAt: lastRefreshAt
      ? new Date(lastRefreshAt).toISOString()
      : null,
    records: recordCount,
    blockedHosts: blockedHosts.size
  };
}
