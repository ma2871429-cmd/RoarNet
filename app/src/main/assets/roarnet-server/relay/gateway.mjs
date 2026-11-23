import http from 'node:http';
import crypto from 'node:crypto';
import { resolvePublicDestination } from './destination-policy.mjs';
import {
  initializeThreatIntelligence,
  refreshThreatIntelligenceIfDue,
  getThreatIntelligenceStatus
} from './threat-intelligence.mjs';
import {
  initializePhishTank,
  refreshPhishTankIfDue,
  getPhishTankStatus
} from './phishtank.mjs';
import { openTcpSession } from './tcp-engine.mjs';
import { createGatewaySessionRuntime } from './gateway-session-runtime.mjs';
import { createSessionBridge } from './session-bridge.mjs';
import { createSessionBridgeAdapter } from './session-bridge-adapter.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const relayDir = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.resolve(relayDir, '..', '.env');

if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z_]+)=(.*)$/);
    if (match && process.env[match[1]] === undefined) {
      process.env[match[1]] = match[2].trim();
    }
  }
}





const CORE_URL = (process.env.CORE_URL || 'http://127.0.0.1:3180').replace(/\/+$/, '');
const HOST = process.env.RELAY_GATEWAY_HOST || '127.0.0.1';
const PORT = Number(process.env.RELAY_GATEWAY_PORT || 3182);
const GATEWAY_ID = process.env.RELAY_GATEWAY_ID || '';
const RELAY_GATEWAY_TOKEN = process.env.RELAY_GATEWAY_TOKEN || '';
const DEVICE_TTL_MS = 90_000;
const devices = new Map();
const deviceAssignments = new Map();
const deviceBridgeTokens = new Map();
const buyerBridgeTokens = new Map();

// Per-source request limits. Health endpoints are intentionally exempt.
const rateLimits = new Map();
const MAX_RATE_LIMIT_SOURCES = 8192;
const RATE_LIMIT_WINDOW_MS = 60_000;
const GLOBAL_REQUEST_LIMIT = 1200;
const AGENT_REQUEST_LIMIT = 600;

// Repeated failed-authentication protection.
const authFailures = new Map();
const sessionOwnershipAbuse = new Map();
const SESSION_ABUSE_WINDOW_MS = 60_000;
const SESSION_ABUSE_THRESHOLD = 8;
const SESSION_ABUSE_COOLDOWN_MS = 5 * 60_000;
const MAX_SESSION_ABUSE_SOURCES = 4096;

function checkSessionAbuseCooldown(req, res) {
  const key = rateLimitSource(req);
  const state = sessionOwnershipAbuse.get(key);
  if (!state) return true;

  const now = Date.now();
  if (state.blockedUntil > now) {
    const retryAfter = Math.max(1, Math.ceil((state.blockedUntil - now) / 1000));
    res.setHeader('Retry-After', String(retryAfter));
    req.resume();
    reply(res, 429, {
      success: false,
      error: 'SESSION_ABUSE_COOLDOWN',
      retryAfterSeconds: retryAfter
    });
    return false;
  }

  if (state.blockedUntil && state.blockedUntil <= now) {
    sessionOwnershipAbuse.delete(key);
  }
  return true;
}

function recordSessionOwnershipAbuse(req) {
  const key = rateLimitSource(req);
  const now = Date.now();
  let state = sessionOwnershipAbuse.get(key);

  if (!state) {
    if (sessionOwnershipAbuse.size >= MAX_SESSION_ABUSE_SOURCES) {
      for (const [storedKey, storedState] of sessionOwnershipAbuse) {
        if (
          now - storedState.windowStartedAt >= SESSION_ABUSE_WINDOW_MS &&
          now >= storedState.blockedUntil
        ) {
          sessionOwnershipAbuse.delete(storedKey);
        }
      }

      if (sessionOwnershipAbuse.size >= MAX_SESSION_ABUSE_SOURCES) {
        return false;
      }
    }

    state = { windowStartedAt: now, count: 0, blockedUntil: 0 };
    sessionOwnershipAbuse.set(key, state);
  }

  if (now - state.windowStartedAt >= SESSION_ABUSE_WINDOW_MS) {
    state.windowStartedAt = now;
    state.count = 0;
  }

  state.count += 1;
  if (
    state.count >= SESSION_ABUSE_THRESHOLD &&
    !state.blockedUntil
  ) {
    state.blockedUntil = now + SESSION_ABUSE_COOLDOWN_MS;
    queueAbuseSecurityEvent(
      'SESSION_OWNERSHIP_ABUSE_BLOCKED',
      req,
      state.windowStartedAt,
      SESSION_ABUSE_THRESHOLD,
      SESSION_ABUSE_WINDOW_MS,
      SESSION_ABUSE_COOLDOWN_MS
    );
  }
  return true;
}
const AUTH_FAILURE_WINDOW_MS = 60_000;
const AUTH_FAILURE_THRESHOLD = 30;
const AUTH_BLOCK_DURATION_MS = 120_000;
const AUTH_FAILURE_MAX_SOURCES = 4096;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function reply(res, status, value) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(value));
}

async function readJson(req) {
  let raw = '';

  for await (const chunk of req) {
    raw += chunk.toString('utf8');
    if (raw.length > 100 * 1024) {
      throw new Error('PAYLOAD_TOO_LARGE');
    }
  }

  return JSON.parse(raw || '{}');
}

function bearer(req) {
  const value = req.headers.authorization || '';
  if (!value.startsWith('Bearer ')) return '';
  return value.slice(7).trim();
}

function rateLimitSource(req) {
  const address = String(req.socket?.remoteAddress || 'unknown').toLowerCase();
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

function checkAuthenticationAbuse(req, res) {
  const key = rateLimitSource(req);
  const state = authFailures.get(key);
  const now = Date.now();

  if (!state || !state.blockedUntil || now >= state.blockedUntil) {
    if (state && state.blockedUntil && now >= state.blockedUntil) {
      authFailures.delete(key);
    }
    return true;
  }

  const retryAfter = Math.max(
    1,
    Math.ceil((state.blockedUntil - now) / 1000)
  );

  req.resume();
  res.setHeader('Retry-After', String(retryAfter));
  reply(res, 429, {
    error: 'AUTHENTICATION_ABUSE_COOLDOWN',
    retryAfterSeconds: retryAfter
  });
  return false;
}

function recordAuthenticationFailure(req) {
  const key = rateLimitSource(req);
  const now = Date.now();
  let state = authFailures.get(key);

  if (!state || now - state.windowStartedAt >= AUTH_FAILURE_WINDOW_MS) {
    if (!state && authFailures.size >= AUTH_FAILURE_MAX_SOURCES) {
      for (const [storedKey, storedState] of authFailures) {
        if (
          now - storedState.windowStartedAt >= AUTH_FAILURE_WINDOW_MS &&
          (!storedState.blockedUntil || now >= storedState.blockedUntil)
        ) {
          authFailures.delete(storedKey);
        }
      }

      if (authFailures.size >= AUTH_FAILURE_MAX_SOURCES) {
        return false;
      }
    }

    state = {
      count: 0,
      windowStartedAt: now,
      blockedUntil: 0
    };
    authFailures.set(key, state);
  }

  state.count += 1;

  if (
    state.count >= AUTH_FAILURE_THRESHOLD &&
    !state.blockedUntil
  ) {
    state.blockedUntil = now + AUTH_BLOCK_DURATION_MS;
    queueAbuseSecurityEvent(
      'AUTHENTICATION_ABUSE_BLOCKED',
      req,
      state.windowStartedAt,
      AUTH_FAILURE_THRESHOLD,
      AUTH_FAILURE_WINDOW_MS,
      AUTH_BLOCK_DURATION_MS
    );
  }
  return true;
}

function clearAuthenticationFailures(req) {
  authFailures.delete(rateLimitSource(req));
}

function enforceRateLimit(req, res, bucket, limit) {
  const now = Date.now();
  const key = `${bucket}:${rateLimitSource(req)}`;
  let state = rateLimits.get(key);

  if (!state || now >= state.resetAt) {
    if (!state && rateLimits.size >= MAX_RATE_LIMIT_SOURCES) {
      for (const [storedKey, storedState] of rateLimits) {
        if (now >= storedState.resetAt) {
          rateLimits.delete(storedKey);
        }
      }

      if (rateLimits.size >= MAX_RATE_LIMIT_SOURCES) {
        req.resume();
        res.setHeader('Retry-After', '5');
        reply(res, 503, {
          error: 'RATE_LIMIT_CAPACITY',
          retryAfterSeconds: 5
        });
        return false;
      }
    }

    state = {
      count: 0,
      resetAt: now + RATE_LIMIT_WINDOW_MS
    };
    rateLimits.set(key, state);
  }

  state.count += 1;

  if (state.count <= limit) return true;

  const retryAfter = Math.max(
    1,
    Math.ceil((state.resetAt - now) / 1000)
  );

  req.resume();
  res.setHeader('Retry-After', String(retryAfter));
  reply(res, 429, {
    error: 'RATE_LIMIT_EXCEEDED',
    retryAfterSeconds: retryAfter
  });

  return false;
}

async function verifyDevice(accessToken, deviceId) {
  const url = new URL('/api/participant/device/consent', CORE_URL);
  url.searchParams.set('deviceId', deviceId);

  const response = await fetch(url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(10000)
  });

  if (!response.ok) {
    return { valid: false, status: response.status };
  }

  const data = await response.json();

  return {
    valid: data.accepted === true && data.deviceId === deviceId,
    status: 200,
    accepted: data.accepted === true,
    disclosureVersion: data.disclosureVersion || null
  };
}

async function authenticate(req, res, deviceId) {
  if (!checkAuthenticationAbuse(req, res)) return null;

  const token = bearer(req);

  if (token.length < 20 || token.length > 4096) {
    if (!recordAuthenticationFailure(req)) {
      reply(res, 503, {
        error: 'SECURITY_STATE_CAPACITY',
        retryAfterSeconds: 5
      });
      return null;
    }
    reply(res, 401, { error: 'Valid participant login required' });
    return null;
  }

  if (!UUID.test(deviceId || '')) {
    reply(res, 400, { error: 'Valid deviceId required' });
    return null;
  }

  try {
    const result = await verifyDevice(token, deviceId);

    if (!result.valid) {
      if (result.status === 401 &&
          !recordAuthenticationFailure(req)) {
        reply(res, 503, {
          error: 'SECURITY_STATE_CAPACITY',
          retryAfterSeconds: 5
        });
        return null;
      }
      devices.delete(deviceId);
      await sessionRuntime.revokeDevice(deviceId);
      reply(res, result.status === 200 ? 403 : result.status, {
        error: result.status === 200
          ? 'Device consent is not active'
          : 'Device authorization failed',
        accepted: false
      });
      return null;
    }

    clearAuthenticationFailures(req);

    devices.set(deviceId, {
      lastSeenAt: new Date().toISOString(),
      disclosureVersion: result.disclosureVersion
    });

    return result;
  } catch {
    reply(res, 502, { error: 'RoarNet core unavailable' });
    return null;
  }
}


const sessionRuntime = createGatewaySessionRuntime({
  openTcpSession,
  async transitionCore(sessionId, targetStatus, extra = {}) {
    if (RELAY_GATEWAY_TOKEN.length < 32 ||
        GATEWAY_ID.length < 3) {
      throw new Error('GATEWAY_CORE_CREDENTIALS_NOT_CONFIGURED');
    }

    const response = await fetch(
      new URL(
        '/api/relay/gateway/sessions/' +
        encodeURIComponent(sessionId) +
        '/transition',
        CORE_URL
      ),
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${RELAY_GATEWAY_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          gatewayId: GATEWAY_ID,
          targetStatus,
          ...extra
        }),
        signal: AbortSignal.timeout(10000)
      }
    );

    let result;
    try {
      result = await response.json();
    } catch {
      throw new Error('INVALID_CORE_TRANSITION_RESPONSE');
    }

    if (!response.ok || result.success !== true) {
      throw new Error(
        result.error || 'CORE_SESSION_TRANSITION_FAILED'
      );
    }

    return result;
  }
});

// ROARNET_CENTRAL_SESSION_BRIDGE_V1
async function transitionCoreForDevice(sessionId, targetStatus, extra = {}) {
  const response = await fetch(
    new URL(
      '/api/relay/gateway/sessions/' +
      encodeURIComponent(sessionId) +
      '/transition',
      CORE_URL
    ),
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RELAY_GATEWAY_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        targetStatus,
        gatewayId: GATEWAY_ID,
        ...extra
      }),
      signal: AbortSignal.timeout(8000)
    }
  );

  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.success !== true) {
    const error = new Error(
      result.error || 'CORE_SESSION_TRANSITION_FAILED'
    );
    error.statusCode = response.status;
    throw error;
  }
  return result;
}

async function resolveTrustedSession(sessionId) {
  if (RELAY_GATEWAY_TOKEN.length < 32 || GATEWAY_ID.length < 3) {
    return null;
  }

  const assignment = deviceAssignments.get(sessionId);
  if (
    !assignment ||
    Date.parse(assignment.expiresAt) <= Date.now()
  ) return null;

  try {
    const response = await fetch(
      new URL(
        '/api/relay/gateway/session-context/' +
        encodeURIComponent(sessionId),
        CORE_URL
      ),
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${RELAY_GATEWAY_TOKEN}`,
          'x-roarnet-gateway-id': GATEWAY_ID
        },
        signal: AbortSignal.timeout(8000)
      }
    );

    if (!response.ok) return null;
    const context = await response.json();

    if (
      context.sessionId !== sessionId ||
      context.status !== 'ACTIVE' ||
      context.consentActive !== true ||
      context.customerId !== assignment.customerId ||
      context.deviceId !== assignment.deviceId
    ) return null;

    return context;
  } catch {
    return null;
  }
}

const sessionBridge = createSessionBridge({
  resolveSession: resolveTrustedSession
});

const sessionBridgeAdapter = createSessionBridgeAdapter({
  bridge: sessionBridge,
  runtime: sessionRuntime,
  resolveAssignment: resolveTrustedSession,
  isConsentActive: async (deviceId, sessionId) => {
    const context = await resolveTrustedSession(sessionId);
    return Boolean(
      context &&
      context.deviceId === deviceId &&
      context.consentActive === true
    );
  }
});


async function recordRoarNetSecurityEvent(event) {
  if (RELAY_GATEWAY_TOKEN.length < 32 || GATEWAY_ID.length < 3) {
    return false;
  }

  const response = await fetch(
    new URL('/api/internal/security-events', CORE_URL),
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RELAY_GATEWAY_TOKEN}`,
        'x-roarnet-gateway-id': GATEWAY_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(3000)
    }
  );

  if (!response.ok) {
    throw new Error(`SECURITY_EVENT_CORE_HTTP_${response.status}`);
  }

  return response.json();
}

function queueAbuseSecurityEvent(
  eventType,
  req,
  windowStartedAt,
  threshold,
  windowMs,
  cooldownMs
) {
  if (RELAY_GATEWAY_TOKEN.length < 32 || GATEWAY_ID.length < 3) {
    return;
  }

  const source = rateLimitSource(req);
  const sourceHash = crypto
    .createHmac('sha256', RELAY_GATEWAY_TOKEN)
    .update(source)
    .digest('hex');

  const dedupeKey = crypto
    .createHash('sha256')
    .update([
      GATEWAY_ID,
      eventType,
      sourceHash,
      String(windowStartedAt)
    ].join(':'))
    .digest('hex');

  const isAuth = eventType === 'AUTHENTICATION_ABUSE_BLOCKED';

  const event = {
    eventType,
    severity: 'high',
    reasonCode: isAuth
      ? 'AUTHENTICATION_ABUSE_THRESHOLD'
      : 'SESSION_OWNERSHIP_ABUSE_THRESHOLD',
    dedupeKey,
    metadata: {
      sourceHash,
      threshold,
      windowMs,
      cooldownMs,
      route: String(req.url || '').split('?')[0].slice(0, 120)
    }
  };

  void recordRoarNetSecurityEvent(event).catch(error => {
    console.error('[RoarNet] Security event delivery failed:', error.message);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    return reply(res, 200, {
      app: 'RoarNet Relay Gateway',
      gatewayId: GATEWAY_ID || null,
      status: 'running',
      mode: 'authenticated-control-only',
      trafficForwarding: false
    });
  }

  if (req.method === 'GET' && url.pathname === '/gateway/status') {
    return reply(res, 200, {
      gatewayId: GATEWAY_ID || null,
      connectedDevices: devices.size,
      trafficForwarding: false,
      sessionAssignments: false
    });
  }

  if (!enforceRateLimit(
    req, res, 'global', GLOBAL_REQUEST_LIMIT
  )) return;


  const transitionMatch = url.pathname.match(
    /^\/gateway\/sessions\/([A-Za-z0-9_-]{8,100})\/transition$/
  );

  if (req.method === 'POST' && transitionMatch) {
    const supplied = bearer(req);

    if (RELAY_GATEWAY_TOKEN.length < 32 ||
        GATEWAY_ID.length < 3 ||
        supplied.length < 32) {
      return reply(res, 503, {
        error: 'GATEWAY_TRANSITION_AUTH_NOT_CONFIGURED',
        trafficForwarding: false
      });
    }

    const digest = value => crypto.createHash('sha256')
      .update(value)
      .digest();

    if (!crypto.timingSafeEqual(
      digest(supplied),
      digest(RELAY_GATEWAY_TOKEN)
    )) {
      return reply(res, 401, {
        error: 'INVALID_GATEWAY_CREDENTIALS'
      });
    }

    let data;
    try {
      data = await readJson(req);
    } catch (error) {
      return reply(res,
        error.message === 'PAYLOAD_TOO_LARGE' ? 413 : 400,
        { error: 'INVALID_TRANSITION_PAYLOAD' }
      );
    }

    const targetStatus = String(data.targetStatus || '').toUpperCase();

    const allowedTargets = [
      'CONNECTING',
      'ACTIVE',
      'CLOSING',
      'COMPLETED',
      'FAILED',
      'REJECTED'
    ];

    if (!allowedTargets.includes(targetStatus)) {
      return reply(res, 400, {
        error: 'INVALID_GATEWAY_TRANSITION_TARGET'
      });
    }

    if (targetStatus === 'ACTIVE' && data.connected !== true) {
      return reply(res, 400, {
        error: 'REAL_CONNECTION_CONFIRMATION_REQUIRED'
      });
    }

    const reportHash = String(data.reportHash || '').toLowerCase();
    if (targetStatus === 'COMPLETED' &&
        !/^[a-f0-9]{64}$/.test(reportHash)) {
      return reply(res, 400, {
        error: 'VALID_GATEWAY_REPORT_HASH_REQUIRED'
      });
    }

    const failureCode = String(data.failureCode || '').trim();
    if (targetStatus === 'FAILED' &&
        !/^[A-Z0-9_-]{3,64}$/.test(failureCode)) {
      return reply(res, 400, {
        error: 'VALID_FAILURE_CODE_REQUIRED'
      });
    }

    const payload = {
      gatewayId: GATEWAY_ID,
      targetStatus
    };

    if (targetStatus === 'ACTIVE') {
      payload.connected = true;
    }

    if (targetStatus === 'COMPLETED') {
      payload.reportHash = reportHash;
    }

    if (targetStatus === 'FAILED') {
      payload.failureCode = failureCode;
    }

    try {
      const coreResponse = await fetch(
        new URL(
          '/api/relay/gateway/sessions/' +
          encodeURIComponent(transitionMatch[1]) +
          '/transition',
          CORE_URL
        ),
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${RELAY_GATEWAY_TOKEN}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(10000)
        }
      );

      let coreData;
      try {
        coreData = await coreResponse.json();
      } catch {
        return reply(res, 502, {
          error: 'INVALID_CORE_TRANSITION_RESPONSE',
          trafficForwarding: false
        });
      }

      return reply(res, coreResponse.status, {
        ...coreData,
        gatewayId: GATEWAY_ID,
        trafficForwarding: false
      });
    } catch {
      return reply(res, 502, {
        error: 'ROARNET_CORE_TRANSITION_UNAVAILABLE',
        trafficForwarding: false
      });
    }
  }


  // ROARNET_BUYER_BRIDGE_API_V1
  const buyerBridgeMatch = url.pathname.match(
    /^\/internal\/buyer\/sessions\/([0-9a-f-]{36})\/(send|receive)$/i
  );

  if (req.method === 'POST' && buyerBridgeMatch) {
    const supplied = bearer(req);
    const suppliedId = String(req.headers['x-roarnet-gateway-id'] || '');

    if (
      RELAY_GATEWAY_TOKEN.length < 32 ||
      GATEWAY_ID.length < 3 ||
      supplied.length < 32 ||
      suppliedId !== GATEWAY_ID
    ) {
      return reply(res, 401, {
        error: 'INTERNAL_GATEWAY_AUTHENTICATION_REQUIRED'
      });
    }

    const digest = value => crypto.createHash('sha256')
      .update(value)
      .digest();

    if (!crypto.timingSafeEqual(
      digest(supplied),
      digest(RELAY_GATEWAY_TOKEN)
    )) {
      return reply(res, 401, {
        error: 'INVALID_INTERNAL_GATEWAY_CREDENTIALS'
      });
    }

    const sessionId = buyerBridgeMatch[1];
    const operation = buyerBridgeMatch[2].toLowerCase();
    const channelToken = buyerBridgeTokens.get(sessionId);

    if (!channelToken) {
      return reply(res, 404, {
        error: 'BUYER_CHANNEL_NOT_AVAILABLE'
      });
    }

    let data;
    try {
      data = await readJson(req);
    } catch (error) {
      return reply(
        res,
        error.message === 'PAYLOAD_TOO_LARGE' ? 413 : 400,
        { error: 'INVALID_BUYER_PAYLOAD' }
      );
    }

    try {
      const context = await resolveTrustedSession(sessionId);

      if (!context || context.status !== 'ACTIVE') {
        return reply(res, 403, {
          error: 'ACTIVE_SESSION_OR_CONSENT_REQUIRED'
        });
      }

      if (operation === 'send') {
        if (
          typeof data.data !== 'string' ||
          data.data.length < 4 ||
          data.data.length > 87384 ||
          !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data.data)
        ) {
          return reply(res, 400, {
            error: 'INVALID_BASE64_DATA'
          });
        }

        const decoded = Buffer.from(data.data, 'base64');

        if (
          decoded.length < 1 ||
          decoded.length > 64 * 1024 ||
          decoded.toString('base64') !== data.data
        ) {
          return reply(res, 413, {
            error: 'BUYER_CHUNK_SIZE_INVALID'
          });
        }

        const result = await sessionBridge.customerSend(
          sessionId,
          context.customerId,
          channelToken,
          data.data
        );

        return reply(res, 200, {
          success: true,
          result
        });
      }

      const maxItems = Number(data.maxItems ?? 16);

      if (
        !Number.isInteger(maxItems) ||
        maxItems < 1 ||
        maxItems > 32
      ) {
        return reply(res, 400, {
          error: 'INVALID_RECEIVE_LIMIT'
        });
      }

      const result = await sessionBridge.customerReceive(
        sessionId,
        context.customerId,
        channelToken,
        maxItems
      );

      return reply(res, 200, {
        success: true,
        result
      });
    } catch (error) {
      const backpressure =
        String(error?.message || '') === 'CHANNEL_BACKPRESSURE';

      return reply(res, backpressure ? 429 : 409, {
        success: false,
        error: backpressure
          ? 'CHANNEL_BACKPRESSURE'
          : 'BUYER_BRIDGE_OPERATION_FAILED'
      });
    }
  }

  const agentRoutes = [
    '/agent/heartbeat',
    '/agent/next',
    '/agent/session/open',
    '/agent/session/activate',
    '/agent/session/send',
    '/agent/session/receive',
    '/agent/session/close'
  ];

  if (req.method !== 'POST' || !agentRoutes.includes(url.pathname)) {
    return reply(res, 404, { error: 'Not found' });
  }

  if (!enforceRateLimit(
    req, res, 'agent', AGENT_REQUEST_LIMIT
  )) return;

  let data;

  try {
    data = await readJson(req);
  } catch (error) {
    return reply(res, error.message === 'PAYLOAD_TOO_LARGE' ? 413 : 400, {
      error: 'Invalid JSON request'
    });
  }

  const authorization = await authenticate(req, res, String(data.deviceId || ''));
  if (!authorization) return;

  if (url.pathname === '/agent/heartbeat') {
    return reply(res, 200, {
      ok: true,
      deviceId: data.deviceId,
      connected: true,
      consentAccepted: true,
      gatewayMode: 'session-runtime',
      gatewayId: GATEWAY_ID || null,
      activeSessions: sessionRuntime.counts.activeSessions
    });
  }

  if (url.pathname.startsWith('/agent/session/')) {
    if (!checkSessionAbuseCooldown(req, res)) return;

    const sessionId = String(data.sessionId || '');

    if (!/^[A-Za-z0-9_-]{8,100}$/.test(sessionId)) {
      return reply(res, 400, { error: 'INVALID_SESSION_ID' });
    }

    try {
      if (url.pathname === '/agent/session/open') {
        const assignment = deviceAssignments.get(sessionId);

        if (!assignment ||
            assignment.deviceId !== data.deviceId ||
            authorization.accepted !== true) {
          if (assignment && assignment.deviceId !== data.deviceId) {
            if (!recordSessionOwnershipAbuse(req)) {
              return reply(res, 503, {
                success: false,
                error: 'SECURITY_STATE_CAPACITY',
                retryAfterSeconds: 5
              });
            }
          }
          return reply(res, 409, {
            success: false,
            error: 'DEVICE_ASSIGNMENT_NOT_AVAILABLE',
            trafficForwarding: false
          });
        }

        if (Date.parse(assignment.expiresAt) <= Date.now()) {
          deviceAssignments.delete(sessionId);
          deviceBridgeTokens.delete(sessionId);
          buyerBridgeTokens.delete(sessionId);
          sessionBridge.close(sessionId, 'ASSIGNMENT_EXPIRED');

          return reply(res, 409, {
            success: false,
            error: 'DEVICE_ASSIGNMENT_EXPIRED',
            trafficForwarding: false
          });
        }

        await transitionCoreForDevice(sessionId, 'CONNECTING');

        return reply(res, 200, {
          success: true,
          assignment,
          requiresDeviceTcp: true,
          trafficForwarding: false
        });
      }

      if (url.pathname === '/agent/session/activate') {
        const assignment = deviceAssignments.get(sessionId);

        if (!assignment ||
            assignment.deviceId !== data.deviceId ||
            authorization.accepted !== true ||
            data.connected !== true ||
            Date.parse(assignment.expiresAt) <= Date.now()) {
          if (assignment && assignment.deviceId !== data.deviceId) {
            if (!recordSessionOwnershipAbuse(req)) {
              return reply(res, 503, {
                success: false,
                error: 'SECURITY_STATE_CAPACITY',
                retryAfterSeconds: 5
              });
            }
          }
          return reply(res, 409, {
            success: false,
            error: 'DEVICE_SESSION_ACTIVATION_REJECTED',
            trafficForwarding: false
          });
        }

        let deviceToken = deviceBridgeTokens.get(sessionId);

        if (!deviceToken) {
          await transitionCoreForDevice(sessionId, 'ACTIVE', {
            connected: true
          });

          const trusted = await resolveTrustedSession(sessionId);
          if (!trusted) {
            throw new Error('TRUSTED_SESSION_CONTEXT_UNAVAILABLE');
          }

          const opened = await sessionBridge.open(sessionId);
          if (!opened || !opened.deviceToken) {
            throw new Error('DEVICE_CHANNEL_OPEN_FAILED');
          }

          deviceToken = opened.deviceToken;
          deviceBridgeTokens.set(sessionId, deviceToken);

          if (opened.customerToken) {
            buyerBridgeTokens.set(sessionId, opened.customerToken);
          }
        }

        return reply(res, 200, {
          success: true,
          sessionId,
          deviceToken,
          expiresAt: assignment.expiresAt,
          trafficForwarding: false
        });
      }

      if (url.pathname === '/agent/session/send') {
        const assignment = deviceAssignments.get(sessionId);
        const token = deviceBridgeTokens.get(sessionId);

        if (!assignment ||
            assignment.deviceId !== data.deviceId ||
            !token ||
            Date.parse(assignment.expiresAt) <= Date.now() ||
            typeof data.payload !== 'string') {
          if (assignment && assignment.deviceId !== data.deviceId) {
            if (!recordSessionOwnershipAbuse(req)) {
              return reply(res, 503, {
                success: false,
                error: 'SECURITY_STATE_CAPACITY',
                retryAfterSeconds: 5
              });
            }
          }
          return reply(res, 403, {
            success: false,
            error: 'DEVICE_CHANNEL_NOT_AUTHORIZED',
            trafficForwarding: false
          });
        }

        const result = await sessionBridge.deviceSend(
          sessionId, data.deviceId, token, data.payload
        );
        return reply(res, 200, {
          success: true,
          ...result,
          trafficForwarding: false
        });
      }

      if (url.pathname === '/agent/session/receive') {
        const assignment = deviceAssignments.get(sessionId);
        const token = deviceBridgeTokens.get(sessionId);

        if (!assignment ||
            assignment.deviceId !== data.deviceId ||
            !token ||
            Date.parse(assignment.expiresAt) <= Date.now()) {
          if (assignment && assignment.deviceId !== data.deviceId) {
            if (!recordSessionOwnershipAbuse(req)) {
              return reply(res, 503, {
                success: false,
                error: 'SECURITY_STATE_CAPACITY',
                retryAfterSeconds: 5
              });
            }
          }
          return reply(res, 403, {
            success: false,
            error: 'DEVICE_CHANNEL_NOT_AUTHORIZED',
            trafficForwarding: false
          });
        }

        const result = await sessionBridge.deviceReceive(
          sessionId, data.deviceId, token
        );
        return reply(res, 200, {
          success: true,
          ...result,
          trafficForwarding: false
        });
      }

      if (url.pathname === '/agent/session/close') {
        const assignment = deviceAssignments.get(sessionId);

        if (!assignment || assignment.deviceId !== data.deviceId) {
          if (assignment && assignment.deviceId !== data.deviceId) {
            if (!recordSessionOwnershipAbuse(req)) {
              return reply(res, 503, {
                success: false,
                error: 'SECURITY_STATE_CAPACITY',
                retryAfterSeconds: 5
              });
            }
          }
          return reply(res, 403, {
            success: false,
            error: 'DEVICE_SESSION_NOT_OWNED',
            trafficForwarding: false
          });
        }

        const report = data.agentReport;
        const suppliedHash = String(data.agentReportHash || '').toLowerCase();

        if (!report || typeof report !== 'object' ||
            Array.isArray(report) ||
            report.reportVersion !== 1 ||
            report.sessionId !== sessionId ||
            report.deviceId !== data.deviceId) {
          return reply(res, 400, {
            success: false,
            error: 'INVALID_AGENT_TRAFFIC_REPORT',
            trafficForwarding: false
          });
        }

        const bytesSent = report.bytesSent;
        const bytesReceived = report.bytesReceived;
        const totalBytes = report.totalBytes;

        if (![bytesSent, bytesReceived, totalBytes].every(
              value => Number.isSafeInteger(value) && value >= 0
            ) ||
            bytesSent + bytesReceived !== totalBytes ||
            !Number.isSafeInteger(bytesSent + bytesReceived) ||
            !/^[a-f0-9]{64}$/.test(suppliedHash)) {
          return reply(res, 400, {
            success: false,
            error: 'INVALID_AGENT_TRAFFIC_COUNTERS',
            trafficForwarding: false
          });
        }

        const expectedHash = crypto.createHash('sha256')
          .update(JSON.stringify(report), 'utf8')
          .digest('hex');

        const suppliedBuffer = Buffer.from(suppliedHash, 'hex');
        const expectedBuffer = Buffer.from(expectedHash, 'hex');

        if (!crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)) {
          return reply(res, 400, {
            success: false,
            error: 'AGENT_REPORT_HASH_MISMATCH',
            trafficForwarding: false
          });
        }

        try { await sessionBridge.close(sessionId); } catch {}

        const gatewayReport = {
          reportVersion: 1,
          sessionId,
          deviceId: data.deviceId,
          bytesSent,
          bytesReceived,
          totalBytes,
          agentReportHash: suppliedHash,
          gatewayId: GATEWAY_ID
        };

        const gatewayReportHash = crypto.createHash('sha256')
          .update(JSON.stringify(gatewayReport), 'utf8')
          .digest('hex');

        try {
          try {
            await transitionCoreForDevice(sessionId, 'CLOSING');
          } catch (error) {
            if (error.statusCode !== 409) throw error;
          }

          await transitionCoreForDevice(sessionId, 'COMPLETED', {
            reportHash: gatewayReportHash,
            gatewayReport,
            agentReport: report,
            agentReportHash: suppliedHash
          });
        } catch (error) {
          return reply(res, 502, {
            success: false,
            error: error.message || 'CORE_SESSION_COMPLETION_FAILED',
            trafficForwarding: false,
            payable: false
          });
        }

        deviceAssignments.delete(sessionId);
        deviceBridgeTokens.delete(sessionId);
        buyerBridgeTokens.delete(sessionId);

        return reply(res, 200, {
          success: true,
          closed: true,
          agentReportAccepted: true,
          agentReportHash: suppliedHash,
          traffic: {
            bytesSent,
            bytesReceived,
            totalBytes
          },
          trafficForwarding: false,
          payable: false,
          reconciliationStatus: 'pending'
        });
      }
    } catch (error) {
      const message = String(error?.message || 'SESSION_OPERATION_FAILED');
      const status = (
        message === 'CHANNEL_BACKPRESSURE' ||
        message === 'CHANNEL_CAPACITY_LIMIT'
      )
        ? 429
        : /NOT_FOUND|EXPIRED|ALREADY|INVALID/.test(message)
          ? 409
          : 502;

      return reply(res, status, {
        success: false,
        error: message,
        trafficForwarding: false
      });
    }
  }

  if (RELAY_GATEWAY_TOKEN.length < 32 || GATEWAY_ID.length < 3) {
    return reply(res, 503, {
      error: 'GATEWAY_CORE_CREDENTIALS_NOT_CONFIGURED',
      trafficForwarding: false
    });
  }

  try {
    const coreResponse = await fetch(
      new URL('/api/relay/gateway/next', CORE_URL),
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${RELAY_GATEWAY_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          gatewayId: GATEWAY_ID,
          deviceId: data.deviceId
        }),
        signal: AbortSignal.timeout(10000)
      }
    );

    let coreData;
    try {
      coreData = await coreResponse.json();
    } catch {
      return reply(res, 502, {
        error: 'INVALID_CORE_RESPONSE',
        trafficForwarding: false
      });
    }

    if (!coreResponse.ok || coreData.success !== true) {
      return reply(res, coreResponse.status, {
        ...coreData,
        ok: false,
        deviceId: data.deviceId,
        gatewayId: GATEWAY_ID,
        trafficForwarding: false
      });
    }

    let normalizedAssignment = null;

    if (coreData.assignment) {
      const item = coreData.assignment;

      normalizedAssignment = {
        sessionId: item.session_id,
        nodeId: item.node_id,
        deviceId: item.device_id,
        customerId: item.customer_id,
        orderId: item.order_id,
        destinationHost: item.destination_host,
        destinationPort: Number(item.destination_port),
        protocol: String(item.protocol || '').toLowerCase(),
        expiresAt: item.expires_at,
        providerId: item.provider_id,
        buyerRequestId: item.buyer_request_id,
        status: 'AUTHORIZED'
      };

      if (
        normalizedAssignment.deviceId !== data.deviceId ||
        normalizedAssignment.protocol !== 'tcp' ||
        !Number.isInteger(normalizedAssignment.destinationPort) ||
        ![80, 443].includes(normalizedAssignment.destinationPort) ||
        !normalizedAssignment.destinationHost ||
        !normalizedAssignment.expiresAt ||
        Date.parse(normalizedAssignment.expiresAt) <= Date.now()
      ) {
        return reply(res, 409, {
          success: false,
          error: 'INVALID_DEVICE_ASSIGNMENT',
          trafficForwarding: false
        });
      }

      try {
        await resolvePublicDestination(
          normalizedAssignment.destinationHost
        );
      } catch (error) {
        const reasonCode = String(
          error?.message || 'DESTINATION_POLICY_REJECTED'
        ).replace(/[^A-Z0-9_]/gi, '_').toUpperCase().slice(0, 100);

        const dedupeKey = crypto.createHash('sha256')
          .update([
            'DESTINATION_BLOCKED',
            normalizedAssignment.sessionId,
            normalizedAssignment.deviceId,
            normalizedAssignment.destinationHost,
            normalizedAssignment.destinationPort,
            reasonCode
          ].join('|'))
          .digest('hex');

        try {
          await recordRoarNetSecurityEvent({
            eventType: 'DESTINATION_BLOCKED',
            severity: /SPAMHAUS|PHISHTANK/.test(reasonCode)
              ? 'high'
              : 'medium',
            reasonCode,
            sessionId: normalizedAssignment.sessionId,
            deviceId: normalizedAssignment.deviceId,
            destinationHost: normalizedAssignment.destinationHost,
            destinationPort: normalizedAssignment.destinationPort,
            dedupeKey
          });
        } catch (loggingError) {
          console.error(
            '[RoarNet security event delivery failed]',
            loggingError.message
          );
        }

        return reply(res, 409, {
          success: false,
          error: error?.message || 'DESTINATION_POLICY_REJECTED',
          trafficForwarding: false
        });
      }

      deviceAssignments.set(
        normalizedAssignment.sessionId,
        normalizedAssignment
      );
    }

    return reply(res, 200, {
      success: true,
      ok: true,
      deviceId: data.deviceId,
      gatewayId: GATEWAY_ID,
      assignment: normalizedAssignment,
      reason: coreData.reason || null,
      status: coreData.status || null,
      trafficForwarding: false
    });
  } catch {
    return reply(res, 502, {
      error: 'ROARNET_CORE_UNAVAILABLE',
      trafficForwarding: false
    });
  }
});

// HTTP resource and slow-client protections.
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.timeout = 30_000;
server.maxHeadersCount = 50;

setInterval(() => {
  const now = Date.now();
  const cutoff = now - DEVICE_TTL_MS;

  for (const [key, state] of rateLimits) {
    if (state.resetAt <= now) rateLimits.delete(key);
  }

  for (const [key, state] of authFailures) {
    const windowExpired =
      now - state.windowStartedAt >= AUTH_FAILURE_WINDOW_MS;
    const blockExpired =
      !state.blockedUntil || state.blockedUntil <= now;

    if (windowExpired && blockExpired) authFailures.delete(key);
  }

  for (const [deviceId, state] of devices) {
    if (Date.parse(state.lastSeenAt) < cutoff) {
      devices.delete(deviceId);
    }
  }

  for (const [sessionId, assignment] of deviceAssignments) {
    const expiresAt = Date.parse(assignment?.expiresAt);

    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      deviceAssignments.delete(sessionId);
      deviceBridgeTokens.delete(sessionId);
      buyerBridgeTokens.delete(sessionId);
      sessionBridge.close(sessionId, 'ASSIGNMENT_EXPIRED');
    }
  }

  sessionBridge.stats();
}, 30_000).unref();

try {
  await initializeThreatIntelligence();
} catch (error) {
  console.error('[RoarNet] Threat intelligence initialization error:', error.message);
}


console.log('[RoarNet] Threat intelligence status:', getThreatIntelligenceStatus());

try {
  await initializePhishTank();
} catch (error) {
  console.error('[RoarNet] PhishTank initialization error:', error.message);
}

console.log('[RoarNet] PhishTank status:', getPhishTankStatus());

setInterval(async () => {
  await refreshPhishTankIfDue();
}, 60 * 60 * 1000).unref();


setInterval(async () => {
  await refreshThreatIntelligenceIfDue();
}, 24 * 60 * 60 * 1000).unref();

server.listen(PORT, HOST, () => {
  console.log(`RoarNet Relay Gateway listening on ${HOST}:${PORT}`);
  console.log('Mode: authenticated control only; traffic forwarding disabled.');
});
