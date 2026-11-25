import http from 'node:http';
import crypto from 'node:crypto';
import { resolvePublicDestination } from './destination-policy.mjs';
import { openTcpSession } from './tcp-engine.mjs';
import { createGatewaySessionRuntime } from './gateway-session-runtime.mjs';
import { createSessionBridge } from './session-bridge.mjs';
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
  const token = bearer(req);

  if (token.length < 20 || token.length > 4096) {
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
      devices.delete(deviceId);
      sessionBridge.revokeDevice(deviceId);
      reply(res, result.status === 200 ? 403 : result.status, {
        error: result.status === 200
          ? 'Device consent is not active'
          : 'Device authorization failed',
        accepted: false
      });
      return null;
    }

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


async function transitionCoreForDevice(sessionId, targetStatus, extra = {}) {
  if (RELAY_GATEWAY_TOKEN.length < 32 || GATEWAY_ID.length < 3) {
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
  const expiresAt = Date.parse(assignment?.expiresAt || '');

  if (!assignment || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    return null;
  }

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

function clearBridgeSession(sessionId, reason = 'SESSION_CLOSED') {
  sessionBridge.close(sessionId, reason);
  deviceBridgeTokens.delete(sessionId);
  buyerBridgeTokens.delete(sessionId);
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
      const agentReport = data.agentReport;
      const agentReportHash = String(data.agentReportHash || '').toLowerCase();
      const gatewayReport = data.gatewayReport;

      if (
        !agentReport ||
        typeof agentReport !== 'object' ||
        Array.isArray(agentReport) ||
        !gatewayReport ||
        typeof gatewayReport !== 'object' ||
        Array.isArray(gatewayReport) ||
        !/^[a-f0-9]{64}$/.test(agentReportHash)
      ) {
        return reply(res, 400, {
          error: 'GATEWAY_AGENT_REPORT_REQUIRED',
          trafficForwarding: false
        });
      }

      payload.reportHash = reportHash;
      payload.agentReport = agentReport;
      payload.agentReportHash = agentReportHash;
      payload.gatewayReport = gatewayReport;
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


  // Internal buyer data channel.
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

    let buyerData;
    try {
      buyerData = await readJson(req);
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
          typeof buyerData.data !== 'string' ||
          buyerData.data.length < 4 ||
          buyerData.data.length > 87384 ||
          !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(buyerData.data)
        ) {
          return reply(res, 400, {
            error: 'INVALID_BASE64_DATA'
          });
        }

        const decoded = Buffer.from(buyerData.data, 'base64');

        if (
          decoded.length < 1 ||
          decoded.length > 64 * 1024 ||
          decoded.toString('base64') !== buyerData.data
        ) {
          return reply(res, 413, {
            error: 'BUYER_CHUNK_SIZE_INVALID'
          });
        }

        const result = await sessionBridge.customerSend(
          sessionId,
          context.customerId,
          channelToken,
          buyerData.data
        );

        return reply(res, 200, {
          success: true,
          result
        });
      }

      const maxItems = Number(buyerData.maxItems ?? 16);

      if (
        !Number.isInteger(maxItems) ||
        maxItems < 1 ||
        maxItems > 16
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

  let data;

  try {
    data = await readJson(req);
  } catch (error) {
    return reply(res, error.message === 'PAYLOAD_TOO_LARGE' ? 413 : 400, {
      error: 'Invalid JSON request'
    });
  }

  const authorization = await authenticate(
    req,
    res,
    String(data.deviceId || '')
  );
  if (!authorization) return;

  if (url.pathname === '/agent/heartbeat') {
    return reply(res, 200, {
      ok: true,
      deviceId: data.deviceId,
      connected: true,
      consentAccepted: true,
      gatewayMode: 'participant-device-tcp-bridge',
      gatewayId: GATEWAY_ID || null,
      activeSessions: sessionBridge.stats().activeChannels
    });
  }

  if (url.pathname.startsWith('/agent/session/')) {
    const sessionId = String(data.sessionId || '');

    if (!/^[A-Za-z0-9_-]{8,100}$/.test(sessionId)) {
      return reply(res, 400, { error: 'INVALID_SESSION_ID' });
    }

    const assignment = deviceAssignments.get(sessionId);
    const expiresAt = Date.parse(assignment?.expiresAt || '');
    const ownsAssignment =
      Boolean(assignment) &&
      assignment.deviceId === data.deviceId &&
      Number.isFinite(expiresAt) &&
      expiresAt > Date.now();

    try {
      if (url.pathname === '/agent/session/open') {
        if (!ownsAssignment || authorization.accepted !== true) {
          return reply(res, 409, {
            success: false,
            error: 'DEVICE_ASSIGNMENT_NOT_AVAILABLE',
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
        if (
          !ownsAssignment ||
          authorization.accepted !== true ||
          data.connected !== true
        ) {
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

          if (!opened?.deviceToken || !opened?.customerToken) {
            throw new Error('DEVICE_CHANNEL_OPEN_FAILED');
          }

          deviceToken = opened.deviceToken;
          deviceBridgeTokens.set(sessionId, deviceToken);
          buyerBridgeTokens.set(sessionId, opened.customerToken);
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
        const token = deviceBridgeTokens.get(sessionId);

        if (!ownsAssignment || !token || typeof data.payload !== 'string') {
          return reply(res, 403, {
            success: false,
            error: 'DEVICE_CHANNEL_NOT_AUTHORIZED',
            trafficForwarding: false
          });
        }

        const result = await sessionBridge.deviceSend(
          sessionId,
          data.deviceId,
          token,
          data.payload
        );

        return reply(res, 200, {
          success: true,
          ...result,
          trafficForwarding: false
        });
      }

      if (url.pathname === '/agent/session/receive') {
        const token = deviceBridgeTokens.get(sessionId);

        if (!ownsAssignment || !token) {
          return reply(res, 403, {
            success: false,
            error: 'DEVICE_CHANNEL_NOT_AUTHORIZED',
            trafficForwarding: false
          });
        }

        const result = await sessionBridge.deviceReceive(
          sessionId,
          data.deviceId,
          token,
          16
        );

        return reply(res, 200, {
          success: true,
          ...result,
          trafficForwarding: false
        });
      }

      if (url.pathname === '/agent/session/close') {
        if (!assignment || assignment.deviceId !== data.deviceId) {
          return reply(res, 403, {
            success: false,
            error: 'DEVICE_SESSION_NOT_OWNED'
          });
        }

        const report = data.agentReport;
        const suppliedHash = String(data.agentReportHash || '');

        if (
          !report ||
          typeof report !== 'object' ||
          report.reportVersion !== 1 ||
          report.sessionId !== sessionId ||
          report.deviceId !== data.deviceId ||
          !Number.isSafeInteger(report.bytesSent) ||
          !Number.isSafeInteger(report.bytesReceived) ||
          !Number.isSafeInteger(report.totalBytes) ||
          report.bytesSent < 0 ||
          report.bytesReceived < 0 ||
          report.totalBytes !== report.bytesSent + report.bytesReceived ||
          !/^[a-f0-9]{64}$/i.test(suppliedHash)
        ) {
          return reply(res, 400, {
            success: false,
            error: 'INVALID_AGENT_TRAFFIC_REPORT'
          });
        }

        const calculatedAgentHash = crypto
          .createHash('sha256')
          .update(JSON.stringify(report))
          .digest('hex');

        if (calculatedAgentHash !== suppliedHash.toLowerCase()) {
          return reply(res, 400, {
            success: false,
            error: 'AGENT_REPORT_HASH_MISMATCH'
          });
        }

        const gatewayReport = {
          reportVersion: 1,
          sessionId,
          deviceId: data.deviceId,
          gatewayId: GATEWAY_ID,
          agentReportHash: calculatedAgentHash,
          bytesSent: report.bytesSent,
          bytesReceived: report.bytesReceived,
          totalBytes: report.totalBytes
        };

        const reportHash = crypto
          .createHash('sha256')
          .update(JSON.stringify(gatewayReport))
          .digest('hex');

        try {
          await transitionCoreForDevice(sessionId, 'CLOSING');
        } catch (transitionError) {
          if (transitionError.statusCode !== 409) throw transitionError;
        }

        await transitionCoreForDevice(sessionId, 'COMPLETED', {
          reportHash,
          agentReport: report,
          agentReportHash: calculatedAgentHash,
          gatewayReport
        });

        clearBridgeSession(sessionId, 'SESSION_COMPLETED');
        deviceAssignments.delete(sessionId);

        return reply(res, 200, {
          success: true,
          trafficForwarding: false,
          payable: false,
          reconciliationStatus: 'pending',
          reportHash
        });
      }
    } catch (error) {
      const message = String(
        error?.message || 'SESSION_OPERATION_FAILED'
      );

      const status = error.statusCode ||
        (/NOT_FOUND|EXPIRED|ALREADY|INVALID|MISMATCH/.test(message)
          ? 409
          : 502);

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

      try {
        sessionRuntime.registerAssignment(
          data.deviceId,
          normalizedAssignment
        );

        if (
          !normalizedAssignment.sessionId ||
          normalizedAssignment.deviceId !== data.deviceId ||
          !normalizedAssignment.customerId ||
          !Number.isFinite(Date.parse(normalizedAssignment.expiresAt)) ||
          Date.parse(normalizedAssignment.expiresAt) <= Date.now()
        ) {
          throw new Error('INVALID_NORMALIZED_ASSIGNMENT');
        }

        deviceAssignments.set(
          normalizedAssignment.sessionId,
          normalizedAssignment
        );
      } catch (error) {
        return reply(res, 409, {
          success: false,
          error: String(error?.message || 'ASSIGNMENT_REGISTRATION_FAILED'),
          trafficForwarding: false
        });
      }
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

setInterval(() => {
  const cutoff = Date.now() - DEVICE_TTL_MS;

  for (const [deviceId, state] of devices) {
    if (Date.parse(state.lastSeenAt) < cutoff) {
      devices.delete(deviceId);
    }
  }
}, 30_000).unref();

server.listen(PORT, HOST, () => {
  console.log(`RoarNet Relay Gateway listening on ${HOST}:${PORT}`);
  console.log('Mode: authenticated control only; traffic forwarding disabled.');
});
