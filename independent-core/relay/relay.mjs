import http from 'node:http';
import crypto from 'node:crypto';

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const relayDir = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.resolve(relayDir, '..', '.env');

if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z_]+)=(.*)$/);
    if (m && process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2].trim();
    }
  }
}


const CORE_URL = process.env.CORE_URL || 'http://127.0.0.1:3180';
const RELAY_TOKEN = process.env.RELAY_TOKEN || '';
const PORT = Number(process.env.RELAY_PORT || 3181);

if (RELAY_TOKEN.length < 32) {
  console.error('RELAY_TOKEN must be configured with at least 32 characters.');
  process.exit(1);
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');

  const reply = (status, value) => {
    res.writeHead(status);
    res.end(JSON.stringify(value));
  };

  if (req.method === 'GET' && req.url === '/health') {
    return reply(200, {
      app: 'RoarNet Relay Test',
      status: 'running',
      mode: 'metering-test-only'
    });
  }

  if (req.method !== 'POST' || req.url !== '/usage') {
    return reply(404, { error: 'Not found' });
  }

  const auth = req.headers.authorization || '';
  const supplied = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const a = crypto.createHash('sha256').update(supplied).digest();
  const b = crypto.createHash('sha256').update(RELAY_TOKEN).digest();

  if (!supplied || !crypto.timingSafeEqual(a, b)) {
    return reply(401, { error: 'Unauthorized' });
  }

  let raw = '';
  try {
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > 8192) {
        return reply(413, { error: 'Payload too large' });
      }
    }

    const event = JSON.parse(raw);
    const { reference, nodeId, customerId, bytes } = event;

    if (
      typeof reference !== 'string' ||
      !/^[A-Za-z0-9_-]{8,100}$/.test(reference) ||
      typeof nodeId !== 'string' ||
      !/^[0-9a-f-]{36}$/i.test(nodeId) ||
      typeof customerId !== 'string' ||
      !/^[0-9a-f-]{36}$/i.test(customerId) ||
      !Number.isSafeInteger(bytes) ||
      bytes < 1 ||
      bytes > 100 * 1024 * 1024
    ) {
      return reply(400, { error: 'Invalid usage event' });
    }

    const upstream = await fetch(`${CORE_URL}/api/relay/usage`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RELAY_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ reference, nodeId, customerId, bytes }),
      signal: AbortSignal.timeout(10000)
    });

    const result = await upstream.text();
    res.writeHead(upstream.status);
    return res.end(result);
  } catch {
    return reply(400, { error: 'Invalid request or core unavailable' });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`RoarNet Relay test listening on 127.0.0.1:${PORT}`);
});
