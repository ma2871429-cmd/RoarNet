import net from 'node:net';
import crypto from 'node:crypto';
import { resolvePublicDestination } from './destination-policy.mjs';

const MAX_SESSION_BYTES = 10 * 1024 * 1024;
const CONNECT_TIMEOUT_MS = 10000;
const IDLE_TIMEOUT_MS = 60000;

function makeReportHash(report) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(report))
    .digest('hex');
}

export async function openTcpSession({
  host,
  port,
  authorized,
  consentActive,
  maxBytes = MAX_SESSION_BYTES,
  onData = () => {},
  onClosed = () => {},
  resolveDestination = resolvePublicDestination
}) {
  if (authorized !== true || consentActive !== true) {
    throw new Error('SESSION_NOT_AUTHORIZED');
  }

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('INVALID_DESTINATION_PORT');
  }

  if (!Number.isSafeInteger(maxBytes) ||
      maxBytes < 1 || maxBytes > MAX_SESSION_BYTES) {
    throw new Error('INVALID_SESSION_BYTE_LIMIT');
  }

  if (typeof onData !== 'function' ||
      typeof onClosed !== 'function' ||
      typeof resolveDestination !== 'function') {
    throw new Error('INVALID_SESSION_CALLBACK');
  }

  const records = await resolveDestination(host);
  if (!Array.isArray(records) || records.length === 0) {
    throw new Error('DESTINATION_NOT_RESOLVED');
  }

  const selected = records[0];
  if (!selected ||
      net.isIP(selected.address) === 0 ||
      ![4, 6].includes(selected.family)) {
    throw new Error('INVALID_RESOLVED_DESTINATION');
  }

  const socket = new net.Socket();
  socket.setNoDelay(true);
  socket.setTimeout(IDLE_TIMEOUT_MS);

  let bytesSent = 0;
  let bytesReceived = 0;
  let pendingBytes = 0;
  let startedAt = null;
  let endedAt = null;
  let failureCode = null;
  let closed = false;
  let report = null;

  let resolveFinished;
  const finished = new Promise(resolve => {
    resolveFinished = resolve;
  });

  function buildReport() {
    const data = {
      destinationHost: String(host),
      destinationPort: port,
      destinationAddress: selected.address,
      startedAt,
      endedAt,
      bytesSent,
      bytesReceived,
      totalBytes: bytesSent + bytesReceived,
      measurement: 'gateway-socket-byte-count-v2',
      failureCode
    };

    return {
      ...data,
      reportHash: makeReportHash(data)
    };
  }

  socket.once('close', () => {
    closed = true;
    endedAt = new Date().toISOString();
    report = buildReport();

    try {
      onClosed(report);
    } catch {}

    resolveFinished(report);
  });

  socket.on('error', error => {
    failureCode ||= 'TCP_SOCKET_ERROR';
  });

  socket.on('data', chunk => {
    if (closed) return;

    bytesReceived += chunk.length;

    if (bytesSent + bytesReceived + pendingBytes > maxBytes) {
      failureCode = 'SESSION_BYTE_LIMIT';
      socket.destroy();
      return;
    }

    try {
      onData(chunk);
    } catch {
      failureCode = 'AGENT_DATA_HANDLER_FAILED';
      socket.destroy();
    }
  });

  socket.on('timeout', () => {
    failureCode = 'SESSION_IDLE_TIMEOUT';
    socket.destroy();
  });

  await new Promise((resolve, reject) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      failureCode = 'TCP_CONNECT_TIMEOUT';
      socket.destroy();
      reject(new Error('TCP_CONNECT_TIMEOUT'));
    }, CONNECT_TIMEOUT_MS);

    socket.once('connect', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      startedAt = new Date().toISOString();
      resolve();
    });

    socket.once('error', error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });

    socket.connect({
      host: selected.address,
      port,
      family: selected.family
    });
  }).catch(error => {
    socket.destroy();
    throw error;
  });

  function send(chunk) {
    if (closed || socket.destroyed || !socket.writable) {
      throw new Error('TCP_SESSION_CLOSED');
    }

    if (!Buffer.isBuffer(chunk)) {
      throw new Error('BUFFER_REQUIRED');
    }

    if (bytesSent + bytesReceived + pendingBytes + chunk.length > maxBytes) {
      failureCode = 'SESSION_BYTE_LIMIT';
      socket.destroy();
      throw new Error('SESSION_BYTE_LIMIT');
    }

    pendingBytes += chunk.length;

    socket.write(chunk, error => {
      pendingBytes -= chunk.length;

      if (error) {
        failureCode ||= 'TCP_WRITE_FAILED';
        socket.destroy();
        return;
      }

      bytesSent += chunk.length;
    });

    return socket.writableLength === 0;
  }

  function close() {
    if (!closed && !socket.destroyed) socket.end();
    return finished;
  }

  function destroy(code = 'SESSION_DESTROYED') {
    if (!closed && !socket.destroyed) {
      failureCode ||= code;
      socket.destroy();
    }
    return finished;
  }

  function getReport() {
    return report || buildReport();
  }

  return {
    socket,
    send,
    close,
    destroy,
    finished,
    getReport,
    destinationAddress: selected.address
  };
}
