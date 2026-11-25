import crypto from 'node:crypto';

const MAX_CHUNK_BYTES = 64 * 1024;
const MAX_QUEUE_BYTES = 1024 * 1024;
const DEFAULT_TTL_MS = 10 * 60 * 1000;

export function createBuyerDataChannel({
  maxChunkBytes = MAX_CHUNK_BYTES,
  maxQueueBytes = MAX_QUEUE_BYTES,
  ttlMs = DEFAULT_TTL_MS,
  maxChannels = 256,
  maxChannelsPerDevice = 4,
  maxChannelsPerCustomer = 8,
  maxQueueItems = 256,
  maxTotalQueueBytes = 32 * 1024 * 1024
} = {}) {
  if (!Number.isInteger(maxChunkBytes) || maxChunkBytes < 1 ||
      !Number.isInteger(maxQueueBytes) || maxQueueBytes < maxChunkBytes ||
      !Number.isInteger(ttlMs) || ttlMs < 1000 ||
      !Number.isInteger(maxChannels) || maxChannels < 1 ||
      !Number.isInteger(maxChannelsPerDevice) ||
      maxChannelsPerDevice < 1 ||
      maxChannelsPerDevice > maxChannels ||
      !Number.isInteger(maxChannelsPerCustomer) ||
      maxChannelsPerCustomer < 1 ||
      maxChannelsPerCustomer > maxChannels ||
      !Number.isInteger(maxQueueItems) || maxQueueItems < 1 ||
      !Number.isSafeInteger(maxTotalQueueBytes) ||
      maxTotalQueueBytes < maxChunkBytes) {
    throw new Error('INVALID_CHANNEL_LIMITS');
  }

  const channels = new Map();
  let totalQueuedBytes = 0;

  function close(sessionId, reason = 'CLOSED') {
    const channel = channels.get(sessionId);
    if (!channel) return false;

    channel.toDevice.length = 0;
    channel.toBuyer.length = 0;

    totalQueuedBytes = Math.max(
      0,
      totalQueuedBytes - channel.queuedBytes
    );

    channel.queuedBytes = 0;
    channel.queuedItems = 0;
    channel.customerToken = '';
    channel.deviceToken = '';
    channel.closeReason = String(reason).slice(0, 80);
    channels.delete(sessionId);

    return true;
  }

  function cleanupExpired() {
    const now = Date.now();

    for (const [sessionId, channel] of channels) {
      if (now >= channel.expiresAt) {
        close(sessionId, 'EXPIRED');
      }
    }
  }

  function getChannel(sessionId) {
    const channel = channels.get(sessionId);
    if (!channel) throw new Error('CHANNEL_NOT_FOUND');

    if (Date.now() >= channel.expiresAt) {
      close(sessionId, 'EXPIRED');
      throw new Error('CHANNEL_EXPIRED');
    }

    return channel;
  }

  function create({ sessionId, customerId, deviceId, authorized }) {
    if (authorized !== true) {
      throw new Error('SESSION_NOT_AUTHORIZED');
    }

    if (typeof sessionId !== 'string' || !sessionId ||
        typeof customerId !== 'string' || !customerId ||
        typeof deviceId !== 'string' || !deviceId) {
      throw new Error('INVALID_CHANNEL_IDENTITY');
    }

    cleanupExpired();

    if (channels.has(sessionId)) {
      throw new Error('CHANNEL_ALREADY_EXISTS');
    }

    if (channels.size >= maxChannels) {
      throw new Error('CHANNEL_CAPACITY_LIMIT');
    }

    let deviceChannels = 0;
    let customerChannels = 0;

    for (const channel of channels.values()) {
      if (channel.deviceId === deviceId) deviceChannels++;
      if (channel.customerId === customerId) customerChannels++;
    }

    if (deviceChannels >= maxChannelsPerDevice ||
        customerChannels >= maxChannelsPerCustomer) {
      throw new Error('CHANNEL_CAPACITY_LIMIT');
    }

    const customerToken = crypto.randomBytes(32).toString('hex');
    const deviceToken = crypto.randomBytes(32).toString('hex');
    const now = Date.now();

    const channel = {
      sessionId,
      customerId,
      deviceId,
      customerToken,
      deviceToken,
      toDevice: [],
      toBuyer: [],
      queuedBytes: 0,
      queuedItems: 0,
      createdAt: now,
      expiresAt: now + ttlMs
    };

    channels.set(sessionId, channel);

    return {
      sessionId,
      customerToken,
      deviceToken,
      expiresAt: channel.expiresAt
    };
  }

  function authenticate(sessionId, role, identity, token) {
    const channel = getChannel(sessionId);

    const expectedIdentity =
      role === 'customer' ? channel.customerId :
      role === 'device' ? channel.deviceId : null;

    const expectedToken =
      role === 'customer' ? channel.customerToken :
      role === 'device' ? channel.deviceToken : null;

    const identityValue =
      role === 'customer' ? identity?.customerId :
      role === 'device' ? identity?.deviceId : null;

    if (!expectedIdentity || identityValue !== expectedIdentity) {
      throw new Error('CHANNEL_IDENTITY_MISMATCH');
    }

    if (typeof token !== 'string' ||
        token.length !== expectedToken.length ||
        !crypto.timingSafeEqual(
          Buffer.from(token),
          Buffer.from(expectedToken)
        )) {
      throw new Error('INVALID_CHANNEL_TOKEN');
    }

    return channel;
  }

  function decodeChunk(data) {
    if (typeof data !== 'string' ||
        data.length === 0 ||
        data.length > Math.ceil(maxChunkBytes / 3) * 4 + 4 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data)) {
      throw new Error('INVALID_CHUNK');
    }

    const bytes = Buffer.from(data, 'base64');

    if (bytes.length === 0 ||
        bytes.length > maxChunkBytes ||
        bytes.toString('base64') !== data) {
      throw new Error('CHUNK_SIZE_LIMIT');
    }

    return bytes;
  }

  function enqueue(sessionId, direction, data, identity, token) {
    const role = direction === 'toDevice' ? 'customer' :
      direction === 'toBuyer' ? 'device' : null;

    if (!role) throw new Error('INVALID_CHANNEL_DIRECTION');

    const channel = authenticate(sessionId, role, identity, token);
    const bytes = decodeChunk(data);

    if (channel.queuedBytes + bytes.length > maxQueueBytes ||
        channel.queuedItems >= maxQueueItems ||
        totalQueuedBytes + bytes.length > maxTotalQueueBytes) {
      throw new Error('CHANNEL_BACKPRESSURE');
    }

    channel[direction].push({
      id: crypto.randomUUID(),
      data: bytes.toString('base64'),
      bytes: bytes.length,
      createdAt: Date.now()
    });

    channel.queuedBytes += bytes.length;
    channel.queuedItems++;
    totalQueuedBytes += bytes.length;

    return { accepted: true, bytes: bytes.length };
  }

  function receive(sessionId, direction, identity, token, maxItems = 16) {
    const role = direction === 'toDevice' ? 'device' :
      direction === 'toBuyer' ? 'customer' : null;

    if (!role) throw new Error('INVALID_CHANNEL_DIRECTION');

    const channel = authenticate(sessionId, role, identity, token);
    const count = Math.max(1, Math.min(16, Number(maxItems) || 1));
    const items = channel[direction].splice(0, count);

    for (const item of items) {
      channel.queuedBytes -= item.bytes;
      channel.queuedItems--;
      totalQueuedBytes -= item.bytes;
    }

    return {
      sessionId,
      items,
      queuedBytes: channel.queuedBytes,
      closed: false
    };
  }

  function closeForDevice(deviceId, reason = 'CONSENT_REVOKED') {
    let count = 0;

    for (const [sessionId, channel] of channels) {
      if (channel.deviceId === deviceId) {
        close(sessionId, reason);
        count++;
      }
    }

    return count;
  }

  function closeForCustomer(customerId, reason = 'CUSTOMER_CANCELLED') {
    let count = 0;

    for (const [sessionId, channel] of channels) {
      if (channel.customerId === customerId) {
        close(sessionId, reason);
        count++;
      }
    }

    return count;
  }

  function stats() {
    cleanupExpired();

    return {
      activeChannels: channels.size,
      queuedBytes: totalQueuedBytes,
      maxChunkBytes,
      maxQueueBytes,
      maxChannels,
      maxChannelsPerDevice,
      maxChannelsPerCustomer,
      maxQueueItems,
      maxTotalQueueBytes
    };
  }

  return {
    create,
    enqueue,
    receive,
    close,
    closeForDevice,
    closeForCustomer,
    stats
  };
}
