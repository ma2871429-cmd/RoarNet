import { createBuyerDataChannel } from './buyer-data-channel.mjs';

export function createSessionBridge({
  resolveSession,
  channelOptions = {}
} = {}) {
  if (typeof resolveSession !== 'function') {
    throw new Error('SESSION_RESOLVER_REQUIRED');
  }

  const channel = createBuyerDataChannel(channelOptions);
  const bindings = new Map();
  const pendingOpens = new Set();

  function cleanupExpiredBindings() {
    const now = Date.now();
    let cleaned = 0;

    for (const [sessionId, binding] of bindings) {
      if (!Number.isFinite(binding.expiresAt) ||
          now >= binding.expiresAt) {
        bindings.delete(sessionId);
        channel.close(sessionId, 'EXPIRED');
        cleaned++;
      }
    }

    return cleaned;
  }

  async function activeSession(sessionId) {
    const session = await resolveSession(sessionId);

    if (!session ||
        session.status !== 'ACTIVE' ||
        !session.sessionId ||
        session.sessionId !== sessionId ||
        !session.customerId ||
        !session.deviceId ||
        session.consentActive !== true) {
      channel.close(sessionId, 'SESSION_NOT_ACTIVE');
      bindings.delete(sessionId);
      throw new Error('SESSION_NOT_ACTIVE');
    }

    return session;
  }

  async function verifyBinding(sessionId) {
    cleanupExpiredBindings();
    const session = await activeSession(sessionId);
    const binding = bindings.get(sessionId);

    if (!binding ||
        binding.customerId !== session.customerId ||
        binding.deviceId !== session.deviceId) {
      channel.close(sessionId, 'SESSION_BINDING_CHANGED');
      bindings.delete(sessionId);
      throw new Error('SESSION_BINDING_CHANGED');
    }

    return { session, binding };
  }

  async function open(sessionId) {
    cleanupExpiredBindings();

    if (bindings.has(sessionId) || pendingOpens.has(sessionId)) {
      throw new Error('SESSION_CHANNEL_ALREADY_OPEN');
    }

    pendingOpens.add(sessionId);

    try {
      const session = await activeSession(sessionId);

      const credentials = channel.create({
        sessionId,
        customerId: session.customerId,
        deviceId: session.deviceId,
        authorized: true
      });

      bindings.set(sessionId, {
        customerId: session.customerId,
        deviceId: session.deviceId,
        expiresAt: credentials.expiresAt
      });

      return {
        sessionId,
        customerToken: credentials.customerToken,
        deviceToken: credentials.deviceToken,
        expiresAt: credentials.expiresAt
      };
    } finally {
      pendingOpens.delete(sessionId);
    }
  }

  async function customerSend(sessionId, customerId, token, data) {
    const { session } = await verifyBinding(sessionId);

    if (customerId !== session.customerId) {
      throw new Error('CUSTOMER_SESSION_MISMATCH');
    }

    return channel.enqueue(
      sessionId,
      'toDevice',
      data,
      { customerId },
      token
    );
  }

  async function deviceSend(sessionId, deviceId, token, data) {
    const { session } = await verifyBinding(sessionId);

    if (deviceId !== session.deviceId) {
      throw new Error('DEVICE_SESSION_MISMATCH');
    }

    return channel.enqueue(
      sessionId,
      'toBuyer',
      data,
      { deviceId },
      token
    );
  }

  async function deviceReceive(sessionId, deviceId, token, maxItems) {
    const { session } = await verifyBinding(sessionId);

    if (deviceId !== session.deviceId) {
      throw new Error('DEVICE_SESSION_MISMATCH');
    }

    return channel.receive(
      sessionId,
      'toDevice',
      { deviceId },
      token,
      maxItems
    );
  }

  async function customerReceive(sessionId, customerId, token, maxItems) {
    const { session } = await verifyBinding(sessionId);

    if (customerId !== session.customerId) {
      throw new Error('CUSTOMER_SESSION_MISMATCH');
    }

    return channel.receive(
      sessionId,
      'toBuyer',
      { customerId },
      token,
      maxItems
    );
  }

  function close(sessionId, reason = 'SESSION_CLOSED') {
    bindings.delete(sessionId);
    return channel.close(sessionId, reason);
  }

  function revokeDevice(deviceId) {
    let count = 0;

    for (const [sessionId, binding] of bindings) {
      if (binding.deviceId === deviceId) {
        bindings.delete(sessionId);
        if (channel.close(sessionId, 'CONSENT_REVOKED')) count++;
      }
    }

    return count;
  }

  function closeForCustomer(customerId) {
    let count = 0;

    for (const [sessionId, binding] of bindings) {
      if (binding.customerId === customerId) {
        bindings.delete(sessionId);
        if (channel.close(sessionId, 'CUSTOMER_CANCELLED')) count++;
      }
    }

    return count;
  }

  function stats() {
    cleanupExpiredBindings();

    return {
      ...channel.stats(),
      boundSessions: bindings.size,
      pendingOpens: pendingOpens.size
    };
  }

  return {
    open,
    customerSend,
    customerReceive,
    deviceSend,
    deviceReceive,
    close,
    revokeDevice,
    closeForCustomer,
    stats
  };
}
