const MAX_CHUNK_BYTES = 64 * 1024;
const MAX_QUEUED_BYTES = 1024 * 1024;

export function createGatewaySessionRuntime({
  openTcpSession,
  transitionCore
}) {
  if (typeof openTcpSession !== 'function' ||
      typeof transitionCore !== 'function') {
    throw new Error('INVALID_RUNTIME_DEPENDENCIES');
  }

  const assignments = new Map();
  const sessions = new Map();

  async function transition(sessionId, targetStatus, extra = {}) {
    const result = await transitionCore(
      sessionId,
      targetStatus,
      extra
    );

    if (!result || (result.success !== true && result.ok !== true)) {
      throw new Error('CORE_SESSION_TRANSITION_FAILED');
    }

    return result;
  }

  async function failSession(sessionId, state, failureCode) {
    if (state.failurePromise) return state.failurePromise;

    state.closed = true;
    state.failureCode ||= failureCode;
    assignments.delete(sessionId);
    sessions.delete(sessionId);

    try {
      state.tcp?.destroy(state.failureCode);
    } catch {}

    state.failurePromise = (async () => {
      try {
        await transition(sessionId, 'FAILED', {
          failureCode: state.failureCode
        });
      } catch {}
    })();

    return state.failurePromise;
  }

  function registerAssignment(deviceId, assignment) {
    if (!deviceId || !assignment ||
        assignment.status !== 'AUTHORIZED' ||
        !assignment.sessionId ||
        assignment.deviceId !== deviceId ||
        assignment.nodeId !== deviceId ||
        assignment.protocol !== 'tcp' ||
        !assignment.destinationHost ||
        !Number.isInteger(assignment.destinationPort) ||
        assignment.destinationPort < 1 ||
        assignment.destinationPort > 65535 ||
        !assignment.expiresAt ||
        Date.parse(assignment.expiresAt) <= Date.now()) {
      throw new Error('INVALID_SESSION_ASSIGNMENT');
    }

    if (assignments.has(assignment.sessionId) ||
        sessions.has(assignment.sessionId)) {
      throw new Error('SESSION_ALREADY_REGISTERED');
    }

    assignments.set(assignment.sessionId, {
      ...assignment,
      deviceId
    });

    return true;
  }

  async function open(deviceId, sessionId, consentActive) {
    const assignment = assignments.get(sessionId);

    if (!assignment || assignment.deviceId !== deviceId) {
      throw new Error('SESSION_ASSIGNMENT_NOT_FOUND');
    }

    if (Date.parse(assignment.expiresAt) <= Date.now()) {
      assignments.delete(sessionId);
      throw new Error('SESSION_ASSIGNMENT_EXPIRED');
    }

    if (consentActive !== true) {
      throw new Error('PARTICIPANT_CONSENT_REQUIRED');
    }

    await transition(sessionId, 'CONNECTING');

    const state = {
      deviceId,
      assignment,
      tcp: null,
      queue: [],
      queuedBytes: 0,
      closed: false,
      opening: true,
      failureCode: null,
      failurePromise: null
    };

    try {
      const tcp = await openTcpSession({
        host: assignment.destinationHost,
        port: assignment.destinationPort,
        authorized: assignment.status === 'AUTHORIZED',
        consentActive: consentActive === true,
        onData(chunk) {
          if (state.closed) return;

          if (state.queuedBytes + chunk.length > MAX_QUEUED_BYTES) {
            state.failureCode = 'AGENT_RECEIVE_QUEUE_LIMIT';
            state.closed = true;

            try {
              state.tcp?.destroy(state.failureCode);
            } catch {}

            if (!state.opening) {
              void failSession(sessionId, state, state.failureCode);
            }
            return;
          }

          state.queue.push(Buffer.from(chunk));
          state.queuedBytes += chunk.length;
        }
      });

      state.tcp = tcp;

      if (state.closed) {
        state.tcp.destroy(state.failureCode || 'SESSION_OPEN_ABORTED');
        throw new Error(state.failureCode || 'SESSION_OPEN_ABORTED');
      }

      sessions.set(sessionId, state);
      assignments.delete(sessionId);

      await transition(sessionId, 'ACTIVE', {
        connected: true
      });

      state.opening = false;

      if (state.closed) {
        await failSession(
          sessionId,
          state,
          state.failureCode || 'SESSION_OPEN_ABORTED'
        );
        throw new Error(state.failureCode || 'SESSION_OPEN_ABORTED');
      }

      return {
        sessionId,
        status: 'ACTIVE'
      };
    } catch (error) {
      state.opening = false;
      assignments.delete(sessionId);
      sessions.delete(sessionId);

      if (state.failurePromise) {
        await state.failurePromise;
      } else {
        try {
          await transition(sessionId, 'FAILED', {
            failureCode: state.failureCode || 'TCP_SESSION_OPEN_FAILED'
          });
        } catch {}
      }

      throw error;
    }
  }

  function send(deviceId, sessionId, encoded) {
    const state = sessions.get(sessionId);

    if (!state || state.deviceId !== deviceId || state.closed) {
      throw new Error('ACTIVE_SESSION_NOT_FOUND');
    }

    if (typeof encoded !== 'string' ||
        encoded.length > Math.ceil(MAX_CHUNK_BYTES * 4 / 3) + 8 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
      throw new Error('INVALID_SESSION_DATA');
    }

    const chunk = Buffer.from(encoded, 'base64');

    if (!chunk.length || chunk.length > MAX_CHUNK_BYTES) {
      throw new Error('SESSION_CHUNK_SIZE_INVALID');
    }

    state.tcp.send(chunk);

    return {
      accepted: true,
      bytes: chunk.length
    };
  }

  function receive(deviceId, sessionId) {
    const state = sessions.get(sessionId);

    if (!state || state.deviceId !== deviceId) {
      throw new Error('ACTIVE_SESSION_NOT_FOUND');
    }

    const chunks = state.queue.splice(0);
    const bytes = state.queuedBytes;
    state.queuedBytes = 0;

    return {
      chunks: chunks.map(chunk => chunk.toString('base64')),
      bytes,
      closed: state.closed
    };
  }

  async function close(deviceId, sessionId) {
    const state = sessions.get(sessionId);

    if (!state || state.deviceId !== deviceId) {
      throw new Error('ACTIVE_SESSION_NOT_FOUND');
    }

    if (state.closed) {
      throw new Error('SESSION_ALREADY_CLOSING');
    }

    state.closed = true;

    try {
      await transition(sessionId, 'CLOSING');

      const report = await state.tcp.close();

      if (!report || !/^[a-f0-9]{64}$/.test(report.reportHash || '')) {
        throw new Error('INVALID_TCP_SESSION_REPORT');
      }

      await transition(sessionId, 'COMPLETED', {
        reportHash: report.reportHash
      });

      sessions.delete(sessionId);

      return {
        sessionId,
        status: 'COMPLETED',
        report
      };
    } catch (error) {
      try {
        state.tcp.destroy('SESSION_FINALIZATION_FAILED');
      } catch {}

      try {
        await transition(sessionId, 'FAILED', {
          failureCode: 'SESSION_FINALIZATION_FAILED'
        });
      } catch {}

      sessions.delete(sessionId);
      throw error;
    }
  }

  async function revokeDevice(deviceId) {
    for (const [sessionId, assignment] of assignments) {
      if (assignment.deviceId === deviceId) {
        assignments.delete(sessionId);

        try {
          await transition(sessionId, 'REJECTED');
        } catch {}
      }
    }

    for (const [sessionId, state] of sessions) {
      if (state.deviceId !== deviceId) continue;

      state.closed = true;

      try {
        state.tcp.destroy('PARTICIPANT_CONSENT_REVOKED');
      } catch {}

      try {
        await transition(sessionId, 'FAILED', {
          failureCode: 'CONSENT_REVOKED'
        });
      } catch {}

      sessions.delete(sessionId);
    }
  }

  return {
    registerAssignment,
    open,
    send,
    receive,
    close,
    revokeDevice,
    get counts() {
      return {
        assignments: assignments.size,
        activeSessions: sessions.size
      };
    }
  };
}
