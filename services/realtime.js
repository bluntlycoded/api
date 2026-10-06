import { Server } from 'socket.io';
import { config } from '../config/env.js';
import * as approvals from '../repositories/approvalRepository.js';
import * as devices from '../repositories/deviceRepository.js';
import { sha256, safeEqualHex } from '../utils/crypto.js';
import { verifyJwt } from './authService.js';

const AUTH_TIMEOUT_MS = 15000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let io = null;

/**
 * Live approval prompts over Socket.IO. Two kinds of client, each of which must
 * identify itself within 15 seconds or is disconnected:
 *   - a trusted device:  emit('authenticate', {token}) -> receives 'approval_request'
 *   - a login screen:    emit('watch', {challengeId, pollSecret}) -> receives 'approval_resolved'
 * Polling the REST status endpoint remains available as a fallback.
 */
const initRealtime = (httpServer) => {
  io = new Server(httpServer, {
    cors: { origin: config.allowedOrigins.length ? config.allowedOrigins : true },
  });

  io.on('connection', (socket) => {
    const timer = setTimeout(() => socket.disconnect(true), AUTH_TIMEOUT_MS);
    const identified = () => clearTimeout(timer);

    socket.on('authenticate', async ({ token } = {}, ack = () => {}) => {
      try {
        const { userId, did } = verifyJwt(token);
        const trusted = did && (await devices.isTrusted(userId, did));
        if (!trusted) return ack({ ok: false });
        socket.join(`user:${userId}`);
        identified();
        ack({ ok: true });
      } catch {
        ack({ ok: false });
      }
    });

    socket.on('watch', async ({ challengeId, pollSecret } = {}, ack = () => {}) => {
      try {
        const approval = UUID.test(challengeId) ? await approvals.findById(challengeId) : null;
        if (!approval || typeof pollSecret !== 'string' || !safeEqualHex(approval.pollSecretHash, sha256(pollSecret))) {
          return ack({ ok: false });
        }
        socket.join(`approval:${challengeId}`);
        identified();
        ack({ ok: true, status: approval.status });
      } catch {
        ack({ ok: false });
      }
    });
  });

  return io;
};

const notifyApprovalRequest = (userId, view) => io?.to(`user:${userId}`).emit('approval_request', view);

const notifyApprovalResolved = (userId, id, status) => {
  io?.to(`approval:${id}`).emit('approval_resolved', { status });
  io?.to(`user:${userId}`).emit('approval_closed', { id, status });
};

export { initRealtime, notifyApprovalRequest, notifyApprovalResolved };
