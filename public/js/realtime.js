import { getToken, refresh } from './api.js';

// Live approval prompts for a trusted device. Falls back silently to the list
// the Approvals tab loads over HTTP if the socket cannot connect.
export const connectApprover = ({ onRequest, onClosed }) => {
  // The socket.io script comes from the server, so it is missing when offline.
  if (!window.io) return () => {};
  const socket = window.io({ transports: ['websocket', 'polling'] });

  const authenticate = () =>
    socket.emit('authenticate', { token: getToken() }, async (reply) => {
      if (reply?.ok) return;
      try {
        await refresh();
        socket.emit('authenticate', { token: getToken() });
      } catch {
        /* session ended; the app will show the login screen on its next call */
      }
    });

  socket.on('connect', authenticate);
  socket.on('approval_request', onRequest);
  socket.on('approval_closed', onClosed);
  return () => socket.close();
};

// Login screen: learns when the challenge is approved without a token.
export const watchChallenge = (challengeId, pollSecret, onResolved) => {
  if (!window.io) return () => {};
  const socket = window.io({ transports: ['websocket', 'polling'] });
  socket.on('connect', () => socket.emit('watch', { challengeId, pollSecret }));
  socket.on('approval_resolved', ({ status }) => onResolved(status));
  return () => socket.close();
};
