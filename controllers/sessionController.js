import { refreshSession, endSession } from '../services/sessionService.js';
import { revokeForUser } from '../repositories/refreshTokenRepository.js';
import { audit } from '../services/auditService.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const refresh = asyncHandler(async (req, res) => {
  res.status(200).json(await refreshSession(req.body.refreshToken, req.ip));
});

// Ends this login only. Unknown or already-ended tokens are not an error.
const logout = asyncHandler(async (req, res) => {
  await endSession(req.body.refreshToken);
  res.status(200).json({ message: 'Logged out' });
});

// Ends every session on every device. Access tokens already issued stay valid until
// they expire (at most accessTokenSeconds).
const logoutAll = asyncHandler(async (req, res) => {
  await revokeForUser(req.user.userId);
  await audit(req.user.userId, 'logout_all', req.ip);
  res.status(200).json({ message: 'Logged out everywhere' });
});

export { refresh, logout, logoutAll };
