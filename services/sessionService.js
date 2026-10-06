import { randomUUID } from 'crypto';
import { config } from '../config/env.js';
import * as refreshTokens from '../repositories/refreshTokenRepository.js';
import * as devices from '../repositories/deviceRepository.js';
import * as users from '../repositories/userRepository.js';
import { signToken } from './authService.js';
import { audit } from './auditService.js';
import { sha256, randomToken } from '../utils/crypto.js';
import { HttpError } from '../utils/httpError.js';

const REFRESH_DAYS = 30;
const FAMILY_DAYS = 90;
const DAY_MS = 86400000;

// Short-lived access token plus a rotating refresh token. Every refresh token
// belongs to a family that started at one login and ends after FAMILY_DAYS.
const issueSession = async (userId, deviceHash, family) => {
  const now = Date.now();
  const familyId = family?.id ?? randomUUID();
  const familyExpiresAt = family?.expiresAt ?? new Date(now + FAMILY_DAYS * DAY_MS);
  const refreshToken = randomToken();

  await refreshTokens.create({
    userId,
    familyId,
    deviceHash,
    tokenHash: sha256(refreshToken),
    expiresAt: new Date(Math.min(now + REFRESH_DAYS * DAY_MS, familyExpiresAt.getTime())),
    familyExpiresAt,
  });

  return { token: signToken(userId, deviceHash), refreshToken, expiresInSeconds: config.accessTokenSeconds };
};

const invalid = () => new HttpError(401, 'Session expired. Please log in again.', { code: 'REFRESH_INVALID' });

// Each refresh token works once. Presenting one a second time means it was copied,
// so the whole family is revoked and the user has to log in again.
const refreshSession = async (refreshToken, ip) => {
  const tokenHash = sha256(refreshToken);
  const row = await refreshTokens.consume(tokenHash);

  if (!row) {
    const known = await refreshTokens.findByHash(tokenHash);
    if (known) {
      await refreshTokens.revokeFamily(known.familyId);
      if (known.usedAt) await audit(known.userId, 'refresh_token_reuse', ip, { familyId: known.familyId });
    }
    throw invalid();
  }

  const [device, user] = await Promise.all([devices.find(row.userId, row.deviceHash), users.findById(row.userId)]);
  if (!device || !user || user.locked) {
    await refreshTokens.revokeFamily(row.familyId);
    throw invalid();
  }

  return issueSession(row.userId, row.deviceHash, { id: row.familyId, expiresAt: row.familyExpiresAt });
};

const endSession = async (refreshToken) => {
  const known = await refreshTokens.findByHash(sha256(refreshToken));
  if (known) await refreshTokens.revokeFamily(known.familyId);
};

export { issueSession, refreshSession, endSession };
