import * as users from '../repositories/userRepository.js';
import { hashPassword } from './authService.js';
import { sendPasswordReset } from './mailService.js';
import { audit } from './auditService.js';
import { revokeForUser } from '../repositories/refreshTokenRepository.js';
import { sha256, randomToken } from '../utils/crypto.js';
import { HttpError } from '../utils/httpError.js';

const RESET_TTL_MINUTES = 15;

const requestPasswordReset = async (email, ip) => {
  const user = await users.findByEmail(email);
  if (!user) return;

  const token = randomToken();
  await users.setResetToken(user.id, sha256(token), new Date(Date.now() + RESET_TTL_MINUTES * 60000));
  await audit(user.id, 'password_reset_requested', ip);
  try {
    await sendPasswordReset(email, token);
  } catch (err) {
    // Same response either way, so delivery failures are only visible in logs.
    console.error('Password reset email failed:', err.message);
  }
};

// Reset does not trust the device: a new device still needs approval to log in.
const resetPassword = async (token, newPassword, ip) => {
  const user = await users.resetPasswordByToken(sha256(token), await hashPassword(newPassword));
  if (!user) throw new HttpError(400, 'Reset link is invalid or has expired');
  await revokeForUser(user.id);
  await audit(user.id, 'password_reset', ip);
};

export { requestPasswordReset, resetPassword };
