import User from '../models/userModel.js';
import { hashPassword } from './authService.js';
import { sendPasswordReset } from './mailService.js';
import { audit } from './auditService.js';
import { sha256, randomToken } from '../utils/crypto.js';
import { HttpError } from '../utils/httpError.js';

const RESET_TTL_MINUTES = 15;

const requestPasswordReset = async (email, ip) => {
  const user = await User.findOne({ email }).select('_id');
  if (!user) return;

  const token = randomToken();
  await User.updateOne(
    { _id: user._id },
    { $set: { resetTokenHash: sha256(token), resetTokenExpires: new Date(Date.now() + RESET_TTL_MINUTES * 60000) } }
  );
  await audit(user._id, 'password_reset_requested', ip);
  try {
    await sendPasswordReset(email, token);
  } catch (err) {
    // Same response either way, so delivery failures are only visible in logs.
    console.error('Password reset email failed:', err.message);
  }
};

// Reset does not trust the device: a new device still needs approval to log in.
const resetPassword = async (token, newPassword, ip) => {
  const user = await User.findOneAndUpdate(
    { resetTokenHash: sha256(token), resetTokenExpires: { $gt: new Date() } },
    {
      $set: { password: await hashPassword(newPassword) },
      $unset: { resetTokenHash: '', resetTokenExpires: '' },
    }
  );
  if (!user) throw new HttpError(400, 'Reset link is invalid or has expired');
  await audit(user._id, 'password_reset', ip);
};

export { requestPasswordReset, resetPassword };
