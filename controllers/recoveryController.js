import * as users from '../repositories/userRepository.js';
import * as devices from '../repositories/deviceRepository.js';
import * as blockedIps from '../repositories/blockedIpRepository.js';
import * as recovery from '../repositories/recoveryRepository.js';
import { revokeForUser } from '../repositories/refreshTokenRepository.js';
import { LOCKOUT_FAILURES } from '../config/risk.js';
import { generateCodes, useCode } from '../services/recoveryService.js';
import { verifyPassword } from '../services/authService.js';
import { requestContext, recordEvent, countRecentFailures, completeLogin } from '../services/loginService.js';
import { sendSecurityNotice } from '../services/mailService.js';
import { audit } from '../services/auditService.js';
import { sha256 } from '../utils/crypto.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

// Trusted device only, and needs the password again. Replaces any earlier set;
// the codes are returned once and cannot be shown again.
const generate = asyncHandler(async (req, res) => {
  const user = await users.findById(req.user.userId);
  if (!user || !(await verifyPassword(req.body.password, user.passwordHash))) {
    throw new HttpError(403, 'Incorrect password');
  }
  const codes = await generateCodes(user.id);
  await audit(user.id, 'recovery_codes_generated', req.ip);
  res.status(200).json({ codes });
});

const status = asyncHandler(async (req, res) => {
  res.status(200).json({ remaining: await recovery.remaining(req.user.userId) });
});

// For someone who has lost every trusted device: password plus one recovery code
// starts a session on this device, makes it the only trusted device, and ends
// every other session, since the lost devices may be in someone else's hands.
const recover = asyncHandler(async (req, res) => {
  const { email, password, recoveryCode, deviceId, deviceName } = req.body;
  const deviceHash = sha256(deviceId);
  const ctx = requestContext(req);

  if (await blockedIps.isBlocked(ctx.ip)) throw new HttpError(403, 'Access denied', { code: 'IP_BLOCKED' });

  const user = await users.findByEmail(email);
  const failures = user ? await countRecentFailures(user.id, ctx.now) : 0;
  if (failures >= LOCKOUT_FAILURES) throw new HttpError(429, 'Too many failed attempts. Try again in a few minutes.');

  const passwordOk = await verifyPassword(password, user?.passwordHash);
  if (!user || !passwordOk) {
    if (user) await recordEvent(user.id, 'failed_credentials', ctx, deviceHash);
    throw new HttpError(400, 'Invalid credentials');
  }
  if (user.locked) {
    throw new HttpError(423, 'This account is locked. Reset your password to unlock it.', { code: 'ACCOUNT_LOCKED' });
  }

  if (!(await useCode(user.id, recoveryCode))) {
    await recordEvent(user.id, 'failed_credentials', ctx, deviceHash);
    throw new HttpError(401, 'Invalid or already used recovery code', { code: 'RECOVERY_INVALID' });
  }

  await revokeForUser(user.id);
  await devices.untrustOthers(user.id, deviceHash);
  const session = await completeLogin(user, {
    deviceHash,
    deviceName,
    trust: true,
    ctx,
    risk: { score: 0, signals: [{ id: 'recovery', points: 0, detail: 'Signed in with a recovery code' }] },
  });

  const remaining = await recovery.remaining(user.id);
  await audit(user.id, 'recovery_used', ctx.ip, { remaining });
  sendSecurityNotice(
    user.email,
    'A recovery code was used on your account',
    `A recovery code was just used to sign in from ${ctx.ip}. All other devices were signed out and lost their trusted status. ${remaining} codes remain. If this was not you, reset your password now.`
  ).catch((err) => console.error('Security notice failed:', err.message));

  res.status(200).json({ ...session, remainingCodes: remaining });
});

export { generate, status, recover };
