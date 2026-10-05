import User from '../models/userModel.js';
import { buildSetup, generateSecret, verifyCode } from '../services/totpService.js';
import { verifyPassword } from '../services/authService.js';
import { audit } from '../services/auditService.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

// Step 1: create a secret (not active yet) and return it with a QR code.
const setupTotp = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('email totpEnabled');
  if (!user) throw new HttpError(404, 'User not found');
  if (user.totpEnabled) throw new HttpError(409, 'Two-factor authentication is already enabled');

  const secret = generateSecret();
  await User.updateOne({ _id: user._id }, { $set: { totpSecret: secret, totpLastStep: 0 } });
  res.status(200).json(await buildSetup(user.email, secret));
});

// Step 2: prove the authenticator app works, then switch it on.
const enableTotp = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('+totpSecret +totpLastStep totpEnabled');
  if (!user?.totpSecret) throw new HttpError(400, 'Start setup first');
  if (user.totpEnabled) throw new HttpError(409, 'Two-factor authentication is already enabled');

  const step = verifyCode(req.body.token, user.totpSecret);
  if (step === null) throw new HttpError(400, 'Invalid code');

  await User.updateOne({ _id: user._id }, { $set: { totpEnabled: true, totpLastStep: step } });
  await audit(user._id, 'totp_enabled', req.ip);
  res.status(200).json({ message: 'Two-factor authentication enabled' });
});

// Needs both the password and a current code.
const disableTotp = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('+password +totpSecret +totpLastStep totpEnabled');
  if (!user?.totpEnabled) throw new HttpError(400, 'Two-factor authentication is not enabled');

  const passwordOk = await verifyPassword(req.body.password, user.password);
  const step = verifyCode(req.body.token, user.totpSecret, user.totpLastStep);
  if (!passwordOk || step === null) throw new HttpError(400, 'Invalid password or code');

  await User.updateOne(
    { _id: user._id },
    { $set: { totpEnabled: false, totpLastStep: 0 }, $unset: { totpSecret: '' } }
  );
  await audit(user._id, 'totp_disabled', req.ip);
  res.status(200).json({ message: 'Two-factor authentication disabled' });
});

export { setupTotp, enableTotp, disableTotp };
