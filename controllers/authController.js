import User from '../models/userModel.js';
import Approval from '../models/approvalModel.js';
import {
  APPROVAL_TTL_SECONDS,
  APPROVAL_MAX_PENDING,
  APPROVAL_MAX_PER_HOUR,
  LOCKOUT_FAILURES,
} from '../config/risk.js';
import { createNumberChallenge, toApproverView } from '../services/approvalService.js';
import { hashPassword, verifyPassword } from '../services/authService.js';
import { verifyCode } from '../services/totpService.js';
import {
  requestContext,
  recordEvent,
  countRecentFailures,
  assessLogin,
  completeLogin,
} from '../services/loginService.js';
import { requestPasswordReset, resetPassword } from '../services/passwordResetService.js';
import { notifyApprovalRequest } from '../services/realtime.js';
import { sha256, randomToken } from '../utils/crypto.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

// The registering device becomes the first trusted device.
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password, deviceId, deviceName } = req.body;

  if (await User.exists({ email })) throw new HttpError(400, 'User already exists');

  const user = await User.create({ name, email, password: await hashPassword(password) });
  const token = await completeLogin(user, {
    deviceHash: sha256(deviceId),
    deviceName,
    trust: true,
    ctx: requestContext(req),
    risk: { score: 0, signals: [] },
  });

  res.status(201).json({ token });
});

// Low-risk logins get a token. Risky ones get a challenge that a trusted device
// must approve by matching the number shown on the login screen.
const loginUser = asyncHandler(async (req, res) => {
  const { email, password, deviceId, deviceName, totp } = req.body;
  const deviceHash = sha256(deviceId);
  const ctx = requestContext(req);

  const user = await User.findOne({ email }).select('+password +totpSecret +totpLastStep');
  const recentFailures = user ? await countRecentFailures(user._id, ctx.now) : 0;
  if (recentFailures >= LOCKOUT_FAILURES) {
    throw new HttpError(429, 'Too many failed attempts. Try again in a few minutes.');
  }

  const passwordOk = await verifyPassword(password, user?.password);
  if (!user || !passwordOk) {
    if (user) await recordEvent(user._id, 'failed_credentials', ctx, deviceHash);
    throw new HttpError(400, 'Invalid credentials');
  }

  if (user.totpEnabled) {
    if (!totp) throw new HttpError(401, 'A 6-digit authenticator code is required', { code: 'TOTP_REQUIRED' });
    const step = verifyCode(totp, user.totpSecret, user.totpLastStep);
    // The conditional update makes a reused code fail even under concurrent requests.
    const accepted =
      step !== null &&
      (await User.updateOne({ _id: user._id, totpLastStep: { $lt: step } }, { $set: { totpLastStep: step } }))
        .modifiedCount === 1;
    if (!accepted) {
      await recordEvent(user._id, 'failed_credentials', ctx, deviceHash);
      throw new HttpError(401, 'Invalid authenticator code', { code: 'TOTP_INVALID' });
    }
  }

  const { risk } = await assessLogin(user, deviceId, ctx, recentFailures);

  if (!risk.requiresApproval) {
    const token = await completeLogin(user, { deviceHash, deviceName, trust: Boolean(risk.baseline), ctx, risk });
    return res.status(200).json({ token, riskScore: risk.score });
  }

  // Limit challenges so an attacker holding the password cannot spam the user.
  const [pending, lastHour] = await Promise.all([
    Approval.countDocuments({ userId: user._id, status: 'pending', expiresAt: { $gt: ctx.now } }),
    Approval.countDocuments({ userId: user._id, createdAt: { $gte: new Date(ctx.now - 3600 * 1000) } }),
  ]);
  if (pending >= APPROVAL_MAX_PENDING || lastHour >= APPROVAL_MAX_PER_HOUR) {
    await recordEvent(user._id, 'denied', ctx, deviceHash, risk);
    throw new HttpError(429, 'Too many approval requests. Try again later or log in from a trusted device.', {
      code: 'APPROVAL_RATE_LIMITED',
    });
  }

  const { number, options } = createNumberChallenge();
  const pollSecret = randomToken();
  const approval = await Approval.create({
    userId: user._id,
    number,
    options,
    pollSecretHash: sha256(pollSecret),
    requestDeviceHash: deviceHash,
    requestDeviceName: deviceName,
    site: ctx.site || undefined,
    siteSource: ctx.siteSource,
    ip: ctx.ip,
    geo: ctx.geo ? { country: ctx.geo.country, region: ctx.geo.region, city: ctx.geo.city } : undefined,
    userAgent: ctx.userAgent,
    riskScore: risk.score,
    signals: risk.signals,
    expiresAt: new Date(ctx.now.getTime() + APPROVAL_TTL_SECONDS * 1000),
  });
  await recordEvent(user._id, 'challenged', ctx, deviceHash, risk);
  notifyApprovalRequest(user._id, toApproverView(approval));

  res.status(202).json({
    status: 'approval_required',
    challengeId: approval._id,
    pollSecret,
    displayNumber: number,
    expiresInSeconds: APPROVAL_TTL_SECONDS,
  });
});

// Exchange an approved challenge for a token. Single use, bound to the device
// and to the poll secret that started the login.
const completeApprovedLogin = asyncHandler(async (req, res) => {
  const { challengeId, pollSecret, deviceId } = req.body;

  const approval = await Approval.findOneAndUpdate(
    {
      _id: challengeId,
      status: 'approved',
      requestDeviceHash: sha256(deviceId),
      pollSecretHash: sha256(pollSecret),
      expiresAt: { $gt: new Date() },
    },
    { $set: { status: 'consumed' } }
  );
  if (!approval) throw new HttpError(403, 'Approval not found, not approved, or expired');

  const user = await User.findById(approval.userId);
  if (!user) throw new HttpError(404, 'User not found');

  const token = await completeLogin(user, {
    deviceHash: approval.requestDeviceHash,
    deviceName: approval.requestDeviceName,
    trust: approval.trustDevice,
    ctx: requestContext(req),
    risk: { score: approval.riskScore, signals: approval.signals },
  });
  res.status(200).json({ token });
});

// Always answers the same way so it cannot be used to find registered emails.
const forgotPassword = asyncHandler(async (req, res) => {
  await requestPasswordReset(req.body.email, requestContext(req).ip);
  res.status(200).json({ message: 'If that email is registered, a reset message has been sent.' });
});

const resetPasswordHandler = asyncHandler(async (req, res) => {
  await resetPassword(req.body.token, req.body.password, requestContext(req).ip);
  res.status(200).json({ message: 'Password updated' });
});

export { registerUser, loginUser, completeApprovedLogin, forgotPassword, resetPasswordHandler as resetPassword };
