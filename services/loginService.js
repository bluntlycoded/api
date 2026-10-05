import { config } from '../config/env.js';
import { HISTORY_SIZE, FAILURE_WINDOW_MINUTES } from '../config/risk.js';
import Device from '../models/deviceModel.js';
import LoginEvent from '../models/loginEventModel.js';
import { lookupGeo, normalizeIp, localHour } from '../utils/geo.js';
import { sha256 } from '../utils/crypto.js';
import { scoreLogin } from './riskService.js';
import { signToken } from './authService.js';

// What the server itself observed about this request. The site comes from the
// Origin header; a client-supplied value is kept only as a labelled claim.
const requestContext = (req) => {
  const ip = normalizeIp(req.ip);
  const now = new Date();
  const geo = lookupGeo(ip);
  const origin = req.get('origin');
  const claimed = typeof req.body?.site === 'string' ? req.body.site.slice(0, 200) : null;
  return {
    ip,
    now,
    geo,
    localHour: localHour(now, geo?.timezone),
    userAgent: (req.get('user-agent') || '').slice(0, 200),
    site: origin || claimed,
    siteSource: origin ? 'origin-header' : claimed ? 'client-claimed' : 'none',
    originUnrecognized: Boolean(
      origin && config.allowedOrigins.length > 0 && !config.allowedOrigins.includes(origin)
    ),
  };
};

const recordEvent = (userId, outcome, ctx, deviceHash, risk) =>
  LoginEvent.create({
    userId,
    outcome,
    deviceHash,
    ip: ctx.ip,
    geo: ctx.geo || undefined,
    localHour: ctx.localHour ?? undefined,
    riskScore: risk?.score,
    signals: risk?.signals,
    at: ctx.now,
  });

const countRecentFailures = (userId, now) =>
  LoginEvent.countDocuments({
    userId,
    outcome: 'failed_credentials',
    at: { $gte: new Date(now - FAILURE_WINDOW_MINUTES * 60000) },
  });

const assessLogin = async (user, deviceId, ctx, recentFailures) => {
  const deviceHash = sha256(deviceId);
  const [device, history] = await Promise.all([
    Device.findOne({ userId: user._id, deviceHash }).select('trusted').lean(),
    LoginEvent.find({ userId: user._id, outcome: 'success' })
      .sort({ at: -1 })
      .limit(HISTORY_SIZE)
      .select('ip geo localHour at')
      .lean(),
  ]);
  const risk = scoreLogin({
    now: ctx.now,
    deviceTrusted: Boolean(device?.trusted),
    ip: ctx.ip,
    geo: ctx.geo,
    localHour: ctx.localHour,
    originUnrecognized: ctx.originUnrecognized,
    recentFailures,
    history,
  });
  return { deviceHash, risk };
};

// Record a successful login, register or refresh the device, and issue the JWT.
// `trust` is true for the baseline device, or when an approver chose to trust it.
const completeLogin = async (user, { deviceHash, deviceName, trust, ctx, risk }) => {
  const update = {
    $set: { lastSeen: ctx.now, lastIp: ctx.ip },
    $setOnInsert: { firstSeen: ctx.now, name: deviceName || 'Unknown device' },
  };
  if (trust) update.$set.trusted = true;
  await Promise.all([
    Device.updateOne({ userId: user._id, deviceHash }, update, { upsert: true }),
    recordEvent(user._id, 'success', ctx, deviceHash, risk),
  ]);
  return signToken(user._id, deviceHash);
};

export { requestContext, recordEvent, countRecentFailures, assessLogin, completeLogin };
