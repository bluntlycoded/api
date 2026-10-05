import { config } from '../config/env.js';
import { HISTORY_SIZE, FAILURE_WINDOW_MINUTES } from '../config/risk.js';
import * as devices from '../repositories/deviceRepository.js';
import * as events from '../repositories/eventRepository.js';
import { lookupGeo, normalizeIp, localHour } from '../utils/geo.js';
import { sha256 } from '../utils/crypto.js';
import { scoreLogin } from './riskService.js';
import { signToken } from './authService.js';
import { isAnonymizingIp } from './ipReputationService.js';

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
    originUnrecognized: Boolean(origin && config.allowedOrigins.length > 0 && !config.allowedOrigins.includes(origin)),
    anonymizingIp: isAnonymizingIp(ip),
  };
};

const recordEvent = (userId, outcome, ctx, deviceHash, risk) =>
  events.recordLogin(userId, outcome, { deviceHash, ip: ctx.ip, geo: ctx.geo, localHour: ctx.localHour, risk, at: ctx.now });

const countRecentFailures = (userId, now) =>
  events.countFailures(userId, new Date(now - FAILURE_WINDOW_MINUTES * 60000));

const assessLogin = async (user, deviceId, ctx, recentFailures) => {
  const deviceHash = sha256(deviceId);
  const [device, history] = await Promise.all([
    devices.find(user.id, deviceHash),
    events.recentSuccesses(user.id, HISTORY_SIZE),
  ]);
  const risk = scoreLogin({
    now: ctx.now,
    deviceTrusted: Boolean(device?.trusted),
    ip: ctx.ip,
    geo: ctx.geo,
    localHour: ctx.localHour,
    originUnrecognized: ctx.originUnrecognized,
    anonymizingIp: ctx.anonymizingIp,
    recentFailures,
    history,
  });
  return { deviceHash, risk };
};

// Record a successful login, register or refresh the device, and issue the JWT.
// `trust` is true for the baseline device, or when an approver chose to trust it.
const completeLogin = async (user, { deviceHash, deviceName, trust, ctx, risk }) => {
  await Promise.all([
    devices.upsert(user.id, deviceHash, { name: deviceName, ip: ctx.ip, trust, now: ctx.now }),
    recordEvent(user.id, 'success', ctx, deviceHash, risk),
  ]);
  return signToken(user.id, deviceHash);
};

export { requestContext, recordEvent, countRecentFailures, assessLogin, completeLogin };
