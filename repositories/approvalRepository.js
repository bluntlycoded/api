import { query, one, many } from '../lib/db.js';

const LIVE = `id = $1 and user_id = $2 and status = 'pending' and expires_at > now()`;

const create = (a) =>
  one(
    `insert into approvals (user_id, number, options, poll_secret_hash, request_device_hash, request_device_name,
       site, site_source, ip, geo, user_agent, risk_score, signals, expires_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) returning *`,
    [
      a.userId, a.number, JSON.stringify(a.options), a.pollSecretHash, a.requestDeviceHash, a.requestDeviceName ?? null,
      a.site ?? null, a.siteSource, a.ip, a.geo ? JSON.stringify(a.geo) : null, a.userAgent, a.riskScore,
      JSON.stringify(a.signals), a.expiresAt,
    ]
  );

const countPending = async (userId) =>
  (await one(`select count(*)::int as n from approvals where user_id = $1 and status = 'pending' and expires_at > now()`, [userId])).n;

const countSince = async (userId, since) =>
  (await one('select count(*)::int as n from approvals where user_id = $1 and created_at >= $2', [userId, since])).n;

const listPending = (userId) =>
  many(`select * from approvals where user_id = $1 and status = 'pending' and expires_at > now() order by created_at desc`, [userId]);

const findLive = (id, userId) => one(`select * from approvals where ${LIVE}`, [id, userId]);

// Resolves a live challenge. Returns null if it was already resolved or expired.
const resolveLive = (id, userId, status, { approvedByDeviceHash = null, trustDevice = false } = {}) =>
  one(
    `update approvals set status = $3, approved_by_device_hash = $4, trust_device = $5
     where ${LIVE} returning id`,
    [id, userId, status, approvedByDeviceHash, trustDevice]
  );

const addWrongAttempt = async (id, userId) =>
  (await one(`update approvals set wrong_attempts = wrong_attempts + 1 where ${LIVE} returning wrong_attempts`, [id, userId]))?.wrongAttempts;

const findById = (id) => one('select * from approvals where id = $1', [id]);

// Single use: moves approved -> consumed only for the device and secret that asked.
const consume = (id, deviceHash, pollSecretHash) =>
  one(
    `update approvals set status = 'consumed'
     where id = $1 and status = 'approved' and request_device_hash = $2 and poll_secret_hash = $3 and expires_at > now()
     returning *`,
    [id, deviceHash, pollSecretHash]
  );

const purgeOlderThan = (cutoff) => query('delete from approvals where expires_at < $1', [cutoff]);

export { create, countPending, countSince, listPending, findLive, resolveLive, addWrongAttempt, findById, consume, purgeOlderThan };
