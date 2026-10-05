import { query, many } from '../lib/db.js';

const json = (value) => (value === undefined || value === null ? null : JSON.stringify(value));

const recordLogin = (userId, outcome, { deviceHash, ip, geo, localHour, risk, at }) =>
  query(
    `insert into login_events (user_id, outcome, device_hash, ip, geo, local_hour, risk_score, signals, at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [userId, outcome, deviceHash ?? null, ip, json(geo), localHour ?? null, risk?.score ?? null, json(risk?.signals), at]
  );

// Successful logins form the baseline for risk scoring.
const recentSuccesses = (userId, limit) =>
  many(
    `select ip, geo, local_hour, at from login_events
     where user_id = $1 and outcome = 'success' order by at desc limit $2`,
    [userId, limit]
  );

const countFailures = async (userId, since) =>
  (await many(`select count(*)::int as n from login_events where user_id = $1 and outcome = 'failed_credentials' and at >= $2`, [userId, since]))[0].n;

const recentLogins = (userId, limit) =>
  many('select at, outcome, ip, geo, risk_score, signals from login_events where user_id = $1 order by at desc limit $2', [userId, limit]);

const recordAudit = (userId, type, ip, details) =>
  query('insert into audit_events (user_id, type, ip, details) values ($1,$2,$3,$4)', [userId, type, ip ?? null, json(details)]);

const recentAudit = (userId, limit) =>
  many('select type, ip, details, at from audit_events where user_id = $1 order by at desc limit $2', [userId, limit]);

export { recordLogin, recentSuccesses, countFailures, recentLogins, recordAudit, recentAudit };
