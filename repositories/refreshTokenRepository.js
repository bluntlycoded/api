import { query, one } from '../lib/db.js';

const create = ({ userId, familyId, deviceHash, tokenHash, expiresAt, familyExpiresAt }) =>
  query(
    `insert into refresh_tokens (user_id, family_id, device_hash, token_hash, expires_at, family_expires_at)
     values ($1,$2,$3,$4,$5,$6)`,
    [userId, familyId, deviceHash, tokenHash, expiresAt, familyExpiresAt]
  );

// Marks a token used. Only the first caller gets a row, so a token works once.
const consume = (tokenHash) =>
  one(
    `update refresh_tokens set used_at = now()
     where token_hash = $1 and used_at is null and revoked_at is null and expires_at > now()
     returning *`,
    [tokenHash]
  );

const findByHash = (tokenHash) => one('select * from refresh_tokens where token_hash = $1', [tokenHash]);

const revokeFamily = (familyId) =>
  query('update refresh_tokens set revoked_at = now() where family_id = $1 and revoked_at is null', [familyId]);

const revokeForUser = (userId) =>
  query('update refresh_tokens set revoked_at = now() where user_id = $1 and revoked_at is null', [userId]);

const revokeForDevice = (userId, deviceHash) =>
  query('update refresh_tokens set revoked_at = now() where user_id = $1 and device_hash = $2 and revoked_at is null', [userId, deviceHash]);

const purgeExpired = (cutoff) => query('delete from refresh_tokens where family_expires_at < $1', [cutoff]);

export { create, consume, findByHash, revokeFamily, revokeForUser, revokeForDevice, purgeExpired };
