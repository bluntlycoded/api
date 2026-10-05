import { query, one } from '../lib/db.js';

const create = ({ userId = null, purpose, challenge, deviceHash = null, expiresAt }) =>
  one(
    'insert into webauthn_challenges (user_id, purpose, challenge, device_hash, expires_at) values ($1,$2,$3,$4,$5) returning id',
    [userId, purpose, challenge, deviceHash, expiresAt]
  );

// Single use: deleting it is what consumes it.
const take = (id, purpose) =>
  one('delete from webauthn_challenges where id = $1 and purpose = $2 and expires_at > now() returning *', [id, purpose]);

const purgeExpired = () => query('delete from webauthn_challenges where expires_at < now()');

export { create, take, purgeExpired };
