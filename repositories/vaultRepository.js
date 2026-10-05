import { query, one } from '../lib/db.js';

const get = (userId) => one('select ciphertext, version, updated_at from vaults where user_id = $1', [userId]);

// Optimistic concurrency: succeeds only if `expectedVersion` is still current
// (0 means "no vault yet"). Returns the new version, or null on conflict.
const put = async (userId, ciphertext, expectedVersion) => {
  if (expectedVersion === 0) {
    try {
      return (await one('insert into vaults (user_id, ciphertext) values ($1, $2) returning version', [userId, ciphertext])).version;
    } catch (err) {
      if (err.code === '23505' || /duplicate key|unique/i.test(err.message)) return null;
      throw err;
    }
  }
  const updated = await one(
    'update vaults set ciphertext = $2, version = version + 1, updated_at = now() where user_id = $1 and version = $3 returning version',
    [userId, ciphertext, expectedVersion]
  );
  return updated?.version ?? null;
};

const remove = async (userId) => (await query('delete from vaults where user_id = $1', [userId])).rowCount === 1;

export { get, put, remove };
