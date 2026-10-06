import { query, one } from '../lib/db.js';

// Replaces the user's whole set of codes.
const replaceAll = async (userId, hashes) => {
  await query('delete from recovery_codes where user_id = $1', [userId]);
  for (const hash of hashes) {
    await query('insert into recovery_codes (user_id, code_hash) values ($1, $2)', [userId, hash]);
  }
};

// Single use: only the first caller with a valid, unused code gets a row.
const consume = async (userId, hash) =>
  Boolean(await one('update recovery_codes set used_at = now() where user_id = $1 and code_hash = $2 and used_at is null returning id', [userId, hash]));

const remaining = async (userId) =>
  (await one('select count(*)::int as n from recovery_codes where user_id = $1 and used_at is null', [userId])).n;

export { replaceAll, consume, remaining };
