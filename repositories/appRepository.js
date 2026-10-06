import { query, one, many } from '../lib/db.js';
import { encrypt, decrypt } from '../utils/crypto.js';

// `_id` is kept as an alias so existing clients that read it keep working.
const toApp = (row) => (row ? { ...row, _id: row.id, secretKey: decrypt(row.secretKey) } : null);

const EDITABLE = { appName: 'app_name', issuer: 'issuer', account: 'account', folder: 'folder', icon: 'icon', favorite: 'favorite' };

const insert = async (userId, a) =>
  toApp(
    await one(
      `insert into user_apps (user_id, app_name, issuer, account, secret_key, type, algorithm, digits, period, counter, folder, icon, favorite, sort_order)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
         coalesce((select max(sort_order) + 1 from user_apps where user_id = $1), 0))
       returning *`,
      [userId, a.appName, a.issuer ?? null, a.account ?? null, encrypt(a.secretKey), a.type, a.algorithm, a.digits, a.period, a.counter, a.folder ?? null, a.icon ?? null, a.favorite ?? false]
    )
  );

const list = async (userId, { q, folder, favorite } = {}) => {
  const params = [userId];
  const where = ['user_id = $1'];
  if (q) {
    params.push(`%${q.replace(/[\\%_]/g, '\\$&')}%`);
    where.push(`(app_name ilike $${params.length} or issuer ilike $${params.length})`);
  }
  if (folder !== undefined) {
    params.push(folder);
    where.push(`folder = $${params.length}`);
  }
  if (favorite !== undefined) {
    params.push(favorite);
    where.push(`favorite = $${params.length}`);
  }
  const rows = await many(
    `select * from user_apps where ${where.join(' and ')} order by favorite desc, sort_order asc, created_at asc`,
    params
  );
  return rows.map(toApp);
};

const findOne = async (userId, id) => toApp(await one('select * from user_apps where id = $1 and user_id = $2', [id, userId]));

const update = async (userId, id, changes) => {
  const sets = [];
  const params = [id, userId];
  for (const [field, column] of Object.entries(EDITABLE)) {
    if (changes[field] !== undefined) {
      params.push(changes[field]);
      sets.push(`${column} = $${params.length}`);
    }
  }
  if (sets.length === 0) return findOne(userId, id);
  return toApp(await one(`update user_apps set ${sets.join(', ')} where id = $1 and user_id = $2 returning *`, params));
};

const remove = async (userId, id) => (await query('delete from user_apps where id = $1 and user_id = $2', [id, userId])).rowCount === 1;

// Returns the entry with its counter advanced, for HOTP code generation.
const nextCounter = async (userId, id) =>
  toApp(await one(`update user_apps set counter = counter + 1 where id = $1 and user_id = $2 and type = 'hotp' returning *`, [id, userId]));

// Offline devices advance HOTP counters locally. Syncing only ever moves a counter
// forward, so a stale device can never make the server reuse a code.
const raiseCounter = async (userId, id, counter) =>
  (await query(
    `update user_apps set counter = case when counter < $3 then $3 else counter end
     where id = $1 and user_id = $2 and type = 'hotp'`,
    [id, userId, counter]
  )).rowCount === 1;

const reorder = async (userId, ids) => {
  const params = [userId, ...ids];
  const cases = ids.map((_, i) => `when $${i + 2}::uuid then ${i}`).join(' ');
  const inList = ids.map((_, i) => `$${i + 2}::uuid`).join(', ');
  await query(`update user_apps set sort_order = case id ${cases} end where user_id = $1 and id in (${inList})`, params);
};

const count = async (userId) => Number((await one('select count(*)::int as n from user_apps where user_id = $1', [userId])).n);

export { insert, list, findOne, update, remove, nextCounter, raiseCounter, reorder, count };
