import { query, one, many } from '../lib/db.js';

const find = (userId, deviceHash) =>
  one('select id, trusted from devices where user_id = $1 and device_hash = $2', [userId, deviceHash]);

// Creates or refreshes a device. Trust is only ever added here, never removed.
const upsert = (userId, deviceHash, { name, ip, trust, now }) =>
  query(
    `insert into devices (user_id, device_hash, name, trusted, first_seen, last_seen, last_ip)
     values ($1, $2, $3, $4, $5, $5, $6)
     on conflict (user_id, device_hash)
     do update set last_seen = $5, last_ip = $6, trusted = devices.trusted or $4`,
    [userId, deviceHash, name || 'Unknown device', Boolean(trust), now, ip]
  );

const isTrusted = async (userId, deviceHash) =>
  (await query('select 1 from devices where user_id = $1 and device_hash = $2 and trusted = true', [userId, deviceHash])).rowCount > 0;

const list = (userId) =>
  many('select id, device_hash, name, trusted, first_seen, last_seen, last_ip from devices where user_id = $1 order by last_seen desc', [userId]);

const remove = (userId, id) => one('delete from devices where id = $1 and user_id = $2 returning name', [id, userId]);

export { find, upsert, isTrusted, list, remove };
