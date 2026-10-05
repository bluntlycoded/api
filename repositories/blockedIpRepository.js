import { query } from '../lib/db.js';

const block = (ip, reason, until) =>
  query(
    `insert into blocked_ips (ip, reason, blocked_until) values ($1,$2,$3)
     on conflict (ip) do update set reason = $2, blocked_until = $3`,
    [ip, reason, until]
  );

const isBlocked = async (ip) => (await query('select 1 from blocked_ips where ip = $1 and blocked_until > now()', [ip])).rowCount > 0;

const purgeExpired = () => query('delete from blocked_ips where blocked_until < now()');

export { block, isBlocked, purgeExpired };
