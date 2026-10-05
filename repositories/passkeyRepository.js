import { query, one, many } from '../lib/db.js';

const insert = (userId, { credentialId, publicKey, counter, transports, name }) =>
  one(
    `insert into passkeys (user_id, credential_id, public_key, counter, transports, name)
     values ($1,$2,$3,$4,$5,$6) returning id, name, created_at`,
    [userId, credentialId, publicKey, counter, JSON.stringify(transports || []), name]
  );

const findByCredentialId = (credentialId) => one('select * from passkeys where credential_id = $1', [credentialId]);

const listForUser = (userId) =>
  many('select id, credential_id, transports, name, created_at, last_used from passkeys where user_id = $1 order by created_at', [userId]);

// Only moves the counter forward; a stale or cloned authenticator fails this.
const recordUse = async (id, counter) =>
  (await query('update passkeys set counter = $2::bigint, last_used = now() where id = $1 and ($2::bigint = 0 or counter < $2::bigint)', [id, counter])).rowCount === 1;

const remove = (userId, id) => one('delete from passkeys where id = $1 and user_id = $2 returning id', [id, userId]);

export { insert, findByCredentialId, listForUser, recordUse, remove };
