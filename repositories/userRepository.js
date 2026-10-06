import { query, one } from '../lib/db.js';
import { encrypt, decrypt } from '../utils/crypto.js';

const toUser = (row) => (row ? { ...row, totpSecret: row.totpSecret ? decrypt(row.totpSecret) : null } : null);

const findById = async (id) => toUser(await one('select * from users where id = $1', [id]));

const findByEmail = async (email) => toUser(await one('select * from users where email = $1', [email]));

const emailExists = async (email) => (await query('select 1 from users where email = $1', [email])).rowCount > 0;

const create = async ({ name, email, passwordHash }) =>
  toUser(await one('insert into users (name, email, password_hash) values ($1, $2, $3) returning *', [name, email, passwordHash]));

const startTotpSetup = (id, secret) =>
  query('update users set totp_secret = $2, totp_last_step = 0 where id = $1', [id, encrypt(secret)]);

const enableTotp = (id, step) => query('update users set totp_enabled = true, totp_last_step = $2 where id = $1', [id, step]);

const disableTotp = (id) =>
  query('update users set totp_enabled = false, totp_secret = null, totp_last_step = 0 where id = $1', [id]);

// True only for the request that advances the step, so a code works once.
const advanceTotpStep = async (id, step) =>
  (await query('update users set totp_last_step = $2 where id = $1 and totp_last_step < $2', [id, step])).rowCount === 1;

const setResetToken = (id, hash, expires) =>
  query('update users set reset_token_hash = $2, reset_token_expires = $3 where id = $1', [id, hash, expires]);

// Also clears any "not me" lock: reaching the reset email proves account ownership.
const resetPasswordByToken = async (tokenHash, passwordHash) =>
  one(
    `update users set password_hash = $2, locked = false, reset_token_hash = null, reset_token_expires = null
     where reset_token_hash = $1 and reset_token_expires > now() returning id`,
    [tokenHash, passwordHash]
  );

const lock = (id) => query('update users set locked = true where id = $1', [id]);

export {
  findById,
  findByEmail,
  emailExists,
  create,
  startTotpSetup,
  enableTotp,
  disableTotp,
  advanceTotpStep,
  setResetToken,
  resetPasswordByToken,
  lock,
};
