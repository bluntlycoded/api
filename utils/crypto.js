import crypto from 'crypto';
import { config } from '../config/env.js';

const PREFIX = 'enc:v1:';
const IV_BYTES = 12;
const TAG_BYTES = 16;

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

const safeEqualHex = (a, b) => {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
};

// AES-256-GCM. Output: prefix + base64url(iv | tag | ciphertext).
const encrypt = (plaintext) => {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', config.encryptionKey, iv);
  const body = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return PREFIX + Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
};

// Values without the prefix are legacy plaintext and are returned unchanged.
const decrypt = (value) => {
  if (typeof value !== 'string' || !value.startsWith(PREFIX)) return value;
  const raw = Buffer.from(value.slice(PREFIX.length), 'base64url');
  const decipher = crypto.createDecipheriv('aes-256-gcm', config.encryptionKey, raw.subarray(0, IV_BYTES));
  decipher.setAuthTag(raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
  return Buffer.concat([decipher.update(raw.subarray(IV_BYTES + TAG_BYTES)), decipher.final()]).toString('utf8');
};

export { sha256, randomToken, safeEqualHex, encrypt, decrypt };
