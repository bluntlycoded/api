// One-time passwords computed on the device (RFC 4226 HOTP and RFC 6238 TOTP), so
// codes keep working with no connection. Pure functions on Web Crypto; no DOM.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export const base32Decode = (input) => {
  const clean = String(input).replace(/[\s=-]/g, '').toUpperCase();
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) throw new Error('Invalid base32 secret');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
};

export const hotp = async (secret, counter, { digits = 6, algorithm = 'SHA1' } = {}) => {
  const key = await crypto.subtle.importKey(
    'raw',
    base32Decode(secret),
    { name: 'HMAC', hash: HASHES[algorithm] ?? HASHES.SHA1 },
    false,
    ['sign']
  );
  const message = new DataView(new ArrayBuffer(8));
  message.setUint32(0, Math.floor(counter / 2 ** 32));
  message.setUint32(4, counter >>> 0);

  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
};

export const totp = (secret, { period = 30, timestamp = Date.now(), ...options } = {}) =>
  hotp(secret, Math.floor(timestamp / 1000 / period), options);

export const secondsRemaining = (period = 30, timestamp = Date.now()) => period - (Math.floor(timestamp / 1000) % period);

// Code for one saved entry, as returned by the API. HOTP uses the counter as given.
export const codeFor = (entry, timestamp = Date.now()) => {
  const options = { digits: entry.digits, algorithm: entry.algorithm };
  return entry.type === 'hotp'
    ? hotp(entry.secretKey, entry.counter, options)
    : totp(entry.secretKey, { ...options, period: entry.period, timestamp });
};
