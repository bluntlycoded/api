import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { base32Decode, hotp, totp, secondsRemaining, codeFor } from '../public/js/otp.js';
import { deriveKey, newSalt, encryptJson, decryptJson } from '../public/js/localCrypto.js';
import { generateCode } from '../services/otpService.js';

const ascii = (text) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const byte of Buffer.from(text)) bits += byte.toString(2).padStart(8, '0');
  return (bits.match(/.{1,5}/g) || []).map((b) => alphabet[parseInt(b.padEnd(5, '0'), 2)]).join('');
};

test('base32 decoding', () => {
  assert.equal(Buffer.from(base32Decode('MZXW6YTBOI======')).toString(), 'foobar');
  assert.equal(Buffer.from(base32Decode('mzxw 6ytb-oi')).toString(), 'foobar', 'case, spaces and dashes are ignored');
  assert.throws(() => base32Decode('NOT*BASE32'), /Invalid base32/);
});

test('HOTP matches the RFC 4226 vectors', async () => {
  const secret = ascii('12345678901234567890');
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  for (const [counter, code] of expected.entries()) assert.equal(await hotp(secret, counter), code, `counter ${counter}`);
});

test('TOTP matches the RFC 6238 vectors for SHA-1, SHA-256 and SHA-512', async () => {
  const secrets = {
    SHA1: ascii('12345678901234567890'),
    SHA256: ascii('12345678901234567890123456789012'),
    SHA512: ascii('1234567890123456789012345678901234567890123456789012345678901234'),
  };
  const vectors = [
    [59, { SHA1: '94287082', SHA256: '46119246', SHA512: '90693936' }],
    [1111111109, { SHA1: '07081804', SHA256: '68084774', SHA512: '25091201' }],
    [1234567890, { SHA1: '89005924', SHA256: '91819424', SHA512: '93441116' }],
    [2000000000, { SHA1: '69279037', SHA256: '90698825', SHA512: '38618901' }],
  ];
  for (const [time, codes] of vectors) {
    for (const algorithm of Object.keys(secrets)) {
      const code = await totp(secrets[algorithm], { digits: 8, algorithm, timestamp: time * 1000 });
      assert.equal(code, codes[algorithm], `${algorithm} at ${time}`);
    }
  }
});

test('browser and server both match an independent HMAC for every algorithm', async () => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const decode = (text) => {
    let bits = 0;
    let value = 0;
    const out = [];
    for (const c of text) {
      value = (value << 5) | alphabet.indexOf(c);
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    return Buffer.from(out);
  };
  const reference = (secret, counter, algorithm, digits) => {
    const message = Buffer.alloc(8);
    message.writeBigUInt64BE(BigInt(counter));
    const mac = createHmac(algorithm.toLowerCase(), decode(secret)).update(message).digest();
    const offset = mac[mac.length - 1] & 15;
    const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
    return String(binary % 10 ** digits).padStart(digits, '0');
  };

  // Typical secrets are 10 to 32 bytes: shorter than the SHA-512 block, which is
  // exactly where a library that stretches keys goes wrong.
  const now = Date.now();
  for (let i = 0; i < 90; i++) {
    const length = [16, 26, 32, 52][i % 4];
    const secretKey = Array.from({ length }, () => alphabet[Math.floor(Math.random() * 32)]).join('');
    const type = i % 2 ? 'hotp' : 'totp';
    const entry = {
      secretKey,
      type,
      algorithm: ['SHA1', 'SHA256', 'SHA512'][i % 3],
      digits: [6, 7, 8][(i >> 1) % 3],
      period: [30, 60, 15][(i >> 2) % 3],
      counter: i * 7,
    };
    const counter = type === 'hotp' ? entry.counter : Math.floor(now / 1000 / entry.period);
    const expected = reference(secretKey, counter, entry.algorithm, entry.digits);
    const label = `${type} ${entry.algorithm} ${entry.digits} digits, ${length}-char secret`;
    assert.equal(await codeFor(entry, now), expected, `browser: ${label}`);
    assert.equal(generateCode(entry).otp, expected, `server: ${label}`);
  }
});

test('secondsRemaining counts down inside each period', () => {
  assert.equal(secondsRemaining(30, 0), 30);
  assert.equal(secondsRemaining(30, 29_000), 1);
  assert.equal(secondsRemaining(30, 30_000), 30);
  assert.equal(secondsRemaining(60, 90_000), 30);
});

test('offline copy: round trip, wrong passcode, tampering, and fresh randomness', async () => {
  const salt = newSalt();
  const key = await deriveKey('correct horse battery', salt, 1000);
  const data = { entries: [{ id: 'a', secretKey: 'JBSWY3DPEHPK3PXP' }], pendingCounters: { a: 4 } };

  const sealed = await encryptJson(key, data);
  assert.deepEqual(await decryptJson(key, sealed), data);
  assert.ok(!JSON.stringify(sealed).includes('JBSWY3DPEHPK3PXP'));
  assert.notEqual((await encryptJson(key, data)).data, sealed.data, 'a new IV every time');

  const wrong = await deriveKey('not the passcode', salt, 1000);
  await assert.rejects(decryptJson(wrong, sealed));
  const otherSalt = await deriveKey('correct horse battery', newSalt(), 1000);
  await assert.rejects(decryptJson(otherSalt, sealed), 'a different salt gives a different key');

  const flipped = { ...sealed, data: sealed.data.slice(0, -4) + (sealed.data.endsWith('AAAA') ? 'BBBB' : 'AAAA') };
  await assert.rejects(decryptJson(key, flipped), 'altered data is rejected');
});

test('derived keys cannot be exported', async () => {
  const key = await deriveKey('correct horse battery', newSalt(), 1000);
  await assert.rejects(crypto.subtle.exportKey('raw', key));
});

test('the service worker caches every client file, and nothing else', () => {
  const worker = readFileSync(new URL('../public/sw.js', import.meta.url), 'utf8');
  const listed = [...worker.matchAll(/'(\/app\/[^']*)'/g)].map((m) => m[1]);
  const modules = readdirSync(new URL('../public/js/', import.meta.url)).map((f) => `/app/js/${f}`);
  for (const file of modules) assert.ok(listed.includes(file), `${file} is missing from the service worker shell`);
  assert.ok(listed.includes('/app/') && listed.includes('/app/app.css'));
  assert.ok(!/\/api\/|socket\.io/.test(worker.replace(/\/\/.*$/gm, '')), 'the worker must not touch API or socket traffic');
});
