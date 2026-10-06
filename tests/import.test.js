import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { parseOtpauthUri, parseGoogleMigration, parseImport, toOtpauthUri, base32Encode } from '../services/importService.js';
import { generateCode } from '../services/otpService.js';

const varint = (n) => {
  const out = [];
  while (n > 127) {
    out.push((n & 127) | 128);
    n = Math.floor(n / 128);
  }
  return [...out, n];
};
const bytesField = (field, bytes) => [...varint((field << 3) | 2), ...varint(bytes.length), ...bytes];
const intField = (field, n) => [...varint(field << 3), ...varint(n)];

test('base32 matches the RFC 4648 vectors', () => {
  assert.equal(base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
  assert.equal(base32Encode(Buffer.from('fooba')), 'MZXW6YTB');
  assert.equal(base32Encode(Buffer.from('12345678901234567890')), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
});

test('TOTP codes match the RFC 6238 test vectors', () => {
  mock.method(Date, 'now', () => 59000);
  const sha1 = { type: 'totp', secretKey: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', digits: 8, period: 30, algorithm: 'SHA1' };
  assert.equal(generateCode(sha1).otp, '94287082');
  const sha256 = { ...sha1, algorithm: 'SHA256', secretKey: base32Encode(Buffer.from('12345678901234567890123456789012')) };
  assert.equal(generateCode(sha256).otp, '46119246');
  mock.restoreAll();
});

test('HOTP codes match the RFC 4226 test vectors', () => {
  const entry = { type: 'hotp', secretKey: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', digits: 6, algorithm: 'SHA1' };
  assert.equal(generateCode({ ...entry, counter: 0 }).otp, '755224');
  assert.equal(generateCode({ ...entry, counter: 1 }).otp, '287082');
});

test('otpauth URIs: issuer, account, options and bad input', () => {
  const loose = parseOtpauthUri('otpauth://totp/GitHub:me?secret=jbsw%20y3dp-ehpk3pxp');
  assert.equal(loose.secretKey, 'JBSWY3DPEHPK3PXP', 'spaces, dashes and case are cleaned');
  const ok = parseOtpauthUri('otpauth://totp/GitHub:me%40x.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=60&digits=8');
  assert.deepEqual(
    { n: ok.appName, i: ok.issuer, a: ok.account, p: ok.period, d: ok.digits, t: ok.type },
    { n: 'GitHub', i: 'GitHub', a: 'me@x.com', p: 60, d: 8, t: 'totp' }
  );
  assert.equal(parseOtpauthUri('https://example.com'), null);
  assert.equal(parseOtpauthUri('otpauth://totp/x?secret=short'), null);
});

test('export then import round-trips', () => {
  const original = parseOtpauthUri('otpauth://hotp/Bank:me?secret=JBSWY3DPEHPK3PXP&issuer=Bank&counter=7&digits=7');
  const again = parseOtpauthUri(toOtpauthUri(original));
  assert.deepEqual(again, original);
});

test('Google Authenticator export format', () => {
  const secret = Buffer.from('12345678901234567890');
  const params = [
    ...bytesField(1, secret),
    ...bytesField(2, Buffer.from('me@x.com')),
    ...bytesField(3, Buffer.from('Google')),
    ...intField(4, 2), // SHA256
    ...intField(5, 2), // 8 digits
    ...intField(6, 2), // TOTP
  ];
  const payload = [...bytesField(1, params), ...intField(2, 1)];
  const uri = `otpauth-migration://offline?data=${encodeURIComponent(Buffer.from(payload).toString('base64'))}`;
  const [entry] = parseGoogleMigration(uri);
  assert.deepEqual(
    { n: entry.appName, a: entry.account, s: entry.secretKey, alg: entry.algorithm, d: entry.digits, t: entry.type },
    { n: 'Google', a: 'me@x.com', s: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', alg: 'SHA256', d: 8, t: 'totp' }
  );
  assert.equal(parseImport(uri).valid.length, 1);
});

test('import limits and invalid lines', () => {
  const lines = Array(501).fill('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP').join('\n');
  assert.throws(() => parseImport(lines), /limited to 500/);
  assert.deepEqual(parseImport('garbage\n\n').skipped, 1);
});
