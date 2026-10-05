import test from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt } from '../utils/crypto.js';

test('encrypt then decrypt returns the original', () => {
  const secret = 'JBSWY3DPEHPK3PXP';
  assert.equal(decrypt(encrypt(secret)), secret);
});

test('ciphertext is not the plaintext and differs per call', () => {
  const a = encrypt('JBSWY3DPEHPK3PXP');
  const b = encrypt('JBSWY3DPEHPK3PXP');
  assert.ok(a.startsWith('enc:v1:'));
  assert.ok(!a.includes('JBSWY3DPEHPK3PXP'));
  assert.notEqual(a, b);
});

test('tampered ciphertext is rejected', () => {
  const value = encrypt('JBSWY3DPEHPK3PXP');
  const flipped = value.slice(0, -2) + (value.endsWith('AA') ? 'BB' : 'AA');
  assert.throws(() => decrypt(flipped));
});

test('legacy plaintext values pass through unchanged', () => {
  assert.equal(decrypt('JBSWY3DPEHPK3PXP'), 'JBSWY3DPEHPK3PXP');
});
