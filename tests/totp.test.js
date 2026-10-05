import test from 'node:test';
import assert from 'node:assert/strict';
import { generateSecret, generateCode, verifyCode } from '../services/totpService.js';

test('a current code is accepted and returns its time step', () => {
  const secret = generateSecret();
  const step = verifyCode(generateCode(secret), secret);
  assert.equal(typeof step, 'number');
});

test('a code cannot be reused once its step is recorded', () => {
  const secret = generateSecret();
  const code = generateCode(secret);
  const step = verifyCode(code, secret);
  assert.equal(verifyCode(code, secret, step), null);
});

test('a wrong code is rejected', () => {
  const secret = generateSecret();
  const wrong = generateCode(secret) === '000000' ? '111111' : '000000';
  assert.equal(verifyCode(wrong, secret), null);
});
