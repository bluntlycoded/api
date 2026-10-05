import test from 'node:test';
import assert from 'node:assert/strict';
import { createNumberChallenge } from '../services/approvalService.js';
import { sha256, safeEqualHex, randomToken } from '../utils/crypto.js';

test('challenge has 3 distinct two-digit options including the number', () => {
  for (let i = 0; i < 500; i++) {
    const { number, options } = createNumberChallenge();
    assert.equal(options.length, 3);
    assert.equal(new Set(options).size, 3);
    assert.ok(options.includes(number));
    assert.ok(options.every((n) => n >= 10 && n <= 99));
  }
});

test('the correct number is not always in the same position', () => {
  const positions = new Set();
  for (let i = 0; i < 200; i++) {
    const { number, options } = createNumberChallenge();
    positions.add(options.indexOf(number));
  }
  assert.equal(positions.size, 3);
});

test('tokens are unique and hash comparison is exact', () => {
  const a = randomToken();
  const b = randomToken();
  assert.notEqual(a, b);
  assert.equal(a.length, 64);
  assert.ok(safeEqualHex(sha256(a), sha256(a)));
  assert.ok(!safeEqualHex(sha256(a), sha256(b)));
  assert.ok(!safeEqualHex(sha256(a), 'abcd'));
});
