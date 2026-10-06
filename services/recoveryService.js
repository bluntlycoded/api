import crypto from 'crypto';
import * as recovery from '../repositories/recoveryRepository.js';
import { sha256 } from '../utils/crypto.js';

const CODE_COUNT = 10;
// No 0/O or 1/I so codes survive being read off paper.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

const randomCode = () => {
  const chars = Array.from({ length: 12 }, () => ALPHABET[crypto.randomInt(ALPHABET.length)]).join('');
  return chars.match(/.{4}/g).join('-');
};

const normalize = (code) => String(code).replace(/[\s-]/g, '').toUpperCase();

const hashCode = (code) => sha256(`recovery:${normalize(code)}`);

// 60 bits each, shown once, stored only as hashes.
const generateCodes = async (userId) => {
  const codes = Array.from({ length: CODE_COUNT }, randomCode);
  await recovery.replaceAll(userId, codes.map(hashCode));
  return codes;
};

const useCode = (userId, code) => recovery.consume(userId, hashCode(code));

export { generateCodes, useCode, hashCode };
