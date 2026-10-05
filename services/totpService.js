import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import { config } from '../config/env.js';

// Accept the previous and next 30s step to allow for clock drift.
const totp = authenticator.clone({ window: 1 });

const generateSecret = () => totp.generateSecret();

const buildSetup = async (email, secret) => {
  const otpauthUrl = totp.keyuri(email, config.totpIssuer, secret);
  return { secret, otpauthUrl, qrCode: await QRCode.toDataURL(otpauthUrl) };
};

// Returns the accepted time step, or null if the code is wrong or was already
// used (its step is not newer than `lastStep`).
const verifyCode = (code, secret, lastStep = 0) => {
  const delta = totp.checkDelta(code, secret);
  if (delta === null) return null;
  const step = Math.floor(Date.now() / (totp.allOptions().step * 1000)) + delta;
  return step > lastStep ? step : null;
};

const generateCode = (secret) => totp.generate(secret);

export { generateSecret, buildSetup, verifyCode, generateCode };
