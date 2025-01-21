import { authenticator } from 'otplib';
import speakeasy from 'speakeasy';
import { totpConfig } from '../config/env.js';

// Generate TOTP secret
const generateTOTPSecret = () => {
  const secret = speakeasy.generateSecret();
  return secret.base32;  // Return base32 secret
};

// Verify TOTP code
const verifyTOTPCode = (token, secret) => {
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
  });
  return verified;
};

export { generateTOTPSecret, verifyTOTPCode };
