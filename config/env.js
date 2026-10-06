import dotenv from 'dotenv';

dotenv.config();

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required (see .env.example)`);
  return value;
};

const encryptionKey = () => {
  const hex = required('ENCRYPTION_KEY');
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('ENCRYPTION_KEY must be 64 hex characters (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
};

const list = (value) =>
  (value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

const trustProxy = () => {
  const value = process.env.TRUST_PROXY;
  if (!value) return false;
  if (value === 'true') return true;
  return Number.isNaN(Number(value)) ? value : Number(value);
};

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT) || 2700,
  trustProxy: trustProxy(),
  databaseUrl: process.env.DATABASE_URL,
  // Supabase requires TLS. Set DATABASE_SSL=false for a local Postgres.
  databaseSsl: process.env.DATABASE_SSL !== 'false',
  jwtSecret: required('JWT_SECRET'),
  jwtExpiresIn: '15m',
  accessTokenSeconds: 900,
  encryptionKey: encryptionKey(),
  // Origins allowed to call the API. Empty means any origin (CORS) and
  // disables the unrecognized-origin risk signal.
  allowedOrigins: list(process.env.ALLOWED_ORIGINS),
  rateLimitDisabled: process.env.RATE_LIMIT_DISABLED === 'true',
  totpIssuer: process.env.TOTP_ISSUER || 'FraudShield Authenticator',
  solanaRpcUrl: process.env.SOLANA_RPC_URL || 'https://api.devnet.solana.com',
  passwordResetUrl: process.env.PASSWORD_RESET_URL,
  webauthn: {
    rpId: process.env.WEBAUTHN_RP_ID,
    rpName: process.env.WEBAUTHN_RP_NAME || 'FraudShield Authenticator',
    origins: list(process.env.WEBAUTHN_ORIGINS),
  },
  // Optional file of VPN/proxy/datacentre CIDR ranges, one per line.
  ipRangesFile: process.env.IP_RANGES_FILE,
  smtp: {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.SMTP_FROM,
  },
};
