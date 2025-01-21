import dotenv from 'dotenv';
dotenv.config();

// MongoDB Configuration
const mongoConfig = {
  URI: process.env.MONGO_URI,
};

// Solana Configuration
const solanaConfig = {
  rpcUrl: process.env.SOLANA_RPC_URL || 'https://api.devnet.solana.com',
  privateKey: process.env.SOLANA_PRIVATE_KEY,
};

// JWT Configuration
const jwtConfig = {
  secretKey: process.env.JWT_SECRET || 'your-jwt-secret-key',
};

// TOTP Configuration (using otplib)
const totpConfig = {
  secret: process.env.TOTP_SECRET || 'your-totp-secret-key', // Ensure you store this securely
};

export { mongoConfig, solanaConfig, jwtConfig, totpConfig };
