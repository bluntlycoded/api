// Test-only configuration, loaded before any module reads the environment.
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.ENCRYPTION_KEY = '0123456789abcdef'.repeat(4);
process.env.TRUST_PROXY = '1';
process.env.RATE_LIMIT_DISABLED = 'true';
process.env.WEBAUTHN_RP_ID = 'localhost';
process.env.WEBAUTHN_ORIGINS = 'http://localhost:3000';
