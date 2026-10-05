// Test-only configuration, loaded before any module reads the environment.
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.ENCRYPTION_KEY = '0123456789abcdef'.repeat(4);
