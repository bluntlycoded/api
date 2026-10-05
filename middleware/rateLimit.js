import rateLimit from 'express-rate-limit';

const limiter = (windowMinutes, limit, message) =>
  rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { message },
  });

// Whole API, per IP.
export const apiLimiter = limiter(15, 600, 'Too many requests. Try again later.');

// Credential endpoints: login, register, password reset, login completion.
export const credentialLimiter = limiter(15, 30, 'Too many attempts. Try again later.');
