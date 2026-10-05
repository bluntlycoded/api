import otplib from 'otplib';

const { authenticator, hotp } = otplib;

const ALGORITHMS = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };
const algorithm = (name) => ALGORITHMS[name] ?? ALGORITHMS.SHA1;

// Current code for a saved entry. HOTP entries must pass the already
// advanced counter (see appRepository.nextCounter).
const generateCode = (app) => {
  const options = { digits: app.digits, algorithm: algorithm(app.algorithm) };
  // The hotp object takes hex secrets, so decode the base32 secret first.
  if (app.type === 'hotp') {
    return { otp: hotp.clone({ ...options, encoding: 'hex' }).generate(authenticator.decode(app.secretKey), app.counter), counter: app.counter };
  }

  const totp = authenticator.clone({ ...options, step: app.period });
  return { otp: totp.generate(app.secretKey), expiresInSeconds: app.period - (Math.floor(Date.now() / 1000) % app.period) };
};

export { generateCode };
