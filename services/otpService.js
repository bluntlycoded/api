import otplib from 'otplib';

const { authenticator, hotp } = otplib;

const ALGORITHMS = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };
const algorithm = (name) => ALGORITHMS[name] ?? ALGORITHMS.SHA1;

// Both code types go through the hotp primitive with the secret decoded to hex.
// otplib's own TOTP quietly stretches secrets shorter than the hash block for
// SHA-512, which gives codes no other authenticator produces.
const generate = (secretKey, counter, options) =>
  hotp.clone({ ...options, encoding: 'hex' }).generate(authenticator.decode(secretKey), counter);

// Current code for a saved entry. HOTP entries must pass the already
// advanced counter (see appRepository.nextCounter).
const generateCode = (app) => {
  const options = { digits: app.digits, algorithm: algorithm(app.algorithm) };
  if (app.type === 'hotp') return { otp: generate(app.secretKey, app.counter, options), counter: app.counter };

  const seconds = Math.floor(Date.now() / 1000);
  return {
    otp: generate(app.secretKey, Math.floor(seconds / app.period), options),
    expiresInSeconds: app.period - (seconds % app.period),
  };
};

export { generateCode };
