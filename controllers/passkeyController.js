import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { config } from '../config/env.js';
import * as users from '../repositories/userRepository.js';
import * as passkeys from '../repositories/passkeyRepository.js';
import * as challenges from '../repositories/challengeRepository.js';
import * as blockedIps from '../repositories/blockedIpRepository.js';
import { requestContext, completeLogin } from '../services/loginService.js';
import { audit } from '../services/auditService.js';
import { sha256 } from '../utils/crypto.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const { rpId, rpName, origins } = config.webauthn;

const requirePasskeys = (req, res, next) => {
  if (!rpId || origins.length === 0) throw new HttpError(501, 'Passkeys are not configured on this server');
  next();
};

const expiry = () => new Date(Date.now() + CHALLENGE_TTL_MS);

// Registration (trusted device only): the passkey is stored against the account.
const registrationOptions = asyncHandler(async (req, res) => {
  const user = await users.findById(req.user.userId);
  const existing = await passkeys.listForUser(user.id);

  const options = await generateRegistrationOptions({
    rpName,
    rpID: rpId,
    userName: user.email,
    userDisplayName: user.name,
    userID: Buffer.from(user.id.replace(/-/g, ''), 'hex'),
    attestationType: 'none',
    excludeCredentials: existing.map((p) => ({ id: p.credentialId, transports: p.transports })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
  });
  const { id } = await challenges.create({
    userId: user.id,
    purpose: 'register',
    challenge: options.challenge,
    expiresAt: expiry(),
  });
  res.status(200).json({ challengeId: id, options });
});

const registrationVerify = asyncHandler(async (req, res) => {
  const { challengeId, response, name } = req.body;
  const challenge = await challenges.take(challengeId, 'register');
  if (!challenge || challenge.userId !== req.user.userId) throw new HttpError(400, 'Challenge expired or invalid');

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: origins,
      expectedRPID: rpId,
      requireUserVerification: true,
    });
  } catch {
    throw new HttpError(400, 'Passkey registration could not be verified');
  }
  if (!verification.verified) throw new HttpError(400, 'Passkey registration could not be verified');

  const { credential } = verification.registrationInfo;
  const saved = await passkeys.insert(req.user.userId, {
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    transports: credential.transports,
    name: name || 'Passkey',
  });
  await audit(req.user.userId, 'passkey_added', req.ip, { name: saved.name });
  res.status(201).json({ id: saved.id, name: saved.name });
});

const listPasskeys = asyncHandler(async (req, res) => {
  const rows = await passkeys.listForUser(req.user.userId);
  res.status(200).json(rows.map(({ id, name, createdAt, lastUsed }) => ({ id, name, createdAt, lastUsed })));
});

const removePasskey = asyncHandler(async (req, res) => {
  if (!(await passkeys.remove(req.user.userId, req.params.id))) throw new HttpError(404, 'Passkey not found');
  await audit(req.user.userId, 'passkey_removed', req.ip, { id: req.params.id });
  res.status(200).json({ message: 'Passkey removed' });
});

// Login (public): usernameless, using a discoverable credential.
const loginOptions = asyncHandler(async (req, res) => {
  const options = await generateAuthenticationOptions({ rpID: rpId, userVerification: 'required' });
  const { id } = await challenges.create({ purpose: 'login', challenge: options.challenge, expiresAt: expiry() });
  res.status(200).json({ challengeId: id, options });
});

// A verified passkey is phishing-resistant (bound to the site) and proves
// possession plus user verification, so it replaces the password and the
// approval step. A new device still starts untrusted.
const loginVerify = asyncHandler(async (req, res) => {
  const { challengeId, response, deviceId, deviceName } = req.body;
  const ctx = requestContext(req);

  if (await blockedIps.isBlocked(ctx.ip)) throw new HttpError(403, 'Access denied', { code: 'IP_BLOCKED' });

  const challenge = await challenges.take(challengeId, 'login');
  if (!challenge) throw new HttpError(400, 'Challenge expired or invalid');

  const passkey = await passkeys.findByCredentialId(response?.id);
  if (!passkey) throw new HttpError(401, 'Passkey not recognized');

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: origins,
      expectedRPID: rpId,
      requireUserVerification: true,
      credential: {
        id: passkey.credentialId,
        publicKey: Buffer.from(passkey.publicKey, 'base64url'),
        counter: passkey.counter,
        transports: passkey.transports,
      },
    });
  } catch {
    throw new HttpError(401, 'Passkey could not be verified');
  }
  if (!verification.verified) throw new HttpError(401, 'Passkey could not be verified');

  // Rejects a replayed or cloned authenticator whose counter did not advance.
  if (!(await passkeys.recordUse(passkey.id, verification.authenticationInfo.newCounter))) {
    throw new HttpError(401, 'Passkey could not be verified');
  }

  const user = await users.findById(passkey.userId);
  if (user.locked) {
    throw new HttpError(423, 'This account is locked. Reset your password to unlock it.', { code: 'ACCOUNT_LOCKED' });
  }

  const token = await completeLogin(user, {
    deviceHash: sha256(deviceId),
    deviceName,
    trust: false,
    ctx,
    risk: { score: 0, signals: [{ id: 'passkey', points: 0, detail: 'Signed in with a passkey' }] },
  });
  res.status(200).json({ token });
});

export {
  requirePasskeys,
  registrationOptions,
  registrationVerify,
  listPasskeys,
  removePasskey,
  loginOptions,
  loginVerify,
};
