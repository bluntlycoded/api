import * as approvals from '../repositories/approvalRepository.js';
import * as users from '../repositories/userRepository.js';
import * as blockedIps from '../repositories/blockedIpRepository.js';
import { revokeForUser } from '../repositories/refreshTokenRepository.js';
import { APPROVAL_MAX_WRONG_ATTEMPTS, BLOCK_DAYS } from '../config/risk.js';
import { toApproverView } from '../services/approvalService.js';
import { audit } from '../services/auditService.js';
import { notifyApprovalResolved } from '../services/realtime.js';
import { sha256, safeEqualHex } from '../utils/crypto.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const NOT_FOUND = 'Request not found or already resolved';

const listPending = asyncHandler(async (req, res) => {
  res.status(200).json((await approvals.listPending(req.user.userId)).map(toApproverView));
});

const respond = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { action, choice, trustDevice } = req.body;
  const { userId, did } = req.user;

  const resolve = async (status, options) => {
    if (!(await approvals.resolveLive(id, userId, status, options))) throw new HttpError(404, NOT_FOUND);
    notifyApprovalResolved(userId, id, status);
    await audit(userId, status === 'approved' ? 'login_approved' : 'login_denied', req.ip, { challengeId: id });
    return res.status(200).json({ status });
  };

  if (action === 'deny') return resolve('denied');

  if (choice === undefined) {
    throw new HttpError(400, 'choice (the number shown on the login screen) is required');
  }

  const approval = await approvals.findLive(id, userId);
  if (!approval) throw new HttpError(404, NOT_FOUND);
  if (approval.requestDeviceHash === did) throw new HttpError(403, 'A device cannot approve its own login');

  if (choice === approval.number) {
    return resolve('approved', { approvedByDeviceHash: did, trustDevice: trustDevice === true });
  }

  // Wrong number: count it, and cancel the request after too many misses.
  const wrongAttempts = await approvals.addWrongAttempt(id, userId);
  if (wrongAttempts === undefined) throw new HttpError(404, NOT_FOUND);
  if (wrongAttempts >= APPROVAL_MAX_WRONG_ATTEMPTS) {
    await approvals.resolveLive(id, userId, 'denied');
    notifyApprovalResolved(userId, id, 'denied');
    await audit(userId, 'login_denied', req.ip, { challengeId: id, reason: 'wrong number' });
    throw new HttpError(403, 'Wrong number too many times. Request cancelled.', { status: 'denied' });
  }
  throw new HttpError(400, 'That is not the number on the login screen', {
    attemptsLeft: APPROVAL_MAX_WRONG_ATTEMPTS - wrongAttempts,
  });
});

// "This wasn't me": denies the request, blocks the requesting IP for a while and
// locks the account until the password is reset.
const report = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { userId } = req.user;

  const approval = await approvals.findLive(id, userId);
  if (!approval) throw new HttpError(404, NOT_FOUND);

  await approvals.resolveLive(id, userId, 'denied');
  await Promise.all([
    blockedIps.block(approval.ip, 'reported by account owner', new Date(Date.now() + BLOCK_DAYS * 86400000)),
    users.lock(userId),
    revokeForUser(userId),
  ]);
  notifyApprovalResolved(userId, id, 'denied');
  await audit(userId, 'login_reported', req.ip, { challengeId: id, blockedIp: approval.ip });
  res.status(200).json({ status: 'reported', accountLocked: true });
});

// Called by the login screen, which has no JWT yet.
const pollStatus = asyncHandler(async (req, res) => {
  const approval = await approvals.findById(req.params.id);
  if (!approval || !safeEqualHex(approval.pollSecretHash, sha256(req.body.pollSecret))) {
    throw new HttpError(404, 'Request not found');
  }
  const expired = approval.status === 'pending' && approval.expiresAt <= new Date();
  res.status(200).json({ status: expired ? 'expired' : approval.status });
});

export { listPending, respond, report, pollStatus };
