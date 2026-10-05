import Approval from '../models/approvalModel.js';
import { APPROVAL_MAX_WRONG_ATTEMPTS } from '../config/risk.js';
import { toApproverView } from '../services/approvalService.js';
import { audit } from '../services/auditService.js';
import { notifyApprovalResolved } from '../services/realtime.js';
import { sha256, safeEqualHex } from '../utils/crypto.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const NOT_FOUND = 'Request not found or already resolved';

const listPending = asyncHandler(async (req, res) => {
  const items = await Approval.find({
    userId: req.user.userId,
    status: 'pending',
    expiresAt: { $gt: new Date() },
  })
    .sort({ createdAt: -1 })
    .lean();
  res.status(200).json(items.map(toApproverView));
});

const respond = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { action, choice, trustDevice } = req.body;
  const { userId, did } = req.user;
  const live = { _id: id, userId, status: 'pending', expiresAt: { $gt: new Date() } };

  const resolve = async (update, status) => {
    const done = await Approval.findOneAndUpdate(live, { $set: { status, ...update } });
    if (!done) throw new HttpError(404, NOT_FOUND);
    notifyApprovalResolved(userId, id, status);
    await audit(userId, status === 'approved' ? 'login_approved' : 'login_denied', req.ip, { challengeId: id });
    return res.status(200).json({ status });
  };

  if (action === 'deny') return resolve({}, 'denied');

  if (choice === undefined) {
    throw new HttpError(400, 'choice (the number shown on the login screen) is required');
  }

  const approval = await Approval.findOne(live).select('number requestDeviceHash').lean();
  if (!approval) throw new HttpError(404, NOT_FOUND);
  if (approval.requestDeviceHash === did) throw new HttpError(403, 'A device cannot approve its own login');

  if (choice === approval.number) {
    return resolve({ approvedByDeviceHash: did, trustDevice: trustDevice === true }, 'approved');
  }

  // Wrong number: count it, and cancel the request after too many misses.
  const updated = await Approval.findOneAndUpdate(live, { $inc: { wrongAttempts: 1 } }, { new: true });
  if (!updated) throw new HttpError(404, NOT_FOUND);
  if (updated.wrongAttempts >= APPROVAL_MAX_WRONG_ATTEMPTS) {
    await Approval.updateOne({ _id: id, status: 'pending' }, { $set: { status: 'denied' } });
    notifyApprovalResolved(userId, id, 'denied');
    await audit(userId, 'login_denied', req.ip, { challengeId: id, reason: 'wrong number' });
    throw new HttpError(403, 'Wrong number too many times. Request cancelled.', { status: 'denied' });
  }
  throw new HttpError(400, 'That is not the number on the login screen', {
    attemptsLeft: APPROVAL_MAX_WRONG_ATTEMPTS - updated.wrongAttempts,
  });
});

// Called by the login screen, which has no JWT yet.
const pollStatus = asyncHandler(async (req, res) => {
  const approval = await Approval.findById(req.params.id).select('pollSecretHash status expiresAt').lean();
  if (!approval || !safeEqualHex(approval.pollSecretHash, sha256(req.body.pollSecret))) {
    throw new HttpError(404, 'Request not found');
  }
  const expired = approval.status === 'pending' && approval.expiresAt <= new Date();
  res.status(200).json({ status: expired ? 'expired' : approval.status });
});

export { listPending, respond, pollStatus };
