import LoginEvent from '../models/loginEventModel.js';
import AuditEvent from '../models/auditEventModel.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const RECENT = 50;

const recentLogins = asyncHandler(async (req, res) => {
  const events = await LoginEvent.find({ userId: req.user.userId }).sort({ at: -1 }).limit(RECENT).lean();
  res.status(200).json(
    events.map((e) => ({
      at: e.at,
      outcome: e.outcome,
      ip: e.ip,
      location: e.geo?.country ? [e.geo.city, e.geo.country].filter(Boolean).join(', ') : null,
      riskScore: e.riskScore ?? null,
      reasons: (e.signals || []).map((s) => s.detail),
    }))
  );
});

const auditLog = asyncHandler(async (req, res) => {
  const events = await AuditEvent.find({ userId: req.user.userId })
    .sort({ at: -1 })
    .limit(RECENT)
    .select('type ip details at -_id')
    .lean();
  res.status(200).json(events);
});

export { recentLogins, auditLog };
