import * as events from '../repositories/eventRepository.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const RECENT = 50;

const recentLogins = asyncHandler(async (req, res) => {
  const rows = await events.recentLogins(req.user.userId, RECENT);
  res.status(200).json(
    rows.map((e) => ({
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
  res.status(200).json(await events.recentAudit(req.user.userId, RECENT));
});

export { recentLogins, auditLog };
