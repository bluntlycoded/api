import crypto from 'crypto';

// Cryptographically random shuffle (Fisher-Yates).
const shuffle = (items) => {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
};

// The login screen shows `number`; the approving device shows `options` (the
// number plus two decoys) and the user must pick the right one.
const createNumberChallenge = () => {
  const number = crypto.randomInt(10, 100);
  const options = new Set([number]);
  while (options.size < 3) options.add(crypto.randomInt(10, 100));
  return { number, options: shuffle([...options]) };
};

// What the approver sees. `number` is deliberately absent.
const toApproverView = (a) => ({
  id: a.id,
  requestedAt: a.createdAt,
  expiresAt: a.expiresAt,
  site: a.site || null,
  siteSource: a.siteSource,
  ip: a.ip,
  location: a.geo?.country ? [a.geo.city, a.geo.region, a.geo.country].filter(Boolean).join(', ') : 'Unknown location',
  deviceName: a.requestDeviceName || 'Unknown device',
  userAgent: a.userAgent,
  riskScore: a.riskScore,
  reasons: (a.signals || []).map((s) => s.detail),
  options: a.options,
});

export { createNumberChallenge, toApproverView };
