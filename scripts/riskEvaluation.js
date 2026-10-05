import { scoreLogin } from '../services/riskService.js';
import { RISK_WEIGHTS, HISTORY_SIZE } from '../config/risk.js';
import { lookupGeo, localHour } from '../utils/geo.js';

// Replays login attempts in time order through the real scoring function.
// Each record: {user, time (ms), ip, device, attack (bool)}.
// The user "approves" every challenged legitimate login, and a challenged
// attacker login fails, so only passed logins feed back into a user's history.
const replay = (records, { thresholds = [20, 30, 40, 50, 60, 70, 80], anonymizing = () => false } = {}) => {
  const histories = new Map();
  const trustedDevices = new Map();
  const scored = [];
  const signalCounts = { legit: {}, attack: {} };
  let legit = 0;
  let attacks = 0;

  for (const r of records) {
    const geo = lookupGeo(r.ip);
    const now = new Date(r.time);
    const history = histories.get(r.user) ?? [];
    const devices = trustedDevices.get(r.user) ?? new Set();

    const result = scoreLogin({
      now,
      deviceTrusted: devices.has(r.device),
      ip: r.ip,
      geo,
      localHour: localHour(now, geo?.timezone),
      anonymizingIp: anonymizing(r.ip),
      recentFailures: 0,
      history,
    });
    scored.push({ attack: r.attack, score: result.score });

    const bucket = r.attack ? 'attack' : 'legit';
    r.attack ? attacks++ : legit++;
    for (const s of result.signals) signalCounts[bucket][s.id] = (signalCounts[bucket][s.id] ?? 0) + 1;

    const passed = !r.attack || !result.requiresApproval;
    if (passed) {
      history.unshift({ ip: r.ip, geo, localHour: localHour(now, geo?.timezone), at: now });
      histories.set(r.user, history.slice(0, HISTORY_SIZE));
      devices.add(r.device);
      trustedDevices.set(r.user, devices);
    }
  }

  const rate = (n, d) => (d === 0 ? 0 : n / d);
  const sweep = thresholds.map((threshold) => ({
    threshold,
    legitChallenged: rate(scored.filter((s) => !s.attack && s.score >= threshold).length, legit),
    attacksChallenged: rate(scored.filter((s) => s.attack && s.score >= threshold).length, attacks),
  }));

  const share = (counts, total) => Object.fromEntries(Object.entries(counts).map(([id, n]) => [id, rate(n, total)]));
  return {
    legit,
    attacks,
    sweep,
    signals: { legit: share(signalCounts.legit, legit), attack: share(signalCounts.attack, attacks) },
    weights: RISK_WEIGHTS,
  };
};

// Small seeded generator so runs are repeatable. It only checks the pipeline;
// its numbers say nothing about real-world accuracy.
const syntheticRecords = ({ users = 200, days = 30, attackRate = 0.05, seed = 7 } = {}) => {
  let state = seed;
  const rand = () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = (list) => list[Math.floor(rand() * list.length)];

  const homeIps = ['103.21.58.1', '49.36.0.1'];
  const foreignIps = ['81.2.69.142', '24.24.24.24', '2.125.160.216', '1.1.1.1'];
  const start = Date.UTC(2026, 0, 1);
  const records = [];

  for (let u = 0; u < users; u++) {
    const devices = [`phone-${u}`, `laptop-${u}`];
    for (let d = 0; d < days; d++) {
      for (let k = 0; k < 1 + Math.floor(rand() * 3); k++) {
        const hour = 8 + Math.floor(rand() * 12);
        const time = start + d * 86400000 + hour * 3600000 + Math.floor(rand() * 3600000);
        records.push({ user: u, time, ip: pick(homeIps), device: pick(devices), attack: false });
      }
      if (rand() < attackRate) {
        const time = start + d * 86400000 + Math.floor(rand() * 86400000);
        const nearby = rand() < 0.3;
        records.push({ user: u, time, ip: nearby ? pick(homeIps) : pick(foreignIps), device: `attacker-${u}-${d}`, attack: true });
      }
    }
  }
  return records.sort((a, b) => a.time - b.time);
};

export { replay, syntheticRecords };
