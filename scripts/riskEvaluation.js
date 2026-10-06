import { scoreLogin } from '../services/riskService.js';
import { RISK_WEIGHTS, HISTORY_SIZE, APPROVAL_THRESHOLD } from '../config/risk.js';
import { lookupGeo, localHour } from '../utils/geo.js';

const geoCache = new Map();
const cachedGeo = (ip) => {
  if (!geoCache.has(ip)) geoCache.set(ip, lookupGeo(ip));
  return geoCache.get(ip);
};

// Walks login records in time order through the real scoring function.
// Record: {user, time (ms), ip, device, attack (bool)}.
// `remember(record, result)` decides whether a login feeds the user's history.
const walk = (records, { historySize = HISTORY_SIZE, anonymizing = () => false, remember }, visit) => {
  const histories = new Map();
  const trusted = new Map();

  for (const r of records) {
    // Datasets may carry their own location and local hour (the public one has
    // synthetic IPs, so looking them up would give meaningless places).
    const geo = r.geo ?? cachedGeo(r.ip);
    const hour = r.localHour ?? localHour(new Date(r.time), geo?.timezone);
    const history = histories.get(r.user) ?? [];
    const devices = trusted.get(r.user) ?? new Set();

    const result = scoreLogin({
      now: new Date(r.time),
      deviceTrusted: devices.has(r.device),
      ip: r.ip,
      geo,
      localHour: hour,
      anonymizingIp: anonymizing(r.ip),
      recentFailures: 0,
      history,
    });
    visit(r, result);

    if (remember(r, result)) {
      history.unshift({ ip: r.ip, geo, localHour: hour, at: r.time });
      if (history.length > historySize) history.length = historySize;
      histories.set(r.user, history);
      devices.add(r.device);
      trusted.set(r.user, devices);
    }
  }
};

const rate = (n, d) => (d === 0 ? 0 : n / d);

// Production-like replay: a challenged attacker fails, a challenged legitimate
// user approves, so only logins that got through feed back into the history.
const replay = (records, { thresholds = [20, 30, 40, 50, 60, 70, 80], ...opts } = {}) => {
  const scored = [];
  const fired = { legit: {}, attack: {} };
  let legit = 0;
  let attacks = 0;

  walk(
    records,
    { ...opts, remember: (r, result) => !r.attack || !result.requiresApproval },
    (r, result) => {
      scored.push({ attack: r.attack, score: result.score });
      r.attack ? attacks++ : legit++;
      const bucket = fired[r.attack ? 'attack' : 'legit'];
      for (const s of result.signals) bucket[s.id] = (bucket[s.id] ?? 0) + 1;
    }
  );

  const share = (counts, total) => Object.fromEntries(Object.entries(counts).map(([id, n]) => [id, rate(n, total)]));
  return {
    legit,
    attacks,
    sweep: thresholds.map((threshold) => ({
      threshold,
      legitChallenged: rate(scored.filter((s) => !s.attack && s.score >= threshold).length, legit),
      attacksChallenged: rate(scored.filter((s) => s.attack && s.score >= threshold).length, attacks),
    })),
    signals: { legit: share(fired.legit, legit), attack: share(fired.attack, attacks) },
    weights: RISK_WEIGHTS,
  };
};

// Signals the data can show. Failed passwords, unrecognized origin and the VPN list
// are not in login datasets, so their weights stay as set.
const TUNABLE = ['newDevice', 'newIp', 'newCountry', 'impossibleTravel', 'oddHour'];

// Held fixed while searching. newDevice is policy (a new device always needs approval)
// and datasets have no reliable device id, so it would be tuned against noise. Impossible
// travel needs coordinates that datasets rarely have.
const FIXED = ['newDevice', 'impossibleTravel'];
const SEARCHED = TUNABLE.filter((id) => !FIXED.includes(id));

// Which signals fired for each login, counted per pattern and per split. Attackers
// are kept out of every user's history, so the pattern of a login does not depend
// on the weights and the table can be searched quickly afterwards.
const collectPatterns = (records, { split, ...opts }) => {
  const table = new Map();
  walk(records, { ...opts, remember: (r) => !r.attack }, (r, result) => {
    const mask = result.signals.reduce((m, s) => {
      const bit = TUNABLE.indexOf(s.id);
      return bit === -1 ? m : m | (1 << bit);
    }, 0);
    const key = `${split(r.user)}:${mask}`;
    const row = table.get(key) ?? { split: split(r.user), mask, legit: 0, attack: 0 };
    row[r.attack ? 'attack' : 'legit']++;
    table.set(key, row);
  });
  return [...table.values()];
};

const scoreOf = (weights, mask) =>
  Math.min(100, TUNABLE.reduce((sum, id, bit) => sum + (mask & (1 << bit) ? weights[id] : 0), 0));

const outcome = (patterns, weights, threshold, split) => {
  let legit = 0;
  let attacks = 0;
  let legitHit = 0;
  let attacksHit = 0;
  for (const p of patterns) {
    if (p.split !== split) continue;
    legit += p.legit;
    attacks += p.attack;
    if (scoreOf(weights, p.mask) >= threshold) {
      legitHit += p.legit;
      attacksHit += p.attack;
    }
  }
  return { legitChallenged: rate(legitHit, legit), attacksChallenged: rate(attacksHit, attacks), legit, attacks };
};

// Random search on the training split: maximise the share of attacks challenged
// while challenging at most `budget` of legitimate logins. Ties go to the weights
// closest to the current ones, so unsupported changes are not made.
const tune = (patterns, { base = RISK_WEIGHTS, budget = 0.02, threshold = APPROVAL_THRESHOLD, iterations = 40000, seed = 11 } = {}) => {
  let state = seed;
  const rand = () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const distance = (w) => TUNABLE.reduce((sum, id) => sum + Math.abs(w[id] - base[id]), 0);
  const current = Object.fromEntries(TUNABLE.map((id) => [id, base[id]]));

  const evaluate = (w) => ({ w, ...outcome(patterns, w, threshold, 'train') });
  const better = (a, b) => {
    const okA = a.legitChallenged <= budget;
    const okB = b.legitChallenged <= budget;
    if (okA !== okB) return okA;
    if (!okA) return a.legitChallenged < b.legitChallenged;
    if (Math.abs(a.attacksChallenged - b.attacksChallenged) > 1e-9) return a.attacksChallenged > b.attacksChallenged;
    return distance(a.w) < distance(b.w);
  };

  let best = evaluate(current);
  for (let i = 0; i < iterations; i++) {
    const candidate = { ...current, ...Object.fromEntries(SEARCHED.map((id) => [id, Math.round((rand() * 40) / 5) * 5])) };
    const result = evaluate(candidate);
    if (better(result, best)) best = result;
  }
  return { weights: best.w, threshold, budget };
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

export { replay, tune, collectPatterns, outcome, syntheticRecords, TUNABLE };
