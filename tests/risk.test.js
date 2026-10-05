import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreLogin } from '../services/riskService.js';
import { haversineKm, lookupGeo, localHour } from '../utils/geo.js';

const NOW = new Date('2026-10-05T12:00:00Z');
const minutesAgo = (m) => new Date(NOW - m * 60000);

const MUMBAI = { country: 'IN', city: 'Mumbai', lat: 19.07, lon: 72.88, timezone: 'Asia/Kolkata' };
const LONDON = { country: 'GB', city: 'London', lat: 51.5, lon: -0.12, timezone: 'Europe/London' };
const PUNE = { country: 'IN', city: 'Pune', lat: 18.52, lon: 73.85, timezone: 'Asia/Kolkata' };

const history = [{ ip: '1.1.1.1', geo: MUMBAI, localHour: 18, at: minutesAgo(60 * 24) }];
const base = {
  now: NOW,
  deviceTrusted: true,
  ip: '1.1.1.1',
  geo: MUMBAI,
  localHour: 17,
  recentFailures: 0,
  history,
};
const ids = (r) => r.signals.map((s) => s.id);

test('known device, known IP, usual hour scores 0', () => {
  const r = scoreLogin(base);
  assert.equal(r.score, 0);
  assert.equal(r.requiresApproval, false);
});

test('first ever login becomes the baseline without a challenge', () => {
  const r = scoreLogin({ ...base, deviceTrusted: false, history: [] });
  assert.equal(r.score, 0);
  assert.equal(r.baseline, true);
});

test('new device alone forces approval', () => {
  const r = scoreLogin({ ...base, deviceTrusted: false });
  assert.deepEqual(ids(r), ['newDevice']);
  assert.equal(r.requiresApproval, true);
});

test('new IP in the same city on a trusted device does not force approval', () => {
  const r = scoreLogin({ ...base, ip: '2.2.2.2', geo: PUNE });
  assert.deepEqual(ids(r), ['newIp']);
  assert.equal(r.requiresApproval, false);
});

test('new country alone is below the threshold, new country at an odd hour is not', () => {
  const alone = scoreLogin({ ...base, ip: '3.3.3.3', geo: { ...LONDON }, now: new Date(NOW.getTime() + 3 * 86400000) });
  assert.ok(ids(alone).includes('newCountry'));
  const night = scoreLogin({ ...base, ip: '3.3.3.3', geo: LONDON, localHour: 3, now: new Date(NOW.getTime() + 3 * 86400000) });
  assert.ok(ids(night).includes('oddHour'));
  assert.equal(night.requiresApproval, true);
});

test('impossible travel: Mumbai then London 30 minutes later', () => {
  const recent = [{ ip: '1.1.1.1', geo: MUMBAI, localHour: 17, at: minutesAgo(30) }];
  const r = scoreLogin({ ...base, history: recent, ip: '3.3.3.3', geo: LONDON, localHour: 12 });
  assert.ok(ids(r).includes('impossibleTravel'));
  assert.equal(r.requiresApproval, true);
});

test('plausible travel: Mumbai then London a day later is not flagged', () => {
  const r = scoreLogin({ ...base, ip: '3.3.3.3', geo: LONDON, localHour: 12 });
  assert.ok(!ids(r).includes('impossibleTravel'));
});

test('short hops are ignored even when fast (IP geolocation is city-level)', () => {
  const recent = [{ ip: '1.1.1.1', geo: MUMBAI, localHour: 17, at: minutesAgo(1) }];
  const r = scoreLogin({ ...base, history: recent, ip: '2.2.2.2', geo: { ...MUMBAI, lat: 19.2, lon: 72.9 } });
  assert.ok(!ids(r).includes('impossibleTravel'));
});

test('same IP twice never counts as travel', () => {
  const recent = [{ ip: '1.1.1.1', geo: MUMBAI, localHour: 17, at: minutesAgo(1) }];
  assert.ok(!ids(scoreLogin({ ...base, history: recent })).includes('impossibleTravel'));
});

test('odd hour is not flagged if the user has logged in at that hour before', () => {
  const nightOwl = [{ ip: '1.1.1.1', geo: MUMBAI, localHour: 3, at: minutesAgo(60 * 24) }];
  assert.ok(!ids(scoreLogin({ ...base, history: nightOwl, localHour: 3 })).includes('oddHour'));
  assert.ok(ids(scoreLogin({ ...base, localHour: 3 })).includes('oddHour'));
});

test('unrecognized origin and repeated failures add risk', () => {
  const r = scoreLogin({ ...base, originUnrecognized: true });
  assert.equal(r.requiresApproval, true);
  const f = scoreLogin({ ...base, recentFailures: 3, localHour: 3 });
  assert.deepEqual(ids(f).sort(), ['oddHour', 'recentFailures']);
});

test('score is capped at 100', () => {
  const recent = [{ ip: '1.1.1.1', geo: MUMBAI, localHour: 17, at: minutesAgo(10) }];
  const r = scoreLogin({
    ...base, history: recent, deviceTrusted: false, ip: '9.9.9.9', geo: LONDON,
    localHour: 3, originUnrecognized: true, recentFailures: 5,
  });
  assert.equal(r.score, 100);
});

test('missing geolocation never triggers location signals', () => {
  const r = scoreLogin({ ...base, geo: null, localHour: null });
  assert.deepEqual(ids(r), []);
});

test('haversine: Mumbai to London is about 7,200 km', () => {
  const d = haversineKm([MUMBAI.lat, MUMBAI.lon], [LONDON.lat, LONDON.lon]);
  assert.ok(d > 7100 && d < 7300, `got ${d}`);
});

test('geo helpers', () => {
  assert.equal(lookupGeo('127.0.0.1'), null);
  assert.equal(lookupGeo('::ffff:10.0.0.1'), null);
  assert.equal(localHour(new Date('2026-10-05T12:00:00Z'), 'Asia/Kolkata'), 17);
  assert.equal(localHour(new Date('2026-10-05T12:00:00Z'), 'Not/AZone'), null);
  assert.equal(localHour(new Date(), undefined), null);
});
