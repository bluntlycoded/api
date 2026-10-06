// Replays login data through the risk scorer, then tunes the signal weights.
//
//   npm run evaluate:risk -- --synthetic
//   npm run evaluate:risk -- rba-dataset.csv [--sample 20] [--history 50] [--budget 0.02]
//   --ignore-device sets the new-device weight to 0 for the tuning step (use it on data whose
//   device column is noisy, such as the public set).
//   unzip -p rba-dataset.zip rba-dataset.csv | npm run evaluate:risk -- - --sample 20 --keep-users ato_users.txt
//
// Account takeovers are rare (141 rows across 138 users in the public data), so a plain
// user sample would contain almost none. --keep-users takes a file with one user id per
// line (an optional leading count is ignored) and keeps every row of those users too:
//   unzip -p rba-dataset.zip rba-dataset.csv | awk -F, 'NR>1 && $NF=="True"{print $3}' | sort -u > ato_users.txt
//
// Input is the public "Login Data Set for Risk-Based Authentication" (Wiefling et al.,
// Zenodo 10.5281/zenodo.6782155), rows in time order. Choices made here:
//  - legitimate = successful login that is neither from an attack IP nor an account takeover
//  - attacker   = account takeover (the attacker had the password, which is the case risk
//                 scoring exists for; wrong-password attempts never reach it)
//  - device     = browser + OS + device type with versions removed (the data has no device id)
//  - location   = the Country column (its IPs are synthetic, so they are not looked up);
//                 there are no coordinates, so impossible travel cannot be evaluated here
//  - local hour = Europe/Oslo for everyone (the service is Norwegian)
//  - users are sampled 1 in --sample by id hash to keep memory bounded; half of the sample
//    trains the weights and the other half only measures them
import fs from 'fs';
import readline from 'readline';
import { replay, tune, collectPatterns, outcome, syntheticRecords, TUNABLE } from './riskEvaluation.js';
import { localHour } from '../utils/geo.js';
import { RISK_WEIGHTS, APPROVAL_THRESHOLD, HISTORY_SIZE } from '../config/risk.js';

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : Number(args[i + 1]);
};
const input = args.includes('--synthetic')
  ? '--synthetic'
  : args.find((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')));
if (!input) {
  console.error('Usage: npm run evaluate:risk -- --synthetic | <rba-dataset.csv | -> [--sample N] [--history N] [--budget X] [--keep-users FILE] [--ignore-device]');
  process.exit(1);
}
const sample = flag('sample', 20);
const historySize = flag('history', HISTORY_SIZE);
const budget = flag('budget', 0.02);
const keepIndex = args.indexOf('--keep-users');
const keepUsers = new Set(
  keepIndex === -1 ? [] : fs.readFileSync(args[keepIndex + 1], 'utf8').split('\n').map((l) => l.trim().split(/\s+/).pop()).filter(Boolean)
);

const hash = (text) => {
  let h = 5381;
  for (let i = 0; i < text.length; i++) h = ((h << 5) + h + text.charCodeAt(i)) | 0;
  return h >>> 0;
};
const split = (user) => ((hash(String(user)) >>> 8) % 2 === 0 ? 'train' : 'test');

const splitCsvLine = (line) => {
  const cells = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (quoted && line[i + 1] === '"') cell += line[i++];
      else quoted = !quoted;
    } else if (c === ',' && !quoted) {
      cells.push(cell);
      cell = '';
    } else cell += c;
  }
  cells.push(cell);
  return cells;
};

const unversioned = (text) => (text || '').replace(/[\s\d._-]+$/, '').toLowerCase();

// Equal strings and objects are shared between rows; a slice of a line would
// otherwise keep the whole line alive.
const interned = new Map();
const intern = (value) => {
  let shared = interned.get(value);
  if (shared === undefined) {
    shared = value;
    interned.set(value, shared);
  }
  return shared;
};

const geos = new Map();
const sharedGeo = ([country, region, city]) => {
  const key = `${country}|${region}|${city}`;
  if (!geos.has(key)) geos.set(key, { country, region, city });
  return geos.get(key);
};

const readCsv = async (source) => {
  const records = [];
  const seen = { rows: 0, sampled: 0, skipped: 0, outOfOrder: 0 };
  let header;
  let col;
  let last = 0;

  for await (const line of readline.createInterface({ input: source, crlfDelay: Infinity })) {
    if (!line) continue;
    if (!header) {
      header = splitCsvLine(line).map((name) => name.trim().toLowerCase());
      col = (name) => header.indexOf(name);
      if (header[2] !== 'user id') throw new Error('Unexpected CSV layout: user id should be the third column');
      continue;
    }
    seen.rows++;
    // The user id is the third column; read it without parsing the rest of the row.
    const c2 = line.indexOf(',', line.indexOf(',') + 1);
    const user = line.slice(c2 + 1, line.indexOf(',', c2 + 1));
    if (hash(user) % sample !== 0 && !keepUsers.has(user)) continue;
    seen.sampled++;
    const cells = splitCsvLine(line);

    const get = (name) => cells[col(name)];
    const attack = get('is account takeover') === 'True';
    const successful = get('login successful') === 'True';
    if (!successful || (!attack && get('is attack ip') === 'True')) {
      seen.skipped++;
      continue;
    }
    const time = Date.parse(`${get('login timestamp').replace(' ', 'T')}Z`);
    if (time < last) seen.outOfOrder++;
    last = Math.max(last, time);
    const place = [get('country'), get('region'), get('city')];
    records.push({
      user: intern(cells[2]),
      time,
      ip: intern(get('ip address')),
      geo: sharedGeo(place),
      localHour: localHour(new Date(time), 'Europe/Oslo'),
      device: intern([unversioned(get('browser name and version')), unversioned(get('os name and version')), get('device type')].join('|')),
      attack,
    });
  }
  return { records, seen };
};

const pct = (x) => `${(x * 100).toFixed(2)}%`;
const weightsLine = (w) => TUNABLE.map((id) => `${id}=${w[id]}`).join('  ');

let records;
if (input === '--synthetic') records = syntheticRecords();
else {
  const started = Date.now();
  const { records: read, seen } = await readCsv(input === '-' ? process.stdin : fs.createReadStream(input));
  records = read;
  console.log(
    `Read ${seen.rows.toLocaleString()} rows, kept ${seen.sampled.toLocaleString()} from the 1-in-${sample} user sample ` +
      `(${seen.skipped.toLocaleString()} failed or attack-IP rows dropped) in ${((Date.now() - started) / 1000).toFixed(0)}s`
  );
  if (seen.outOfOrder) console.log(`Warning: ${seen.outOfOrder} rows were out of time order`);
}
records.sort((a, b) => a.time - b.time);

const result = replay(records, { historySize });
console.log(`\n${result.legit.toLocaleString()} legitimate logins, ${result.attacks.toLocaleString()} account takeovers (history size ${historySize})\n`);
console.log('Current weights, production-like replay');
console.log('threshold  legit challenged  takeovers challenged');
for (const row of result.sweep) {
  console.log(`${String(row.threshold).padStart(9)}  ${pct(row.legitChallenged).padStart(16)}  ${pct(row.attacksChallenged).padStart(20)}`);
}
console.log('\nsignal firing rate (legit / takeover)');
for (const id of TUNABLE) {
  console.log(`${id.padEnd(18)} ${pct(result.signals.legit[id] ?? 0).padStart(8)} / ${pct(result.signals.attack[id] ?? 0).padStart(8)}`);
}

const base = args.includes('--ignore-device') ? { ...RISK_WEIGHTS, newDevice: 0 } : RISK_WEIGHTS;
const patterns = collectPatterns(records, { split, historySize });
console.log(`\nTuning newIp, newCountry and oddHour on the train split (budget: at most ${pct(budget)} of legitimate logins challenged, threshold ${APPROVAL_THRESHOLD})`);
const tuned = tune(patterns, { budget, base });
for (const [label, weights] of [['current', base], ['tuned', tuned.weights]]) {
  console.log(`\n${label}: ${weightsLine(weights)}`);
  for (const part of ['train', 'test']) {
    const o = outcome(patterns, weights, APPROVAL_THRESHOLD, part);
    console.log(`  ${part.padEnd(5)} legit challenged ${pct(o.legitChallenged)}  takeovers challenged ${pct(o.attacksChallenged)}  (${o.legit.toLocaleString()} / ${o.attacks.toLocaleString()})`);
  }
}
