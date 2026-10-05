// Replays login data through the risk scorer and reports, per challenge threshold,
// how many legitimate logins would be challenged (friction) and how many attacker
// logins would be challenged (protection).
//
//   npm run evaluate:risk -- --synthetic
//   npm run evaluate:risk -- path/to/rba-dataset.csv
//
// CSV input follows the public "Login Data Set for Risk-Based Authentication"
// (Wiefling et al., Zenodo 10.5281/zenodo.6782155): rows in time order with the
// columns Login Timestamp, User ID, IP Address, User Agent String, Is Attack IP and
// Is Account Takeover. The dataset has no device id, so the user-agent string stands
// in for the device. It is synthetic data and not for production use.
import fs from 'fs';
import readline from 'readline';
import { replay, syntheticRecords } from './riskEvaluation.js';

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

const readCsv = async (file) => {
  const records = [];
  let header;
  for await (const line of readline.createInterface({ input: fs.createReadStream(file) })) {
    if (!line) continue;
    const cells = splitCsvLine(line);
    if (!header) {
      header = Object.fromEntries(cells.map((name, i) => [name.trim().toLowerCase(), i]));
      continue;
    }
    const get = (name) => cells[header[name]];
    records.push({
      user: get('user id'),
      time: Date.parse(get('login timestamp')),
      ip: get('ip address'),
      device: get('user agent string'),
      attack: get('is attack ip') === 'True' || get('is account takeover') === 'True',
    });
  }
  return records;
};

const arg = process.argv[2];
if (!arg) {
  console.error('Usage: npm run evaluate:risk -- --synthetic | <rba-dataset.csv>');
  process.exit(1);
}

const records = arg === '--synthetic' ? syntheticRecords() : await readCsv(arg);
const result = replay(records);
const pct = (x) => `${(x * 100).toFixed(1)}%`;

console.log(`${result.legit} legitimate and ${result.attacks} attack logins\n`);
console.log('threshold  legit challenged  attacks challenged');
for (const row of result.sweep) {
  console.log(`${String(row.threshold).padStart(9)}  ${pct(row.legitChallenged).padStart(16)}  ${pct(row.attacksChallenged).padStart(18)}`);
}
console.log('\nsignal firing rate (legit / attack)');
for (const id of Object.keys(result.weights)) {
  console.log(`${id.padEnd(20)} ${pct(result.signals.legit[id] ?? 0).padStart(6)} / ${pct(result.signals.attack[id] ?? 0).padStart(6)}`);
}
