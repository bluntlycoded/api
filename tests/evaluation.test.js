import test from 'node:test';
import assert from 'node:assert/strict';
import { replay, syntheticRecords } from '../scripts/riskEvaluation.js';

test('replay: stable on synthetic data and the sweep is monotonic', () => {
  const records = syntheticRecords({ users: 40, days: 20 });
  const a = replay(records);
  const b = replay(syntheticRecords({ users: 40, days: 20 }));
  assert.deepEqual(a, b, 'seeded runs are repeatable');
  assert.ok(a.legit > 100 && a.attacks > 5);
  for (let i = 1; i < a.sweep.length; i++) {
    assert.ok(a.sweep[i].legitChallenged <= a.sweep[i - 1].legitChallenged);
    assert.ok(a.sweep[i].attacksChallenged <= a.sweep[i - 1].attacksChallenged);
  }
});

test('replay: new-device attackers are challenged and ordinary logins mostly are not', () => {
  const a = replay(syntheticRecords({ users: 40, days: 20 }));
  const atDefault = a.sweep.find((r) => r.threshold === 40);
  assert.ok(atDefault.attacksChallenged > 0.8, `attacks challenged: ${atDefault.attacksChallenged}`);
  assert.ok(atDefault.legitChallenged < 0.1, `legit challenged: ${atDefault.legitChallenged}`);
});
