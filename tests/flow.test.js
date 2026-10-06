import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import { io as connect } from 'socket.io-client';
import { authenticator } from 'otplib';
import { useTestDb } from './helpers/testDb.js';

useTestDb();
const { default: createApp } = await import('../app.js');
const { initRealtime } = await import('../services/realtime.js');

const INDIA = '103.21.58.1';
const INDIA_2 = '49.36.0.1';
const UK = '81.2.69.142';
const DEVICE_A = 'a'.repeat(32);
const DEVICE_B = 'b'.repeat(32);
const PASSWORD = 'correct1horse';

let server;
let base;

before(async () => {
  server = http.createServer(createApp());
  initRealtime(server);
  await new Promise((resolve) => server.listen(0, resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

const call = async (method, path, { body, token, ip = INDIA } = {}) => {
  const res = await fetch(base + path, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-forwarded-for': ip,
      ...(token && { authorization: `Bearer ${token}` }),
    },
    body: body && JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
};

let counter = 0;
const newUser = async () => {
  const email = `user${++counter}@example.com`;
  const res = await call('POST', '/api/auth/register', {
    body: { name: 'Test', email, password: PASSWORD, deviceId: DEVICE_A, deviceName: 'Phone A' },
  });
  assert.equal(res.status, 201);
  return { email, token: res.body.token };
};

const login = (email, extra = {}, ip = INDIA) =>
  call('POST', '/api/auth/login', { ip, body: { email, password: PASSWORD, deviceId: DEVICE_A, ...extra } });

test('register makes the first device trusted and login from it is not challenged', async () => {
  const { email, token } = await newUser();
  const devices = await call('GET', '/api/devices', { token });
  assert.equal(devices.body.length, 1);
  assert.equal(devices.body[0].trusted, true);
  assert.equal(devices.body[0].current, true);

  const again = await login(email, {}, INDIA_2);
  assert.equal(again.status, 200);
  assert.ok(again.body.token);
});

test('duplicate email and wrong password are rejected', async () => {
  const { email } = await newUser();
  const dup = await call('POST', '/api/auth/register', {
    body: { name: 'T', email, password: PASSWORD, deviceId: DEVICE_A },
  });
  assert.equal(dup.status, 400);
  const bad = await call('POST', '/api/auth/login', { body: { email, password: 'wrong', deviceId: DEVICE_A } });
  assert.equal(bad.status, 400);
});

test('new device: challenge, number matching, wrong pick, approve, complete', async () => {
  const { email, token: tokenA } = await newUser();

  const attempt = await login(email, { deviceId: DEVICE_B, deviceName: 'Phone B' });
  assert.equal(attempt.status, 202);
  const { challengeId, pollSecret, displayNumber } = attempt.body;

  const pending = await call('GET', '/api/approval/pending', { token: tokenA });
  assert.equal(pending.body.length, 1);
  const view = pending.body[0];
  assert.equal(view.id, challengeId);
  assert.equal(view.deviceName, 'Phone B');
  assert.ok(view.reasons.some((r) => /not trusted/.test(r)));
  assert.ok(view.options.includes(displayNumber));
  assert.equal('number' in view, false, 'the number must never reach the approving device');

  const status = () => call('POST', `/api/approval/${challengeId}/status`, { body: { pollSecret } });
  assert.equal((await status()).body.status, 'pending');
  assert.equal((await status().then(() => call('POST', `/api/approval/${challengeId}/status`, { body: { pollSecret: 'f'.repeat(64) } }))).status, 404);

  const decoy = view.options.find((n) => n !== displayNumber);
  const wrong = await call('POST', `/api/approval/${challengeId}/respond`, { token: tokenA, body: { action: 'approve', choice: decoy } });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.attemptsLeft, 1);

  const early = await call('POST', '/api/auth/login/complete', { body: { challengeId, pollSecret, deviceId: DEVICE_B } });
  assert.equal(early.status, 403, 'cannot complete before approval');

  const ok = await call('POST', `/api/approval/${challengeId}/respond`, { token: tokenA, body: { action: 'approve', choice: displayNumber } });
  assert.equal(ok.body.status, 'approved');
  assert.equal((await status()).body.status, 'approved');

  const wrongDevice = await call('POST', '/api/auth/login/complete', { body: { challengeId, pollSecret, deviceId: 'c'.repeat(32) } });
  assert.equal(wrongDevice.status, 403, 'bound to the requesting device');

  const done = await call('POST', '/api/auth/login/complete', { body: { challengeId, pollSecret, deviceId: DEVICE_B } });
  assert.equal(done.status, 200);
  const reuse = await call('POST', '/api/auth/login/complete', { body: { challengeId, pollSecret, deviceId: DEVICE_B } });
  assert.equal(reuse.status, 403, 'single use');

  // Device B got a session but was not trusted, so it cannot approve anything.
  const asB = await call('GET', '/api/approval/pending', { token: done.body.token });
  assert.equal(asB.status, 403);
});

test('two wrong numbers cancel the request', async () => {
  const { email, token } = await newUser();
  const { body } = await login(email, { deviceId: DEVICE_B });
  const view = (await call('GET', '/api/approval/pending', { token })).body[0];
  const decoy = view.options.find((n) => n !== body.displayNumber);
  const respond = (choice) => call('POST', `/api/approval/${body.challengeId}/respond`, { token, body: { action: 'approve', choice } });
  assert.equal((await respond(decoy)).status, 400);
  const second = await respond(decoy);
  assert.equal(second.status, 403);
  assert.equal(second.body.status, 'denied');
  const status = await call('POST', `/api/approval/${body.challengeId}/status`, { body: { pollSecret: body.pollSecret } });
  assert.equal(status.body.status, 'denied');
});

test('deny, and a device cannot approve its own login', async () => {
  const { email, token } = await newUser();
  const { body } = await login(email, { deviceId: DEVICE_B });
  const deny = await call('POST', `/api/approval/${body.challengeId}/respond`, { token, body: { action: 'deny' } });
  assert.equal(deny.body.status, 'denied');
  const again = await call('POST', `/api/approval/${body.challengeId}/respond`, { token, body: { action: 'deny' } });
  assert.equal(again.status, 404);
});

test('impossible travel forces approval even on a trusted device', async () => {
  const { email } = await newUser();
  const first = await login(email, {}, INDIA);
  assert.equal(first.status, 200);
  const second = await login(email, {}, UK);
  assert.equal(second.status, 202);
  const history = await call('GET', '/api/security/logins', { token: first.body.token });
  const challenged = history.body.find((e) => e.outcome === 'challenged');
  assert.ok(challenged.reasons.some((r) => /km/.test(r)), JSON.stringify(challenged));
  assert.ok(challenged.riskScore >= 60);
});

test('approval requests are rate limited per user', async () => {
  const { email } = await newUser();
  const statuses = [];
  for (let i = 0; i < 4; i++) statuses.push((await login(email, { deviceId: `${i}`.repeat(32) })).status);
  assert.deepEqual(statuses, [202, 202, 202, 429]);
});

test('"not me" blocks the IP, locks the account, and a password reset unlocks it', async () => {
  const { email, token } = await newUser();
  const attacker = '8.8.8.8';
  const { body } = await call('POST', '/api/auth/login', {
    ip: attacker,
    body: { email, password: PASSWORD, deviceId: DEVICE_B },
  });
  const report = await call('POST', `/api/approval/${body.challengeId}/report`, { token });
  assert.equal(report.status, 200);

  const blocked = await call('POST', '/api/auth/login', { ip: attacker, body: { email, password: PASSWORD, deviceId: DEVICE_A } });
  assert.equal(blocked.body.code, 'IP_BLOCKED');
  const locked = await login(email);
  assert.equal(locked.status, 423);

  const logs = [];
  const original = console.log;
  console.log = (...args) => logs.push(args.join(' '));
  await call('POST', '/api/auth/forgot-password', { body: { email } });
  console.log = original;
  const resetToken = logs.join('\n').match(/[0-9a-f]{64}/)[0];

  const reset = await call('POST', '/api/auth/reset-password', { body: { token: resetToken, password: 'newpass99x' } });
  assert.equal(reset.status, 200);
  const reuse = await call('POST', '/api/auth/reset-password', { body: { token: resetToken, password: 'another99x' } });
  assert.equal(reuse.status, 400);

  const unlocked = await call('POST', '/api/auth/login', { body: { email, password: 'newpass99x', deviceId: DEVICE_A } });
  assert.equal(unlocked.status, 200);

  const audit = await call('GET', '/api/security/audit', { token: unlocked.body.token });
  const types = audit.body.map((e) => e.type);
  assert.ok(types.includes('login_reported') && types.includes('password_reset'));
});

test('forgot-password gives the same answer for unknown emails', async () => {
  const known = await newUser();
  const a = await call('POST', '/api/auth/forgot-password', { body: { email: known.email } });
  const b = await call('POST', '/api/auth/forgot-password', { body: { email: 'nobody@example.com' } });
  assert.equal(a.status, b.status);
  assert.deepEqual(a.body, b.body);
});

test('two-factor: setup, enable, required at login, codes cannot be reused', async () => {
  const { email, token } = await newUser();
  const setup = await call('POST', '/api/totp/setup', { token });
  assert.equal(setup.status, 200);
  assert.match(setup.body.qrCode, /^data:image\/png/);
  const { secret } = setup.body;

  const bad = await call('POST', '/api/totp/enable', { token, body: { token: '000000' === authenticator.generate(secret) ? '111111' : '000000' } });
  assert.equal(bad.status, 400);
  const enabled = await call('POST', '/api/totp/enable', { token, body: { token: authenticator.generate(secret) } });
  assert.equal(enabled.status, 200);

  const missing = await login(email);
  assert.equal(missing.body.code, 'TOTP_REQUIRED');

  // The code used to enable is spent; a code from the next step still works once.
  const spent = await login(email, { totp: authenticator.generate(secret) });
  assert.equal(spent.body.code, 'TOTP_INVALID');
  const next = authenticator.clone({ epoch: Date.now() + 30000 }).generate(secret);
  const ok = await login(email, { totp: next });
  assert.equal(ok.status, 200);
  const replay = await login(email, { totp: next });
  assert.equal(replay.body.code, 'TOTP_INVALID');

  const wrongPassword = await call('POST', '/api/totp/disable', {
    token,
    body: { password: 'not-it', token: authenticator.clone({ epoch: Date.now() + 30000 }).generate(secret) },
  });
  assert.equal(wrongPassword.status, 400);
});

test('two-factor can be disabled with the password and a fresh code', async () => {
  const { email, token } = await newUser();
  const { body } = await call('POST', '/api/totp/setup', { token });
  await call('POST', '/api/totp/enable', { token, body: { token: authenticator.generate(body.secret) } });

  const next = authenticator.clone({ epoch: Date.now() + 30000 }).generate(body.secret);
  const off = await call('POST', '/api/totp/disable', { token, body: { password: PASSWORD, token: next } });
  assert.equal(off.status, 200);
  assert.equal((await login(email)).status, 200, 'no code needed any more');
});

test('repeated failures lock logins out and escalate risk', async () => {
  const { email } = await newUser();
  for (let i = 0; i < 10; i++) {
    await call('POST', '/api/auth/login', { body: { email, password: 'wrong', deviceId: DEVICE_A } });
  }
  const locked = await login(email);
  assert.equal(locked.status, 429);
});

test('authenticator entries: fields, search, edit, reorder, delete, other users are isolated', async () => {
  const { token } = await newUser();
  const other = await newUser();
  const secret = 'JBSWY3DPEHPK3PXP';

  const gh = await call('POST', '/api/addapp', { token, body: { appName: 'GitHub', secretKey: secret, issuer: 'GitHub', folder: 'Work', digits: 8, algorithm: 'SHA256' } });
  assert.equal(gh.status, 200);
  assert.equal(gh.body.secretKey, secret, 'the app needs the secret back to generate codes locally');
  assert.equal(gh.body._id, gh.body.id);
  const aws = await call('POST', '/api/addapp', { token, body: { appName: 'AWS', secretKey: 'KRSXG5CTMVRXEZLUKRSXG5CT', favorite: true } });
  assert.equal((await call('POST', '/api/addapp', { token, body: { appName: 'x', secretKey: 'short' } })).status, 400);

  const list = await call('GET', '/api/addapp', { token });
  assert.deepEqual(list.body.map((a) => a.appName), ['AWS', 'GitHub'], 'favorites first');
  assert.equal((await call('GET', '/api/addapp?q=git', { token })).body.length, 1);
  assert.equal((await call('GET', '/api/addapp?folder=Work', { token })).body[0].appName, 'GitHub');
  assert.equal((await call('GET', '/api/addapp?favorite=true', { token })).body[0].appName, 'AWS');

  const edit = await call('PATCH', `/api/addapp/${gh.body.id}`, { token, body: { appName: 'GitHub Inc', favorite: true } });
  assert.equal(edit.body.appName, 'GitHub Inc');
  assert.equal(edit.body.secretKey, secret);

  await call('PUT', '/api/addapp/order', { token, body: { ids: [gh.body.id, aws.body.id] } });
  assert.deepEqual((await call('GET', '/api/addapp', { token })).body.map((a) => a.appName), ['GitHub Inc', 'AWS']);

  const otp = await call('GET', `/api/addapp/${gh.body.id}/otp`, { token });
  assert.equal(otp.body.otp.length, 8);
  assert.ok(otp.body.expiresInSeconds > 0 && otp.body.expiresInSeconds <= 30);

  assert.equal((await call('GET', `/api/addapp/${gh.body.id}/otp`, { token: other.token })).status, 404);
  assert.equal((await call('DELETE', `/api/addapp/${gh.body.id}`, { token: other.token })).status, 404);
  assert.equal((await call('DELETE', `/api/addapp/${gh.body.id}`, { token })).status, 200);
  assert.equal((await call('GET', '/api/addapp', { token })).body.length, 1);
});

test('HOTP entries advance their counter on every code', async () => {
  const { token } = await newUser();
  const { body: entry } = await call('POST', '/api/addapp', { token, body: { appName: 'Bank', secretKey: 'JBSWY3DPEHPK3PXP', type: 'hotp' } });
  const first = await call('GET', `/api/addapp/${entry.id}/otp`, { token });
  const second = await call('GET', `/api/addapp/${entry.id}/otp`, { token });
  assert.equal(first.body.counter, 0);
  assert.equal(second.body.counter, 1);
  assert.notEqual(first.body.otp, second.body.otp);
  assert.equal((await call('GET', '/api/addapp', { token })).body[0].counter, 2);
});

test('secrets are encrypted in the database', async () => {
  const { token } = await newUser();
  await call('POST', '/api/addapp', { token, body: { appName: 'Raw', secretKey: 'JBSWY3DPEHPK3PXP' } });
  const { query } = await import('../lib/db.js');
  const { rows } = await query('select secret_key from user_apps');
  assert.ok(rows.every((r) => r.secret_key.startsWith('enc:v1:')));
  assert.ok(rows.every((r) => !r.secret_key.includes('JBSWY3DPEHPK3PXP')));
});

test('import (otpauth, Aegis) and password-protected export', async () => {
  const { token } = await newUser();
  const uris = [
    'otpauth://totp/GitHub:me%40x.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&algorithm=SHA256',
    'otpauth://hotp/Bank:me?secret=KRSXG5CTMVRXEZLUKRSXG5CT&counter=5',
    'not a uri',
  ].join('\n');
  const imp = await call('POST', '/api/addapp/import', { token, body: { data: uris } });
  assert.deepEqual(imp.body, { imported: 2, skipped: 1 });

  const aegis = { db: { entries: [{ type: 'totp', name: 'me', issuer: 'Reddit', info: { secret: 'JBSWY3DPEHPK3PXPJBSWY3DP', algo: 'SHA1', digits: 6, period: 30 } }] } };
  assert.equal((await call('POST', '/api/addapp/import', { token, body: { data: aegis } })).body.imported, 1);
  assert.equal((await call('POST', '/api/addapp/import', { token, body: { data: { header: { slots: [] }, db: 'encrypted' } } })).status, 400);

  const list = (await call('GET', '/api/addapp', { token })).body;
  const github = list.find((a) => a.appName === 'GitHub');
  assert.equal(github.digits, 8);
  assert.equal(github.algorithm, 'SHA256');
  assert.equal(github.account, 'me@x.com');
  assert.equal(list.find((a) => a.appName === 'Bank').counter, 5);

  assert.equal((await call('POST', '/api/addapp/export', { token, body: { password: 'nope' } })).status, 403);
  const exp = await call('POST', '/api/addapp/export', { token, body: { password: PASSWORD } });
  assert.equal(exp.body.uris.length, 3);
  assert.ok(exp.body.uris.some((u) => u.startsWith('otpauth://hotp/') && u.includes('counter=5')));
});

test('encrypted vault: first upload, version conflicts, delete, device rules', async () => {
  const { email, token } = await newUser();
  assert.equal((await call('GET', '/api/vault', { token })).status, 404);

  const put = (ciphertext, version, t = token) => call('PUT', '/api/vault', { token: t, body: { ciphertext, version } });
  assert.equal((await put('AAAA', 0)).body.version, 1);
  assert.equal((await put('BBBB', 0)).status, 409, 'creating twice conflicts');
  assert.equal((await put('CCCC', 1)).body.version, 2);
  const stale = await put('DDDD', 1);
  assert.equal(stale.status, 409);
  assert.equal(stale.body.currentVersion, 2);
  assert.equal((await call('GET', '/api/vault', { token })).body.ciphertext, 'CCCC');
  assert.equal((await put('not base64!', 2)).status, 400);

  // An untrusted session can read the backup (to restore) but not change it.
  const attempt = await login(email, { deviceId: DEVICE_B });
  const view = (await call('GET', '/api/approval/pending', { token })).body[0];
  await call('POST', `/api/approval/${attempt.body.challengeId}/respond`, { token, body: { action: 'approve', choice: attempt.body.displayNumber } });
  const asB = await call('POST', '/api/auth/login/complete', { body: { challengeId: view.id, pollSecret: attempt.body.pollSecret, deviceId: DEVICE_B } });
  assert.equal((await call('GET', '/api/vault', { token: asB.body.token })).status, 200);
  assert.equal((await put('EEEE', 2, asB.body.token)).status, 403);

  assert.equal((await call('DELETE', '/api/vault', { token })).status, 200);
  assert.equal((await call('GET', '/api/vault', { token })).status, 404);
});

test('trusting a device on approval, and revoking it', async () => {
  const { email, token } = await newUser();
  const attempt = await login(email, { deviceId: DEVICE_B, deviceName: 'Tablet' });
  await call('POST', `/api/approval/${attempt.body.challengeId}/respond`, {
    token,
    body: { action: 'approve', choice: attempt.body.displayNumber, trustDevice: true },
  });
  const done = await call('POST', '/api/auth/login/complete', {
    body: { challengeId: attempt.body.challengeId, pollSecret: attempt.body.pollSecret, deviceId: DEVICE_B },
  });
  const devices = await call('GET', '/api/devices', { token });
  const tablet = devices.body.find((d) => d.name === 'Tablet');
  assert.equal(tablet.trusted, true);
  assert.equal((await call('GET', '/api/approval/pending', { token: done.body.token })).status, 200);

  assert.equal((await call('DELETE', `/api/devices/${tablet.id}`, { token })).status, 200);
  assert.equal((await call('GET', '/api/approval/pending', { token: done.body.token })).status, 403);
  assert.equal((await login(email, { deviceId: DEVICE_B })).status, 202, 'revoked device is new again');
});

test('passkey endpoints: options are issued, bad responses are rejected', async () => {
  const { token } = await newUser();
  const reg = await call('POST', '/api/passkeys/options', { token });
  assert.equal(reg.status, 200);
  assert.equal(reg.body.options.rp.id, 'localhost');
  assert.equal(reg.body.options.authenticatorSelection.userVerification, 'required');

  const forged = await call('POST', '/api/passkeys/verify', { token, body: { challengeId: reg.body.challengeId, response: { id: 'x' } } });
  assert.equal(forged.status, 400);
  const reused = await call('POST', '/api/passkeys/verify', { token, body: { challengeId: reg.body.challengeId, response: { id: 'x' } } });
  assert.equal(reused.status, 400, 'challenge is single use');

  const opts = await call('POST', '/api/auth/passkey/options', { body: {} });
  assert.equal(opts.status, 200);
  const unknown = await call('POST', '/api/auth/passkey/verify', {
    body: { challengeId: opts.body.challengeId, response: { id: 'nope' }, deviceId: DEVICE_A },
  });
  assert.equal(unknown.status, 401);
  assert.equal((await call('GET', '/api/passkeys', { token })).body.length, 0);
});

test('realtime: trusted device is pushed the request, login screen is told the result', async () => {
  const { email, token } = await newUser();
  const url = base;
  const approver = connect(url, { transports: ['websocket'] });
  const screen = connect(url, { transports: ['websocket'] });
  const emit = (socket, event, payload) => new Promise((resolve) => socket.emit(event, payload, resolve));

  try {
    assert.deepEqual(await emit(approver, 'authenticate', { token }), { ok: true });
    assert.deepEqual(await emit(approver, 'authenticate', { token: 'junk' }), { ok: false });

    const pushed = new Promise((resolve) => approver.once('approval_request', resolve));
    const attempt = await login(email, { deviceId: DEVICE_B });
    const request = await pushed;
    assert.equal(request.id, attempt.body.challengeId);
    assert.equal('number' in request, false);

    assert.equal((await emit(screen, 'watch', { challengeId: attempt.body.challengeId, pollSecret: 'f'.repeat(64) })).ok, false);
    const watched = await emit(screen, 'watch', { challengeId: attempt.body.challengeId, pollSecret: attempt.body.pollSecret });
    assert.deepEqual(watched, { ok: true, status: 'pending' });

    const resolved = new Promise((resolve) => screen.once('approval_resolved', resolve));
    const closed = new Promise((resolve) => approver.once('approval_closed', resolve));
    await call('POST', `/api/approval/${request.id}/respond`, { token, body: { action: 'approve', choice: attempt.body.displayNumber } });
    assert.deepEqual(await resolved, { status: 'approved' });
    assert.equal((await closed).id, request.id);
  } finally {
    approver.close();
    screen.close();
  }
});

const registerFull = async () => {
  const email = `user${++counter}@example.com`;
  const res = await call('POST', '/api/auth/register', {
    body: { name: 'Test', email, password: PASSWORD, deviceId: DEVICE_A, deviceName: 'Phone A' },
  });
  return { email, ...res.body };
};

test('sessions: access token is short-lived and refresh tokens rotate', async () => {
  const first = await registerFull();
  assert.equal(first.expiresInSeconds, 900);
  assert.match(first.refreshToken, /^[0-9a-f]{64}$/);

  const second = await call('POST', '/api/auth/refresh', { body: { refreshToken: first.refreshToken } });
  assert.equal(second.status, 200);
  assert.notEqual(second.body.refreshToken, first.refreshToken);
  assert.equal((await call('GET', '/api/devices', { token: second.body.token })).status, 200);

  const third = await call('POST', '/api/auth/refresh', { body: { refreshToken: second.body.refreshToken } });
  assert.equal(third.status, 200);
});

test('sessions: reusing a refresh token revokes the whole family', async () => {
  const { email, refreshToken } = await registerFull();
  const rotated = await call('POST', '/api/auth/refresh', { body: { refreshToken } });
  assert.equal(rotated.status, 200);

  const replay = await call('POST', '/api/auth/refresh', { body: { refreshToken } });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.code, 'REFRESH_INVALID');

  const afterTheft = await call('POST', '/api/auth/refresh', { body: { refreshToken: rotated.body.refreshToken } });
  assert.equal(afterTheft.status, 401, 'the rotated token died with its family');

  const fresh = await login(email);
  const audit = await call('GET', '/api/security/audit', { token: fresh.body.token });
  assert.ok(audit.body.some((e) => e.type === 'refresh_token_reuse'));
});

test('sessions: logout ends one login, logout-all ends every login', async () => {
  const a = await registerFull();
  const b = await login(a.email, {}, INDIA_2);
  assert.equal((await call('POST', '/api/auth/logout', { body: { refreshToken: a.refreshToken } })).status, 200);
  assert.equal((await call('POST', '/api/auth/refresh', { body: { refreshToken: a.refreshToken } })).status, 401);
  assert.equal((await call('POST', '/api/auth/refresh', { body: { refreshToken: 'f'.repeat(64) } })).status, 401);

  assert.equal((await call('POST', '/api/auth/logout-all', { token: b.body.token })).status, 200);
  assert.equal((await call('POST', '/api/auth/refresh', { body: { refreshToken: b.body.refreshToken } })).status, 401);
});

test('sessions: revoking a device or resetting the password ends its refresh tokens', async () => {
  const { email, token } = await registerFull();
  const attempt = await login(email, { deviceId: DEVICE_B });
  await call('POST', `/api/approval/${attempt.body.challengeId}/respond`, {
    token,
    body: { action: 'approve', choice: attempt.body.displayNumber, trustDevice: true },
  });
  const onB = await call('POST', '/api/auth/login/complete', {
    body: { challengeId: attempt.body.challengeId, pollSecret: attempt.body.pollSecret, deviceId: DEVICE_B },
  });
  assert.ok(onB.body.refreshToken);

  const devices = await call('GET', '/api/devices', { token });
  const b = devices.body.find((d) => !d.current);
  await call('DELETE', `/api/devices/${b.id}`, { token });
  assert.equal((await call('POST', '/api/auth/refresh', { body: { refreshToken: onB.body.refreshToken } })).status, 401);

  const again = await login(email);
  const logs = [];
  const original = console.log;
  console.log = (...args) => logs.push(args.join(' '));
  await call('POST', '/api/auth/forgot-password', { body: { email } });
  console.log = original;
  const resetToken = logs.join('\n').match(/[0-9a-f]{64}/)[0];
  await call('POST', '/api/auth/reset-password', { body: { token: resetToken, password: 'newpass99x' } });
  assert.equal((await call('POST', '/api/auth/refresh', { body: { refreshToken: again.body.refreshToken } })).status, 401);
});

test('recovery codes: generate needs the password and a trusted device, codes are single use', async () => {
  const { email, token } = await registerFull();
  assert.equal((await call('POST', '/api/recovery', { token, body: { password: 'wrong' } })).status, 403);

  const gen = await call('POST', '/api/recovery', { token, body: { password: PASSWORD } });
  assert.equal(gen.status, 200);
  assert.equal(gen.body.codes.length, 10);
  assert.ok(gen.body.codes.every((c) => /^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){2}$/.test(c)));
  assert.equal(new Set(gen.body.codes).size, 10);
  assert.equal((await call('GET', '/api/recovery', { token })).body.remaining, 10);

  const { query } = await import('../lib/db.js');
  const { rows } = await query('select code_hash from recovery_codes');
  assert.ok(rows.every((r) => !gen.body.codes.some((c) => r.code_hash.includes(c.replace(/-/g, '')))), 'only hashes are stored');

  const recoverWith = (code, deviceId = DEVICE_B) =>
    call('POST', '/api/auth/recover', { body: { email, password: PASSWORD, recoveryCode: code, deviceId, deviceName: 'New phone' } });

  const ok = await recoverWith(gen.body.codes[0].toLowerCase().replace(/-/g, ' '));
  assert.equal(ok.status, 200, 'case, spaces and dashes do not matter');
  assert.equal(ok.body.remainingCodes, 9);
  assert.equal((await recoverWith(gen.body.codes[0])).body.code, 'RECOVERY_INVALID', 'single use');
  assert.equal((await recoverWith('AAAA-BBBB-CCCC')).status, 401);

  // The recovering device is trusted; the old one lost trust and its sessions.
  assert.equal((await call('GET', '/api/approval/pending', { token: ok.body.token })).status, 200);
  assert.equal((await call('GET', '/api/approval/pending', { token })).status, 403);
  assert.equal((await call('POST', '/api/auth/refresh', { body: { refreshToken: ok.body.refreshToken } })).status, 200);

  const audit = await call('GET', '/api/security/audit', { token: ok.body.token });
  assert.ok(audit.body.some((e) => e.type === 'recovery_used'));

  const wrongPassword = await call('POST', '/api/auth/recover', {
    body: { email, password: 'nope', recoveryCode: gen.body.codes[1], deviceId: DEVICE_B },
  });
  assert.equal(wrongPassword.status, 400);
});

test('recovery codes: regenerating invalidates the old set, and a locked account cannot recover', async () => {
  const { email, token } = await registerFull();
  const first = await call('POST', '/api/recovery', { token, body: { password: PASSWORD } });
  const second = await call('POST', '/api/recovery', { token, body: { password: PASSWORD } });
  const body = (code) => ({ email, password: PASSWORD, recoveryCode: code, deviceId: DEVICE_B });
  assert.equal((await call('POST', '/api/auth/recover', { body: body(first.body.codes[0]) })).status, 401);

  const attempt = await login(email, { deviceId: 'd'.repeat(32) }, '24.24.24.24');
  await call('POST', `/api/approval/${attempt.body.challengeId}/report`, { token });
  const locked = await call('POST', '/api/auth/recover', { body: body(second.body.codes[0]) });
  assert.equal(locked.status, 423);
});
