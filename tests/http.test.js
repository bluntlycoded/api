import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';

const { default: createApp } = await import('../app.js');

let server;
let base;

before(async () => {
  server = createApp().listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

const post = (path, body) =>
  fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

const deviceId = 'a'.repeat(32);

test('health check', async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: 'ok' });
});

test('unknown routes return 404 JSON', async () => {
  const res = await fetch(`${base}/api/nope`);
  assert.equal(res.status, 404);
});

test('protected routes require a token', async () => {
  for (const path of ['/api/addapp', '/api/devices', '/api/security/logins', '/api/approval/pending']) {
    assert.equal((await fetch(base + path)).status, 401, path);
  }
  const bad = await fetch(`${base}/api/addapp`, { headers: { authorization: 'Bearer nope' } });
  assert.equal(bad.status, 403);
});

test('registration rejects weak passwords, bad email and missing deviceId', async () => {
  const ok = { name: 'A', email: 'a@example.com', password: 'abcdefg1', deviceId };
  assert.equal((await post('/api/auth/register', { ...ok, password: 'short1' })).status, 400);
  assert.equal((await post('/api/auth/register', { ...ok, password: 'onlyletters' })).status, 400);
  assert.equal((await post('/api/auth/register', { ...ok, email: 'nope' })).status, 400);
  assert.equal((await post('/api/auth/register', { ...ok, deviceId: 'short' })).status, 400);
});

test('login rejects malformed input before touching the database', async () => {
  const res = await post('/api/auth/login', { email: 'a@example.com', password: 'x' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).message, /deviceId/);
});

test('reset and completion endpoints validate tokens', async () => {
  assert.equal((await post('/api/auth/reset-password', { token: 'xyz', password: 'abcdefg1' })).status, 400);
  assert.equal(
    (await post('/api/auth/login/complete', { challengeId: 'bad', pollSecret: 'bad', deviceId })).status,
    400
  );
  assert.equal((await post(`/api/approval/${'1'.repeat(24)}/status`, { pollSecret: 'bad' })).status, 400);
});

test('malformed JSON gets a 400, not a stack trace', async () => {
  const res = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{oops',
  });
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { message: 'Invalid JSON body' });
});

test('oversized bodies are refused', async () => {
  const res = await post('/api/auth/login', { email: 'a@example.com', password: 'x'.repeat(20000), deviceId });
  assert.equal(res.status, 413);
});
