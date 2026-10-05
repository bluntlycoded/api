import test from 'node:test';
import assert from 'node:assert/strict';

const { default: User } = await import('../models/userModel.js');

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DP';
const build = () => new User({ name: 'A', email: 'A@Example.com ', password: 'hash', apps: [{ appName: 'GitHub', secretKey: SECRET }] });

test('app secrets are encrypted in the stored document', () => {
  const stored = build().toObject().apps[0].secretKey;
  assert.ok(stored.startsWith('enc:v1:'));
  assert.ok(!stored.includes(SECRET));
});

test('app secrets read back as plaintext and serialize for the API', () => {
  const user = build();
  assert.equal(user.apps[0].secretKey, SECRET);
  const json = JSON.parse(JSON.stringify(user.apps));
  assert.equal(json[0].secretKey, SECRET);
  assert.equal(json[0].appName, 'GitHub');
  assert.ok(json[0]._id);
  assert.equal('id' in json[0], false);
});

test('email is normalized and the model validates', () => {
  const user = build();
  assert.equal(user.email, 'a@example.com');
  assert.equal(user.validateSync(), undefined);
});

test('password and 2FA fields are excluded from queries by default', () => {
  for (const field of ['password', 'totpSecret', 'totpLastStep', 'resetTokenHash', 'resetTokenExpires']) {
    assert.equal(User.schema.path(field).options.select, false, field);
  }
});
