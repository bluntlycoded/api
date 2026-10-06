import * as apps from '../repositories/appRepository.js';
import * as users from '../repositories/userRepository.js';
import { generateCode } from '../services/otpService.js';
import { parseImport, toOtpauthUri } from '../services/importService.js';
import { verifyPassword } from '../services/authService.js';
import { audit } from '../services/auditService.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const addApp = asyncHandler(async (req, res) => {
  const b = req.body;
  const created = await apps.insert(req.user.userId, {
    appName: b.appName,
    issuer: b.issuer,
    account: b.account,
    secretKey: b.secretKey,
    type: b.type ?? 'totp',
    algorithm: b.algorithm ?? 'SHA1',
    digits: b.digits ?? 6,
    period: b.period ?? 30,
    counter: b.counter ?? 0,
    folder: b.folder,
    icon: b.icon,
    favorite: b.favorite,
  });
  res.status(200).json(created);
});

const getApps = asyncHandler(async (req, res) => {
  const { q, folder, favorite } = req.query;
  res.status(200).json(await apps.list(req.user.userId, { q, folder, favorite }));
});

const updateApp = asyncHandler(async (req, res) => {
  const updated = await apps.update(req.user.userId, req.params.appId, req.body);
  if (!updated) throw new HttpError(404, 'App not found');
  res.status(200).json(updated);
});

const deleteApp = asyncHandler(async (req, res) => {
  if (!(await apps.remove(req.user.userId, req.params.appId))) throw new HttpError(404, 'App not found');
  res.status(200).json({ message: 'App deleted successfully' });
});

const generateOtp = asyncHandler(async (req, res) => {
  const { userId } = req.user;
  const { appId } = req.params;
  const app = await apps.findOne(userId, appId);
  if (!app) throw new HttpError(404, 'App not found');

  // HOTP codes are single use, so the counter moves forward before the code is made.
  const current = app.type === 'hotp' ? await apps.nextCounter(userId, appId).then((a) => ({ ...a, counter: a.counter - 1 })) : app;
  res.status(200).json(generateCode(current));
});

const syncCounters = asyncHandler(async (req, res) => {
  for (const { id, counter } of req.body.counters) await apps.raiseCounter(req.user.userId, id, counter);
  res.status(200).json({ message: 'Counters synced' });
});

const reorderApps = asyncHandler(async (req, res) => {
  await apps.reorder(req.user.userId, req.body.ids);
  res.status(200).json({ message: 'Order saved' });
});

const importApps = asyncHandler(async (req, res) => {
  let parsed;
  try {
    parsed = parseImport(req.body.data);
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(400, 'Could not read the import data');
  }

  const imported = [];
  for (const entry of parsed.valid) imported.push(await apps.insert(req.user.userId, entry));

  await audit(req.user.userId, 'apps_imported', req.ip, { imported: imported.length, skipped: parsed.skipped });
  res.status(200).json({ imported: imported.length, skipped: parsed.skipped });
});

// Plaintext secrets leave the server here, so it needs the password again.
const exportApps = asyncHandler(async (req, res) => {
  const user = await users.findById(req.user.userId);
  if (!user || !(await verifyPassword(req.body.password, user.passwordHash))) {
    throw new HttpError(403, 'Incorrect password');
  }
  const all = await apps.list(user.id);
  await audit(user.id, 'apps_exported', req.ip, { count: all.length });
  res.status(200).json({ uris: all.map(toOtpauthUri) });
});

export { addApp, getApps, updateApp, deleteApp, generateOtp, syncCounters, reorderApps, importApps, exportApps };
