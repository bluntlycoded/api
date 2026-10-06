import * as devices from '../repositories/deviceRepository.js';
import { revokeForDevice } from '../repositories/refreshTokenRepository.js';
import { audit } from '../services/auditService.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const listDevices = asyncHandler(async (req, res) => {
  const rows = await devices.list(req.user.userId);
  res.status(200).json(
    rows.map((d) => ({
      id: d.id,
      name: d.name,
      trusted: d.trusted,
      firstSeen: d.firstSeen,
      lastSeen: d.lastSeen,
      lastIp: d.lastIp,
      current: d.deviceHash === req.user.did,
    }))
  );
});

// Revokes trust and forgets the device; its next login is treated as a new device.
const revokeDevice = asyncHandler(async (req, res) => {
  const removed = await devices.remove(req.user.userId, req.params.id);
  if (!removed) throw new HttpError(404, 'Device not found');
  await revokeForDevice(req.user.userId, removed.deviceHash);
  await audit(req.user.userId, 'device_revoked', req.ip, { name: removed.name });
  res.status(200).json({ message: 'Device revoked' });
});

export { listDevices, revokeDevice };
