import Device from '../models/deviceModel.js';
import { audit } from '../services/auditService.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const listDevices = asyncHandler(async (req, res) => {
  const devices = await Device.find({ userId: req.user.userId }).sort({ lastSeen: -1 }).lean();
  res.status(200).json(
    devices.map((d) => ({
      id: d._id,
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
  const removed = await Device.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
  if (!removed) throw new HttpError(404, 'Device not found');
  await audit(req.user.userId, 'device_revoked', req.ip, { name: removed.name });
  res.status(200).json({ message: 'Device revoked' });
});

export { listDevices, revokeDevice };
