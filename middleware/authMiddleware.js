import { verifyJwt } from '../services/authService.js';
import Device from '../models/deviceModel.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) throw new HttpError(401, 'No token provided. Authorization denied.');
  try {
    req.user = verifyJwt(token);
  } catch {
    throw new HttpError(403, 'Invalid or expired token. Authorization denied.');
  }
  next();
};

// Must run after verifyToken. Only a session from a trusted device (the `did`
// claim is that device's hash) may approve logins or manage security settings.
const requireTrustedDevice = asyncHandler(async (req, res, next) => {
  const { userId, did } = req.user;
  if (!did) throw new HttpError(403, 'This session is not bound to a device. Log in again.');
  const trusted = await Device.exists({ userId, deviceHash: did, trusted: true });
  if (!trusted) throw new HttpError(403, 'This device is not trusted.');
  next();
});

export { requireTrustedDevice };
export default verifyToken;
