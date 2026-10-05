import express from 'express';
import {
  requirePasskeys,
  registrationOptions,
  registrationVerify,
  listPasskeys,
  removePasskey,
} from '../controllers/passkeyController.js';
import verifyToken, { requireTrustedDevice } from '../middleware/authMiddleware.js';
import { passkeyVerifyRules, deviceIdRules } from '../middleware/validate.js';

const router = express.Router();

router.use(verifyToken, requireTrustedDevice);

router.get('/', listPasskeys);
router.post('/options', requirePasskeys, registrationOptions);
router.post('/verify', requirePasskeys, passkeyVerifyRules, registrationVerify);
router.delete('/:id', deviceIdRules, removePasskey);

export default router;
