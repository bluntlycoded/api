import express from 'express';
import { listDevices, revokeDevice } from '../controllers/deviceController.js';
import verifyToken, { requireTrustedDevice } from '../middleware/authMiddleware.js';
import { deviceIdRules } from '../middleware/validate.js';

const router = express.Router();

router.use(verifyToken);

router.get('/', listDevices);
router.delete('/:id', requireTrustedDevice, deviceIdRules, revokeDevice);

export default router;
