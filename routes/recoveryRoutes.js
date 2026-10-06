import express from 'express';
import { generate, status } from '../controllers/recoveryController.js';
import verifyToken, { requireTrustedDevice } from '../middleware/authMiddleware.js';
import { credentialLimiter } from '../middleware/rateLimit.js';
import { exportRules } from '../middleware/validate.js';

const router = express.Router();

router.use(verifyToken);

router.get('/', status);
router.post('/', requireTrustedDevice, credentialLimiter, exportRules, generate);

export default router;
