import express from 'express';
import { setupTotp, enableTotp, disableTotp } from '../controllers/totpController.js';
import verifyToken, { requireTrustedDevice } from '../middleware/authMiddleware.js';
import { credentialLimiter } from '../middleware/rateLimit.js';
import { totpCodeRules, totpDisableRules } from '../middleware/validate.js';

const router = express.Router();

router.use(verifyToken, requireTrustedDevice, credentialLimiter);

router.post('/setup', setupTotp);
router.post('/enable', totpCodeRules, enableTotp);
router.post('/disable', totpDisableRules, disableTotp);

export default router;
