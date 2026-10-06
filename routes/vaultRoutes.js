import express from 'express';
import { getVault, putVault, deleteVault } from '../controllers/vaultController.js';
import verifyToken, { requireTrustedDevice } from '../middleware/authMiddleware.js';
import { vaultRules } from '../middleware/validate.js';

const router = express.Router();

router.use(verifyToken);

// Reading is open to any signed-in device so a new phone can restore; the blob is encrypted.
router.get('/', getVault);
router.put('/', requireTrustedDevice, vaultRules, putVault);
router.delete('/', requireTrustedDevice, deleteVault);

export default router;
