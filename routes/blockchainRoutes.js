import express from 'express';
import { createWallet, checkBalance } from '../controllers/blockchainController.js';
import verifyToken from '../middleware/authMiddleware.js';
import { balanceRules } from '../middleware/validate.js';

const router = express.Router();

router.use(verifyToken);

router.post('/create-wallet', createWallet);
router.post('/check-balance', balanceRules, checkBalance);

export default router;
