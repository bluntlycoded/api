import express from 'express';
import { createWallet, checkBalance } from '../controllers/blockchainController.js';

const router = express.Router();

// POST request to create a new wallet
router.post('/create-wallet', createWallet);

// POST request to check wallet balance
router.post('/check-balance', checkBalance);

export default router;
