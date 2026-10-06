import express from 'express';
import {
  registerUser,
  loginUser,
  completeApprovedLogin,
  forgotPassword,
  resetPassword,
} from '../controllers/authController.js';
import { requirePasskeys, loginOptions, loginVerify } from '../controllers/passkeyController.js';
import { refresh, logout, logoutAll } from '../controllers/sessionController.js';
import { recover } from '../controllers/recoveryController.js';
import verifyToken from '../middleware/authMiddleware.js';
import { credentialLimiter } from '../middleware/rateLimit.js';
import {
  registerRules,
  loginRules,
  completeLoginRules,
  forgotPasswordRules,
  resetPasswordRules,
  passkeyLoginRules,
  refreshRules,
  recoverRules,
} from '../middleware/validate.js';

const router = express.Router();

router.post('/logout-all', verifyToken, logoutAll);

router.use(credentialLimiter);

router.post('/register', registerRules, registerUser);
router.post('/login', loginRules, loginUser);
router.post('/login/complete', completeLoginRules, completeApprovedLogin);
router.post('/passkey/options', requirePasskeys, loginOptions);
router.post('/passkey/verify', requirePasskeys, passkeyLoginRules, loginVerify);
router.post('/refresh', refreshRules, refresh);
router.post('/logout', refreshRules, logout);
router.post('/recover', recoverRules, recover);
router.post('/forgot-password', forgotPasswordRules, forgotPassword);
router.post('/reset-password', resetPasswordRules, resetPassword);

export default router;
