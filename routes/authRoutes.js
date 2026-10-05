import express from 'express';
import {
  registerUser,
  loginUser,
  completeApprovedLogin,
  forgotPassword,
  resetPassword,
} from '../controllers/authController.js';
import { credentialLimiter } from '../middleware/rateLimit.js';
import {
  registerRules,
  loginRules,
  completeLoginRules,
  forgotPasswordRules,
  resetPasswordRules,
} from '../middleware/validate.js';

const router = express.Router();

router.use(credentialLimiter);

router.post('/register', registerRules, registerUser);
router.post('/login', loginRules, loginUser);
router.post('/login/complete', completeLoginRules, completeApprovedLogin);
router.post('/forgot-password', forgotPasswordRules, forgotPassword);
router.post('/reset-password', resetPasswordRules, resetPassword);

export default router;
