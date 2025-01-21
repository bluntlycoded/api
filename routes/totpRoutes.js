// backend/src/routes/totpRoutes.js

import express from 'express';
import { generateTOTPSecret, verifyTOTP } from '../controllers/totpController.js';

const router = express.Router();

// Route to generate TOTP secret and QR code
router.get('/generate', generateTOTPSecret);

// Route to verify OTP
router.post('/verify', verifyTOTP);

export default router;
