// backend/routes/appRoutes.js

import express from 'express';
import { addapp, getApps, deleteApp,generateOtp } from '../controllers/appController.js';
import verifyToken from '../middleware/authMiddleware.js';
import { body, validationResult } from 'express-validator';

const router = express.Router();

// POST /api/addapp - Add a new app
router.post(
    '/',
    verifyToken,
    [
      body('appName').notEmpty().withMessage('App name is required'),
      body('secretKey').notEmpty().withMessage('Secret key is required'),
    ],
    (req, res, next) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        // Send the first error message
        return res.status(400).json({ message: errors.array()[0].msg });
      }
      next();
    },
    addapp
  );
  
  // GET /api/addapp - Get all apps for the authenticated user
  router.get('/', verifyToken, getApps);
  
  // DELETE /api/addapp/:appId - Delete an app by ID (Optional)
  router.delete('/:appId', verifyToken, deleteApp);
  
  // GET /api/addapp/:appId/otp - Generate OTP for a specific app
  router.get('/:appId/otp', verifyToken, generateOtp);
  
  export default router;