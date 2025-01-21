// backend/src/routes/dashboardRoutes.js

import express from 'express';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// Protected route example
router.get('/dashboard', protect, (req, res) => {
  res.status(200).json({ message: 'Welcome to your dashboard!' });
});

export default router;
