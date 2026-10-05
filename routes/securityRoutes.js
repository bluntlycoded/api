import express from 'express';
import { recentLogins, auditLog } from '../controllers/securityController.js';
import verifyToken from '../middleware/authMiddleware.js';

const router = express.Router();

router.use(verifyToken);

router.get('/logins', recentLogins);
router.get('/audit', auditLog);

export default router;
