import express from 'express';
import { addApp, getApps, deleteApp, generateOtp } from '../controllers/appController.js';
import verifyToken from '../middleware/authMiddleware.js';
import { addAppRules, appIdRules } from '../middleware/validate.js';

const router = express.Router();

router.use(verifyToken);

router.post('/', addAppRules, addApp);
router.get('/', getApps);
router.delete('/:appId', appIdRules, deleteApp);
router.get('/:appId/otp', appIdRules, generateOtp);

export default router;
