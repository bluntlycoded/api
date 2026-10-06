import express from 'express';
import {
  addApp,
  getApps,
  updateApp,
  deleteApp,
  generateOtp,
  syncCounters,
  reorderApps,
  importApps,
  exportApps,
} from '../controllers/appController.js';
import verifyToken, { requireTrustedDevice } from '../middleware/authMiddleware.js';
import {
  addAppRules,
  updateAppRules,
  listAppRules,
  appIdRules,
  reorderRules,
  countersRules,
  importRules,
  exportRules,
} from '../middleware/validate.js';

const router = express.Router();

router.use(verifyToken);

router.post('/', addAppRules, addApp);
router.get('/', listAppRules, getApps);
router.put('/order', reorderRules, reorderApps);
router.put('/counters', countersRules, syncCounters);
router.post('/import', importRules, importApps);
router.post('/export', requireTrustedDevice, exportRules, exportApps);
router.patch('/:appId', updateAppRules, updateApp);
router.delete('/:appId', appIdRules, deleteApp);
router.get('/:appId/otp', appIdRules, generateOtp);

export default router;
