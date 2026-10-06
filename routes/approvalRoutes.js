import express from 'express';
import { listPending, respond, report, pollStatus } from '../controllers/approvalController.js';
import verifyToken, { requireTrustedDevice } from '../middleware/authMiddleware.js';
import { approvalRespondRules, approvalStatusRules, reportRules } from '../middleware/validate.js';

const router = express.Router();

// Login screen: authenticated by the poll secret from the login response.
router.post('/:id/status', approvalStatusRules, pollStatus);

// Approver: a logged-in, trusted device.
router.use(verifyToken, requireTrustedDevice);
router.get('/pending', listPending);
router.post('/:id/respond', approvalRespondRules, respond);
router.post('/:id/report', reportRules, report);

export default router;
