import express from 'express';
import { registerUser, loginUser } from '../controllers/authController.js';
import addapp from '../controllers/appController.js';  // Use default import
import verifyToken from '../middleware/authMiddleware.js';


const router = express.Router();

// POST request to register a new user
router.post('/register', registerUser);
router.post('/addapp',verifyToken,addapp);
// POST request to log in a user
router.post('/login', loginUser);

export default router;
