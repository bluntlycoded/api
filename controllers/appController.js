// backend/controllers/appController.js

import User from '../models/userModel.js';
import { authenticator } from 'otplib';

// Add a new app
const addapp = async (req, res) => {
  console.log('Received Request Body:', req.body); // Log the request body

  const { appName, secretKey } = req.body;

  if (!appName || !secretKey) {
    console.error('Missing appName or secretKey');
    return res.status(400).json({ message: 'App name and secret key are required' });
  }

  console.log('Authenticated User:', req.user); // Log authenticated user

  const userId = req.user.userId; // Updated to match token payload

  // Validate userId format (MongoDB ObjectId)
  if (!userId || !userId.match(/^[0-9a-fA-F]{24}$/)) {
    console.error('Invalid user ID format:', userId);
    return res.status(400).json({ message: 'Invalid user ID format.' });
  }

  try {
    const user = await User.findById(userId);

    if (!user) {
      console.error('User not found with ID:', userId);
      return res.status(404).json({ message: 'User not found' });
    }

    const newApp = { appName, secretKey };
    user.apps.push(newApp);
    await user.save();

    console.log('New App Added:', newApp);
    res.status(200).json(newApp);
  } catch (err) {
    console.error('Error adding app:', err.message);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
};
//otp generation
const generateOtp = async (req, res) => {
  const userId = req.user.userId;
  const { appId } = req.params;

  if (!userId || !appId) {
    return res.status(400).json({ message: 'User ID and App ID are required.' });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const app = user.apps.id(appId);
    if (!app) {
      return res.status(404).json({ message: 'App not found.' });
    }

    const otp = authenticator.generate(app.secretKey);

    res.status(200).json({ otp });
  } catch (err) {
    console.error('Error generating OTP:', err.message);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
};

// Get all apps for the authenticated user
const getApps = async (req, res) => {
  const userId = req.user.userId; // Access userId from token

  if (!userId || !userId.match(/^[0-9a-fA-F]{24}$/)) {
    console.error('Invalid user ID format:', userId);
    return res.status(400).json({ message: 'Invalid user ID format.' });
  }

  try {
    const user = await User.findById(userId).select('apps');

    if (!user) {
      console.error('User not found with ID:', userId);
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(user.apps);
  } catch (err) {
    console.error('Error fetching apps:', err.message);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
};

// Delete an app by ID
const deleteApp = async (req, res) => {
  const userId = req.user.userId; // Access userId from token
  const { appId } = req.params; // Get appId from route parameters

  if (!userId || !userId.match(/^[0-9a-fA-F]{24}$/)) {
    console.error('Invalid user ID format:', userId);
    return res.status(400).json({ message: 'Invalid user ID format.' });
  }

  if (!appId || !appId.match(/^[0-9a-fA-F]{24}$/)) {
    console.error('Invalid app ID format:', appId);
    return res.status(400).json({ message: 'Invalid app ID format.' });
  }

  try {
    const user = await User.findById(userId);

    if (!user) {
      console.error('User not found with ID:', userId);
      return res.status(404).json({ message: 'User not found' });
    }

    const appIndex = user.apps.findIndex(app => app._id.toString() === appId);

    if (appIndex === -1) {
      console.error('App not found with ID:', appId);
      return res.status(404).json({ message: 'App not found' });
    }

    user.apps.splice(appIndex, 1);
    await user.save();

    console.log('App deleted with ID:', appId);
    res.status(200).json({ message: 'App deleted successfully' });
  } catch (err) {
    console.error('Error deleting app:', err.message);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
};
export default addapp;
export{getApps,addapp,deleteApp,generateOtp};