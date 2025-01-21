// backend/src/controllers/totpController.js

import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import User from '../models/userModel.js';  // Assuming you have a User model to store user data

// Generate TOTP secret for the user
export const generateTOTPSecret = async (req, res) => {
  const userId = req.user.id;  // Assuming user is authenticated and user ID is available
  const user = await User.findById(userId);  // Get user from DB

  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  // Generate a new TOTP secret
  const secret = speakeasy.generateSecret({ length: 20 });

  // Save the secret key for the user in the database
  user.totpSecret = secret.base32;
  await user.save();

  // Generate the QR code URI (used by Authenticator app to scan)
  const otpauthUrl = speakeasy.otpauth.URL({
    label: user.email,  // User's email as the label for the QR code
    secret: secret.base32,
    issuer: 'MyApp',  // App name for display in the authenticator
  });

  // Generate the QR code URL for the frontend to display
  QRCode.toDataURL(otpauthUrl, function (err, data_url) {
    if (err) {
      return res.status(500).json({ message: 'Error generating QR code' });
    }
    return res.json({ qrCodeUrl: data_url, secret: secret.base32 });
  });
};

// Verify TOTP token
export const verifyTOTP = async (req, res) => {
  const { token } = req.body;  // OTP entered by the user
  const userId = req.user.id;

  // Get the user's secret from the DB
  const user = await User.findById(userId);
  if (!user || !user.totpSecret) {
    return res.status(400).json({ message: 'TOTP secret not found' });
  }

  // Verify the OTP using speakeasy
  const isValid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: token,
  });

  if (isValid) {
    return res.status(200).json({ message: 'OTP is valid' });
  } else {
    return res.status(400).json({ message: 'Invalid OTP' });
  }
};
