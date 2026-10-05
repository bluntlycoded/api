import User from '../models/userModel.js';
import { authenticator } from 'otplib';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const addApp = asyncHandler(async (req, res) => {
  const { appName, secretKey } = req.body;

  const user = await User.findById(req.user.userId).select('apps');
  if (!user) throw new HttpError(404, 'User not found');

  user.apps.push({ appName, secretKey });
  await user.save();

  res.status(200).json(user.apps.at(-1));
});

const getApps = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('apps');
  if (!user) throw new HttpError(404, 'User not found');

  res.status(200).json(user.apps);
});

const deleteApp = asyncHandler(async (req, res) => {
  const { appId } = req.params;

  const result = await User.updateOne(
    { _id: req.user.userId, 'apps._id': appId },
    { $pull: { apps: { _id: appId } } }
  );
  if (result.modifiedCount === 0) throw new HttpError(404, 'App not found');

  res.status(200).json({ message: 'App deleted successfully' });
});

const generateOtp = asyncHandler(async (req, res) => {
  const user = await User.findOne({ _id: req.user.userId, 'apps._id': req.params.appId }).select('apps');
  const app = user?.apps.id(req.params.appId);
  if (!app) throw new HttpError(404, 'App not found');

  res.status(200).json({
    otp: authenticator.generate(app.secretKey),
    expiresInSeconds: authenticator.timeRemaining(),
  });
});

export { addApp, getApps, deleteApp, generateOtp };
