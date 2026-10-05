import mongoose from 'mongoose';

const approvalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  status: {
    type: String,
    enum: ['pending', 'approved', 'denied', 'consumed'],
    default: 'pending',
  },
  // Number shown on the login screen. Never sent to the approving device.
  number: { type: Number, required: true },
  options: { type: [Number], required: true },
  wrongAttempts: { type: Number, default: 0 },

  // Hash of the secret the login client uses to poll and to complete login.
  pollSecretHash: { type: String, required: true },

  // What is being approved. Shown to the approver.
  requestDeviceHash: { type: String, required: true },
  requestDeviceName: String,
  trustDevice: { type: Boolean, default: false },
  site: String,
  siteSource: { type: String, enum: ['origin-header', 'client-claimed', 'none'], default: 'none' },
  ip: String,
  geo: { country: String, region: String, city: String },
  userAgent: String,
  riskScore: Number,
  signals: [{ _id: false, id: String, points: Number, detail: String }],

  approvedByDeviceHash: String,
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
});

// Keep resolved challenges for a day for the audit trail, then drop them.
approvalSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 86400 });

export default mongoose.model('Approval', approvalSchema);
