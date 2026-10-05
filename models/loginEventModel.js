import mongoose from 'mongoose';

const loginEventSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  // Only 'success' events form the baseline for risk scoring, so a blocked
  // attacker cannot shift what counts as normal for the account.
  outcome: {
    type: String,
    enum: ['success', 'failed_credentials', 'challenged', 'denied'],
    required: true,
  },
  deviceHash: String,
  ip: String,
  geo: {
    country: String,
    region: String,
    city: String,
    lat: Number,
    lon: Number,
    timezone: String,
  },
  localHour: Number,
  riskScore: Number,
  signals: [{ _id: false, id: String, points: Number, detail: String }],
  at: { type: Date, default: Date.now },
});

loginEventSchema.index({ userId: 1, outcome: 1, at: -1 });

export default mongoose.model('LoginEvent', loginEventSchema);
