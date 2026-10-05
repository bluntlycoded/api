import mongoose from 'mongoose';

const auditEventSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true },
  ip: String,
  details: mongoose.Schema.Types.Mixed,
  at: { type: Date, default: Date.now },
});

auditEventSchema.index({ userId: 1, at: -1 });

export default mongoose.model('AuditEvent', auditEventSchema);
