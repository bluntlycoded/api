import mongoose from 'mongoose';
import { encrypt, decrypt } from '../utils/crypto.js';

// Secrets are encrypted at rest and decrypted on read.
const encrypted = { set: encrypt, get: decrypt };

const appSchema = new mongoose.Schema(
  {
    appName: { type: String, required: true, trim: true, maxlength: 100 },
    secretKey: { type: String, required: true, ...encrypted },
  },
  { id: false, toJSON: { getters: true } }
);

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, select: false },
    apps: [appSchema],

    totpEnabled: { type: Boolean, default: false },
    totpSecret: { type: String, select: false, ...encrypted },
    // Last accepted 30s time step, so a code cannot be used twice.
    totpLastStep: { type: Number, default: 0, select: false },

    resetTokenHash: { type: String, select: false },
    resetTokenExpires: { type: Date, select: false },
  },
  { timestamps: true }
);

export default mongoose.model('User', userSchema);
