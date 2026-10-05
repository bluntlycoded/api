// One-off migration: encrypts authenticator secrets stored as plaintext before
// encryption at rest was added. Safe to re-run; already-encrypted values are skipped.
import mongoose from 'mongoose';
import connectDB from '../config/database.js';
import { encrypt } from '../utils/crypto.js';
import User from '../models/userModel.js';

const ENCRYPTED_PREFIX = 'enc:v1:';

await connectDB();

let users = 0;
let secrets = 0;

// Raw driver access on purpose: the model's getters and setters would hide the stored value.
for await (const doc of User.collection.find({ 'apps.0': { $exists: true } })) {
  const apps = doc.apps.map((app) => {
    if (typeof app.secretKey !== 'string' || app.secretKey.startsWith(ENCRYPTED_PREFIX)) return app;
    secrets += 1;
    return { ...app, secretKey: encrypt(app.secretKey) };
  });
  if (apps.some((app, i) => app !== doc.apps[i])) {
    await User.collection.updateOne({ _id: doc._id }, { $set: { apps } });
    users += 1;
  }
}

console.log(`Encrypted ${secrets} secret(s) across ${users} user(s)`);
await mongoose.disconnect();
