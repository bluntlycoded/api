import mongoose from 'mongoose';
import { config } from './env.js';

const connectDB = async () => {
  if (!config.mongoUri) throw new Error('MONGO_URI is required (see .env.example)');
  await mongoose.connect(config.mongoUri);
  console.log('MongoDB connected');
};

export default connectDB;
