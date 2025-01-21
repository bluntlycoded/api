import mongoose from 'mongoose';
import { mongoConfig } from './env.js';  // Import MongoDB configuration from env.js

// MongoDB Connection
const connectDB = async () => {
  try {
    // Connect to MongoDB using the URI from the .env file
    await mongoose.connect(mongoConfig.URI, { 
      useNewUrlParser: true, 
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error.message);
    process.exit(1);  // Exit the process with failure code if the connection fails
  }
};

export default connectDB;
