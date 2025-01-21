// backend/src/models/User.js

import mongoose from 'mongoose';

// Define the schema for the User model
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    apps: [
      {
        appName: { 
          type: String, 
          required: true 
        },  // Name of the app (e.g., GitHub, Google)
        secretKey: { 
          type: String, 
          required: true 
        },  // Secret key for the app used to generate TOTP
      },
    ],
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }  // Automatically adds createdAt and updatedAt fields
);

// Create the User model from the schema
const User = mongoose.model('User', userSchema);

export default User;
