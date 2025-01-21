// backend/server.js

import express from 'express';
import dotenv from 'dotenv';
import connectDB from './config/database.js';  // MongoDB connection function
import authRoutes from './routes/authRoutes.js';  // Authentication routes (sign-up, login)
import blockchainRoutes from './routes/blockchainRoutes.js';  // Blockchain routes (Solana)
import totpRoutes from './routes/totpRoutes.js';
import appRoutes from './routes/appRoutes.js';  // Add App routes
import cors from 'cors';

dotenv.config();  // Load environment variables from .env file

const app = express();


app.use(cors());

// Connect to MongoDB
connectDB();

// Middleware to parse JSON bodies for incoming requests
app.use(express.json());  // Parse JSON in incoming requests

// Define API routes
app.use('/api/auth', authRoutes);  // Authentication routes (sign-up, login, etc.)
app.use('/api/blockchain', blockchainRoutes);  // Blockchain routes (Solana, etc.)
app.use('/api/totp', totpRoutes);
app.use('/api/addapp', appRoutes);  // Add App routes

// Default route (optional)
app.get('/', (req, res) => {
  res.send('Welcome to the Authenticator API!');
});

// Start the server on the specified port
const PORT = process.env.PORT || 2700;  // Use PORT from .env or default to 2700
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
