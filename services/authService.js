import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { jwtConfig } from '../config/env.js';

// Hash password
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

// Verify password
const verifyPassword = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};

// Generate JWT token
const generateJWTToken = (userId) => {
  return jwt.sign({ userId }, jwtConfig.secretKey, { expiresIn: '1h' });
};

// Verify JWT token
const verifyJWTToken = (token) => {
  try {
    return jwt.verify(token, jwtConfig.secretKey);
  } catch (error) {
    return null;
  }
};

export { hashPassword, verifyPassword, generateJWTToken, verifyJWTToken };
