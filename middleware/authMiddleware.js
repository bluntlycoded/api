// backend/src/middleware/authMiddleware.js

import jwt from 'jsonwebtoken';

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract token after 'Bearer '

  console.log('Authorization Header:', authHeader); // Log the Authorization header
  console.log('Extracted Token:', token); // Log the extracted token

  if (!token) {
    console.warn('No token provided in request headers.');
    return res.status(401).json({ message: 'No token provided. Authorization denied.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Decoded Token:', decoded); // Log the decoded token
    req.user = decoded; // Attach decoded token to req.user
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return res.status(403).json({ message: 'Invalid or expired token. Authorization denied.' });
  }
};

export default verifyToken;
