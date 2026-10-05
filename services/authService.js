import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { config } from '../config/env.js';

const BCRYPT_ROUNDS = 10;
// Compared against when the email is unknown, so timing doesn't reveal it.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', BCRYPT_ROUNDS);

const hashPassword = (password) => bcrypt.hash(password, BCRYPT_ROUNDS);

const verifyPassword = (password, hash) => bcrypt.compare(password, hash || DUMMY_HASH);

// `did` binds the session to a device so only trusted devices can approve logins.
const signToken = (userId, deviceHash) =>
  jwt.sign({ userId, did: deviceHash }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });

const verifyJwt = (token) => jwt.verify(token, config.jwtSecret);

export { hashPassword, verifyPassword, signToken, verifyJwt };
