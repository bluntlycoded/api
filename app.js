import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config } from './config/env.js';
import { apiLimiter } from './middleware/rateLimit.js';
import { notFound, errorHandler } from './middleware/errorHandler.js';
import authRoutes from './routes/authRoutes.js';
import appRoutes from './routes/appRoutes.js';
import totpRoutes from './routes/totpRoutes.js';
import approvalRoutes from './routes/approvalRoutes.js';
import deviceRoutes from './routes/deviceRoutes.js';
import securityRoutes from './routes/securityRoutes.js';
import blockchainRoutes from './routes/blockchainRoutes.js';

const createApp = () => {
  const app = express();

  // Behind a proxy, set TRUST_PROXY so req.ip is the client IP. Risk scoring
  // depends on it.
  if (config.trustProxy) app.set('trust proxy', config.trustProxy);

  app.use(helmet());
  app.use(cors({ origin: config.allowedOrigins.length ? config.allowedOrigins : true }));
  app.use(express.json({ limit: '10kb' }));

  app.get('/', (req, res) => res.send('Welcome to the Authenticator API!'));
  app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

  app.use('/api', apiLimiter);
  app.use('/api/auth', authRoutes);
  app.use('/api/addapp', appRoutes);
  app.use('/api/totp', totpRoutes);
  app.use('/api/approval', approvalRoutes);
  app.use('/api/devices', deviceRoutes);
  app.use('/api/security', securityRoutes);
  app.use('/api/blockchain', blockchainRoutes);

  app.use(notFound);
  app.use(errorHandler);
  return app;
};

export default createApp;
