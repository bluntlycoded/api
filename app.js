import path from 'path';
import { fileURLToPath } from 'url';
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
import recoveryRoutes from './routes/recoveryRoutes.js';
import vaultRoutes from './routes/vaultRoutes.js';
import passkeyRoutes from './routes/passkeyRoutes.js';
import blockchainRoutes from './routes/blockchainRoutes.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');

const createApp = () => {
  const app = express();

  // Behind a proxy, set TRUST_PROXY so req.ip is the client IP. Risk scoring
  // depends on it.
  if (config.trustProxy) app.set('trust proxy', config.trustProxy);

  app.use(helmet());
  app.use(cors({ origin: config.allowedOrigins.length ? config.allowedOrigins : true }));
  // Bulk import and the encrypted vault are larger than ordinary requests. These
  // parsers run first; the default one below skips bodies already parsed.
  app.use('/api/addapp/import', express.json({ limit: '512kb' }));
  app.use('/api/vault', express.json({ limit: '1mb' }));
  app.use(express.json({ limit: '10kb' }));

  // Web client for the login and approval screens.
  app.use('/app', express.static(publicDir));
  app.get('/', (req, res) => res.redirect('/app/'));
  app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

  app.use('/api', apiLimiter);
  app.use('/api/auth', authRoutes);
  app.use('/api/addapp', appRoutes);
  app.use('/api/totp', totpRoutes);
  app.use('/api/approval', approvalRoutes);
  app.use('/api/devices', deviceRoutes);
  app.use('/api/security', securityRoutes);
  app.use('/api/recovery', recoveryRoutes);
  app.use('/api/vault', vaultRoutes);
  app.use('/api/passkeys', passkeyRoutes);
  app.use('/api/blockchain', blockchainRoutes);

  app.use(notFound);
  app.use(errorHandler);
  return app;
};

export default createApp;
