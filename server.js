import http from 'http';
import { config } from './config/env.js';
import { query, closePool } from './lib/db.js';
import createApp from './app.js';
import { initRealtime } from './services/realtime.js';
import * as approvals from './repositories/approvalRepository.js';
import * as challenges from './repositories/challengeRepository.js';
import * as blockedIps from './repositories/blockedIpRepository.js';

const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

// Expired challenges and blocks are kept briefly for the audit trail, then dropped.
const cleanup = () =>
  Promise.all([
    approvals.purgeOlderThan(new Date(Date.now() - DAY_MS)),
    challenges.purgeExpired(),
    blockedIps.purgeExpired(),
  ]).catch((err) => console.error('Cleanup failed:', err.message));

const start = async () => {
  await query('select 1');
  console.log('Database connected');

  const server = http.createServer(createApp());
  initRealtime(server);
  server.listen(config.port, () => console.log(`Server is running on port ${config.port}`));

  const timer = setInterval(cleanup, CLEANUP_INTERVAL_MS);
  timer.unref();

  const shutdown = () => {
    clearInterval(timer);
    server.close(async () => {
      await closePool();
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
};

start().catch((err) => {
  console.error('Failed to start:', err.message);
  process.exit(1);
});
