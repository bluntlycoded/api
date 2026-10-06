// Runs the whole app against an in-memory Postgres with throwaway secrets, so the web
// client can be tried with no Supabase project or .env. Everything is lost on restart.
//   npm run dev:memory   then open http://localhost:2700/app/
import http from 'http';
import { randomBytes } from 'crypto';

process.env.JWT_SECRET ??= randomBytes(32).toString('hex');
process.env.ENCRYPTION_KEY ??= randomBytes(32).toString('hex');
process.env.RATE_LIMIT_DISABLED ??= 'true';

const { useTestDb } = await import('../tests/helpers/testDb.js');
const { default: createApp } = await import('../app.js');
const { initRealtime } = await import('../services/realtime.js');
const { config } = await import('../config/env.js');

useTestDb();
const server = http.createServer(createApp());
initRealtime(server);
server.listen(config.port, () => {
  console.log(`In-memory dev server: http://localhost:${config.port}/app/`);
  console.log('Add ?profile=laptop (or any name) to open a second "device" in another tab.');
});
