import http from 'http';
import mongoose from 'mongoose';
import { config } from './config/env.js';
import connectDB from './config/database.js';
import createApp from './app.js';
import { initRealtime } from './services/realtime.js';

const start = async () => {
  await connectDB();

  const server = http.createServer(createApp());
  initRealtime(server);
  server.listen(config.port, () => console.log(`Server is running on port ${config.port}`));

  const shutdown = () => {
    server.close(async () => {
      await mongoose.disconnect();
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
