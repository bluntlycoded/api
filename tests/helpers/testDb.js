import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { newDb, DataType } from 'pg-mem';
import { setPool } from '../../lib/db.js';

const migrations = ['0001_init.sql', '0003_sessions_and_recovery.sql'].map((f) =>
  path.join(import.meta.dirname, '../../supabase/migrations', f)
);

// Fresh in-memory Postgres with the real schema, wired into the app's db module.
export const useTestDb = () => {
  const db = newDb();
  db.public.registerFunction({ name: 'gen_random_uuid', returns: DataType.uuid, implementation: randomUUID, impure: true });
  for (const file of migrations) db.public.none(fs.readFileSync(file, 'utf8'));
  const { Pool } = db.adapters.createPg();
  setPool(new Pool());
};
