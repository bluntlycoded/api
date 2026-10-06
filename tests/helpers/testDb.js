import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import pg from 'pg';
import { newDb, DataType } from 'pg-mem';
import { setPool } from '../../lib/db.js';

const dir = path.join(import.meta.dirname, '../../supabase/migrations');
const sql = (file) => fs.readFileSync(path.join(dir, file), 'utf8');

// In-memory Postgres (pg-mem) by default. Set TEST_DATABASE_URL to run the same tests
// against a real, disposable Postgres; its public schema is wiped first, and the
// row-level-security migrations run too (with stand-ins for Supabase's roles).
export const useTestDb = async () => {
  if (process.env.TEST_DATABASE_URL) {
    const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
    await pool.query('drop schema public cascade; create schema public;');
    await pool.query(`
      do $$ begin
        if not exists (select from pg_roles where rolname = 'anon') then create role anon; end if;
        if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated; end if;
      end $$;`);
    for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) await pool.query(sql(file));
    setPool(pool);
    return;
  }

  const db = newDb();
  db.public.registerFunction({ name: 'gen_random_uuid', returns: DataType.uuid, implementation: randomUUID, impure: true });
  for (const file of ['0001_init.sql', '0003_sessions_and_recovery.sql']) db.public.none(sql(file));
  const { Pool } = db.adapters.createPg();
  setPool(new Pool());
};
