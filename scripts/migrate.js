// Applies supabase/migrations/*.sql in order. Applied files are recorded so
// re-running is safe. Alternatively paste the files into the Supabase SQL editor.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { query, closePool } from '../lib/db.js';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../supabase/migrations');

await query('create table if not exists schema_migrations (name text primary key, applied_at timestamptz not null default now())');
const { rows } = await query('select name from schema_migrations');
const applied = new Set(rows.map((r) => r.name));

for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) {
  if (applied.has(file)) continue;
  await query(fs.readFileSync(path.join(dir, file), 'utf8'));
  await query('insert into schema_migrations (name) values ($1)', [file]);
  console.log(`applied ${file}`);
}

await closePool();
