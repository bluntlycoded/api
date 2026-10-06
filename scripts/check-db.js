// Read-only check of a deployed database: are all tables there, is row level security
// on, and are Supabase's public API roles locked out? Changes nothing.
//   npm run check:db      (uses DATABASE_URL from .env)
import { query, closePool } from '../lib/db.js';

const TABLES = [
  'users', 'user_apps', 'devices', 'login_events', 'approvals', 'audit_events', 'passkeys',
  'webauthn_challenges', 'vaults', 'blocked_ips', 'refresh_tokens', 'recovery_codes',
];
const API_ROLES = ['anon', 'authenticated'];
const PRIVILEGES = ['select', 'insert', 'update', 'delete'];

let failures = 0;
const check = (ok, message) => {
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${message}`);
};

const present = new Map(
  (await query(`select relname, relrowsecurity from pg_class where relnamespace = 'public'::regnamespace and relkind = 'r'`)).rows.map(
    (r) => [r.relname, r.relrowsecurity]
  )
);
const roles = new Set((await query(`select rolname from pg_roles where rolname = any($1)`, [API_ROLES])).rows.map((r) => r.rolname));

for (const table of TABLES) {
  if (!present.has(table)) {
    check(false, `table ${table} is missing`);
    continue;
  }
  check(present.get(table), `${table}: row level security on`);
  for (const role of roles) {
    const open = (
      await query(`select ${PRIVILEGES.map((p) => `has_table_privilege($1, $2, '${p}')`).join(' or ')} as open`, [role, `public.${table}`])
    ).rows[0].open;
    check(!open, `${table}: ${role} has no access`);
  }
}

if (roles.size === 0) console.log('note: no anon/authenticated roles here, so API lockdown was not checked (normal outside Supabase)');

const columns = (await query(`select column_name from information_schema.columns where table_name = 'users' and table_schema = 'public'`)).rows.map((r) => r.column_name);
check(['locked', 'totp_enabled', 'password_hash'].every((c) => columns.includes(c)), 'users has the expected columns');

const recorded = await query(`select version, name from supabase_migrations.schema_migrations order by version`).catch(() => null);
if (recorded) console.log(`info: Supabase recorded ${recorded.rowCount} migrations: ${recorded.rows.map((r) => r.name || r.version).join(', ')}`);

console.log(failures ? `\n${failures} problem(s) found` : '\nAll checks passed');
await closePool();
process.exit(failures ? 1 : 0);
