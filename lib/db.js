import pg from 'pg';
import { config } from '../config/env.js';

// pg returns bigint as strings; the counters here stay far below 2^53.
pg.types.setTypeParser(20, Number);

let pool;

const getPool = () => {
  if (!pool) {
    if (!config.databaseUrl) throw new Error('DATABASE_URL is required (see .env.example)');
    pool = new pg.Pool({
      connectionString: config.databaseUrl,
      ssl: config.databaseSsl ? { rejectUnauthorized: false } : undefined,
      max: 10,
    });
  }
  return pool;
};

// Tests inject an in-memory pool.
const setPool = (replacement) => {
  pool = replacement;
};

const query = (text, params) => getPool().query(text, params);

const closePool = async () => {
  await pool?.end();
  pool = undefined;
};

export { query, setPool, closePool };

const camel = (key) => key.replace(/_([a-z])/g, (_, c) => c.toUpperCase());

// snake_case row -> camelCase object (null stays null).
const mapRow = (row) => (row ? Object.fromEntries(Object.entries(row).map(([k, v]) => [camel(k), v])) : null);

const one = async (text, params) => mapRow((await query(text, params)).rows[0]);
const many = async (text, params) => (await query(text, params)).rows.map(mapRow);

export { mapRow, one, many };
