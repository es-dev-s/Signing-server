/**
 * Quick Supabase Postgres connection test for `signaling-server`.
 *
 * Usage (PowerShell):
 *   cd signaling-server
 *   # ensure SUPABASE_DATABASE_URL is set in env or .env/.env.local
 *   node scripts/test-supabase-conn.js
 *
 * Prints only non-secret info.
 */

const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');

// Match server.js env loading order.
dotenv.config({ path: path.join(__dirname, '..', '.env') });
dotenv.config({ path: path.join(__dirname, '..', '.env.local') });

function boolFromEnv(key) {
  const v = String(process.env[key] || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

async function main() {
  const connStr = process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL || null;
  if (!connStr) {
    console.error('❌ Missing SUPABASE_DATABASE_URL (or DATABASE_URL).');
    process.exit(2);
  }

  const requireSsl =
    process.env.PGSSLMODE === 'require' ||
    boolFromEnv('SUPABASE_REQUIRE_SSL') ||
    process.env.NODE_ENV === 'production';

  const pool = new Pool({
    connectionString: connStr,
    ssl: requireSsl ? { rejectUnauthorized: false } : undefined,
    max: 1,
  });

  try {
    const r1 = await pool.query('select 1 as ok');
    const ok = r1.rows?.[0]?.ok === 1;

    const tables = [
      'organizations',
      'admins',
      'admin_sessions',
      'clients',
      'sessions',
      'transfer_requests',
      'call_events',
      'taskbar_events',
      'app_settings',
    ];

    const r2 = await pool.query(
      `
      select table_name
      from information_schema.tables
      where table_schema = 'public' and table_name = any($1::text[])
      order by table_name asc
      `,
      [tables]
    );
    const found = new Set((r2.rows || []).map((x) => x.table_name));
    const missing = tables.filter((t) => !found.has(t));

    console.log('✅ Postgres reachable:', ok);
    console.log('✅ SSL required:', requireSsl);
    console.log('✅ Tables found:', Array.from(found).length, '/', tables.length);
    if (missing.length) {
      console.log('⚠️  Missing tables (run supabase_migration.sql):', missing.join(', '));
      process.exitCode = 3;
    } else {
      console.log('✅ Schema looks good.');
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('❌ Connection test failed:', msg);
    process.exitCode = 1;
  } finally {
    try {
      await pool.end();
    } catch {
      /* ignore */
    }
  }
}

void main();

