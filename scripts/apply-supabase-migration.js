/**
 * Apply supabase_migration.sql to the Postgres database in SUPABASE_DATABASE_URL.
 * Usage: node scripts/apply-supabase-migration.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');

dotenv.config({ path: path.join(__dirname, '..', '.env') });
dotenv.config({ path: path.join(__dirname, '..', '.env.local') });

async function main() {
  const connStr = process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL;
  if (!connStr) {
    console.error('Missing SUPABASE_DATABASE_URL');
    process.exit(1);
  }
  const sqlPath = path.join(__dirname, '..', 'supabase_migration.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');
  const requireSsl =
    process.env.PGSSLMODE === 'require' ||
    process.env.SUPABASE_REQUIRE_SSL === '1' ||
    process.env.SUPABASE_REQUIRE_SSL === 'true' ||
    /supabase\.co/i.test(connStr);

  const pool = new Pool({
    connectionString: connStr,
    ssl: requireSsl ? { rejectUnauthorized: false } : undefined,
    max: 1,
  });

  try {
    console.log('[migrate] Applying', path.basename(sqlPath), '…');
    await pool.query(sql);
    console.log('[migrate] Done.');
  } catch (err) {
    console.error('[migrate] Failed:', err?.message || err);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();
