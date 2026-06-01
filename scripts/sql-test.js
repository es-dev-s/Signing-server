const { Pool } = require('pg');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const connStr = process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL;
if (!connStr) {
  console.error('Missing SUPABASE_DATABASE_URL');
  process.exit(1);
}

const pool = new Pool({
  connectionString: connStr,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000,
});

(async () => {
  console.log('running queries...');
  const r = await pool.query('SELECT now()');
  console.log('now()', r.rows[0]);
  const r2 = await pool.query(
    `INSERT INTO organizations (name) VALUES ('default')
     ON CONFLICT (name) DO NOTHING
     RETURNING id, name`
  );
  console.log('insert result', r2.rows);
  const r3 = await pool.query('SELECT COUNT(*)::int AS c FROM admins');
  console.log('admins count', r3.rows[0]);
  await pool.end();
  console.log('done');
})().catch((err) => {
  console.error('sql-test error', err);
  process.exit(1);
});
