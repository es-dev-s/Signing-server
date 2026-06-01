// Quick connectivity sanity-check for Supabase/Postgres.
// Usage: npm run db:check (loads .env + .env.local automatically).
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });
dotenv.config({ path: path.join(__dirname, '..', '.env.local') });

const SignalingDatabase = require('../database');

(async () => {
  const envKeys = Object.keys(process.env).filter((k) =>
    k.startsWith('SUPABASE') || k === 'DATABASE_URL' || k === 'PGSSLMODE' || k === 'PG_CONNECT_TIMEOUT_MS'
  );
  console.log('Env keys present:', envKeys);

  const db = new SignalingDatabase(undefined, { healthCheck: true });
  const t0 = Date.now();
  await db._ready;
  console.log(`DB responded to health check in ${Date.now() - t0} ms`);

  await db.close();
  process.exit(0);
})().catch((err) => {
  console.error('DB health check failed:', err?.message || err);
  process.exit(1);
});
