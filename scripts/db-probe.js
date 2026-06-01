// Probe to find where startup hangs.
const path = require('path');
const dotenv = require('dotenv');
dotenv.config({ path: path.join(__dirname, '..', '.env') });
dotenv.config({ path: path.join(__dirname, '..', '.env.local') });
const SignalingDatabase = require('../database');

(async () => {
  console.log('[probe] ctor');
  const db = new SignalingDatabase();
  console.log('[probe] after ctor, awaiting _ready');
  await db._ready;
  console.log('[probe] after _ready, running resetAllOnStartup');
  await db.resetAllOnStartup();
  console.log('[probe] reset done, closing');
  await db.close();
  console.log('[probe] done');
})().catch((err) => {
  console.error('[probe] error', err);
  process.exit(1);
});
