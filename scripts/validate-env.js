'use strict';

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config({ path: path.join(__dirname, '..', '.env.local') });

const required = [
  'TURN_STUN_URL',
  'TURN_UDP_URL',
  'TURN_TCP_URL',
  'TURN_USERNAME',
  'TURN_CREDENTIAL',
  'WS_CONNECT_TOKEN',
  'INGEST_TOKEN_SECRET',
];

const missing = required.filter((k) => !process.env[k]);
const hasDbUrl = !!process.env.SUPABASE_DATABASE_URL || !!process.env.DATABASE_URL;
if (!hasDbUrl) {
  missing.push('SUPABASE_DATABASE_URL|DATABASE_URL');
}

if (missing.length > 0) {
  console.error('[startup] Missing required env variables:', missing.join(', '));
  process.exit(1);
}

console.log('[startup] All required env variables present.');
