#!/usr/bin/env node
/**
 * Verifies signaling-server can reach audit-dashboard super-admin API
 * (same fetch as auditOrgAccessProxy). Requires audit app running if URL is local.
 *
 * Usage: from signaling-server root: node scripts/verify-audit-proxy.js
 */
'use strict';

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config({ path: path.join(__dirname, '..', '.env.local') });

function normalizeAuditOrigin(raw) {
  const s = String(raw || '').trim().replace(/\/$/, '');
  if (!s) return '';
  if (/^https?:\/\//i.test(s)) return s;
  return `http://${s}`;
}

async function main() {
  const rawOrigin = (process.env.AUDIT_DASHBOARD_URL || '').trim();
  const secret = (process.env.AUDIT_SUPERADMIN_SERVICE_SECRET || '').trim();
  const base = normalizeAuditOrigin(rawOrigin);
  if (!rawOrigin || !secret) {
    console.error('FAIL: Set AUDIT_DASHBOARD_URL and AUDIT_SUPERADMIN_SERVICE_SECRET in .env');
    process.exit(1);
  }
  const url = `${base}/api/superadmin/audit-org-access`;
  let res;
  try {
    res = await fetch(url, {
      headers: { Accept: 'application/json', Authorization: `Bearer ${secret}` },
    });
  } catch (e) {
    console.error('FAIL: fetch error — is the audit dashboard running?', e.message || e);
    process.exit(1);
  }
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    console.error('FAIL: non-JSON response', res.status, text.slice(0, 200));
    process.exit(1);
  }
  if (!res.ok) {
    console.error('FAIL: HTTP', res.status, data);
    process.exit(1);
  }
  const n = typeof data.pendingCount === 'number' ? data.pendingCount : 0;
  const reqLen = Array.isArray(data.requests) ? data.requests.length : 0;
  console.log('OK: signaling → audit super-admin API reachable');
  console.log('   URL:', url);
  console.log('   requests:', reqLen, ' pendingCount:', n);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
