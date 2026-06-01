'use strict';

/**
 * Super-admin audit-dashboard proxy (server-side).
 * Electron talks only to signaling WS; this module forwards to the audit Next.js API
 * using AUDIT_DASHBOARD_URL + AUDIT_SUPERADMIN_SERVICE_SECRET on the signaling host.
 */

/**
 * Node/undici often throws TypeError with message "fetch failed"; the real reason is in `cause`
 * (e.g. ECONNREFUSED, certificate hostname mismatch). Flatten for admin UI + logs.
 */
function formatNetworkError(err) {
  if (err == null) return 'Unknown error';
  const parts = [];
  let e = err;
  for (let depth = 0; e && depth < 6; depth += 1) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg && !parts.includes(msg)) parts.push(msg);
    const code = typeof e.code === 'string' ? e.code : null;
    if (code && !parts.some((p) => p.includes(code))) parts.push(`(${code})`);
    e = e.cause;
  }
  return parts.length ? parts.join(' — ') : 'Unknown error';
}

/** Allow AUDIT_DASHBOARD_URL=localhost:3000 (prepend http:// for fetch). */
function normalizeAuditOrigin(raw) {
  const s = String(raw || '').trim().replace(/\/$/, '');
  if (!s) return '';
  if (/^https?:\/\//i.test(s)) return s;
  return `http://${s}`;
}

async function auditFetchJson(origin, secret, path, options = {}) {
  const base = normalizeAuditOrigin(origin);
  if (!base) throw new Error('Missing AUDIT_DASHBOARD_URL');
  const url = `${base}${path.startsWith('/') ? path : `/${path}`}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${secret}`,
      ...(options.headers || {}),
    },
  });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: 'INVALID_JSON', raw: text.slice(0, 400) };
  }
  return { ok: res.ok, status: res.status, data };
}

function auditEnv() {
  const rawOrigin = (process.env.AUDIT_DASHBOARD_URL || '').trim();
  const secret = (process.env.AUDIT_SUPERADMIN_SERVICE_SECRET || '').trim();
  const origin = normalizeAuditOrigin(rawOrigin);
  return { origin, secret, configured: !!(rawOrigin && secret) };
}

async function handleList(signaling, socketId, ws, msg) {
  const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
  const admin = await signaling._requireAdmin(socketId, ws, msg);
  if (!admin) return;
  if (admin.role !== 'super_admin') {
    signaling._send(ws, {
      type: 'admin-audit-org-access-list-response',
      success: false,
      error: 'FORBIDDEN',
      message: 'Super admin only',
      ipcCorrId,
    });
    return;
  }
  const { origin, secret, configured } = auditEnv();
  if (!configured) {
    signaling._send(ws, {
      type: 'admin-audit-org-access-list-response',
      success: false,
      error: 'AUDIT_PROXY_NOT_CONFIGURED',
      message:
        'Set AUDIT_DASHBOARD_URL and AUDIT_SUPERADMIN_SERVICE_SECRET on the signaling server (same as audit-dashboard).',
      ipcCorrId,
    });
    return;
  }
  const statusFilter = typeof msg.status === 'string' ? msg.status.trim() : '';
  const q = statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : '';
  try {
    const { ok, status, data } = await auditFetchJson(
      origin,
      secret,
      `/api/superadmin/audit-org-access${q}`,
    );
    if (!ok) {
      signaling._send(ws, {
        type: 'admin-audit-org-access-list-response',
        success: false,
        error: data.error || 'HTTP_ERROR',
        message: typeof data.error === 'string' ? data.error : `HTTP ${status}`,
        ipcCorrId,
      });
      return;
    }
    const requests = Array.isArray(data.requests) ? data.requests : [];
    const pendingCount =
      typeof data.pendingCount === 'number'
        ? data.pendingCount
        : requests.filter((r) => r && r.status === 'pending').length;
    signaling._send(ws, {
      type: 'admin-audit-org-access-list-response',
      success: true,
      requests,
      pendingCount,
      ipcCorrId,
    });
  } catch (err) {
    const detail = formatNetworkError(err);
    console.warn('[auditOrgAccessProxy] list fetch failed', { detail, target: `${origin}/api/superadmin/audit-org-access` });
    signaling._send(ws, {
      type: 'admin-audit-org-access-list-response',
      success: false,
      error: 'AUDIT_PROXY_FETCH_FAILED',
      message: detail,
      ipcCorrId,
    });
  }
}

async function handleReview(signaling, socketId, ws, msg) {
  const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
  const admin = await signaling._requireAdmin(socketId, ws, msg);
  if (!admin) return;
  if (admin.role !== 'super_admin') {
    signaling._send(ws, {
      type: 'admin-audit-org-access-review-response',
      success: false,
      error: 'FORBIDDEN',
      message: 'Super admin only',
      ipcCorrId,
    });
    return;
  }
  const { origin, secret, configured } = auditEnv();
  if (!configured) {
    signaling._send(ws, {
      type: 'admin-audit-org-access-review-response',
      success: false,
      error: 'AUDIT_PROXY_NOT_CONFIGURED',
      message:
        'Set AUDIT_DASHBOARD_URL and AUDIT_SUPERADMIN_SERVICE_SECRET on the signaling server (same as audit-dashboard).',
      ipcCorrId,
    });
    return;
  }
  const id = typeof msg.id === 'string' ? msg.id.trim() : '';
  const action = msg.action;
  const reviewerUsername = typeof msg.reviewerUsername === 'string' ? msg.reviewerUsername.trim() : '';
  if (!id || !reviewerUsername || !['approve', 'reject', 'revoke'].includes(String(action))) {
    signaling._send(ws, {
      type: 'admin-audit-org-access-review-response',
      success: false,
      error: 'INVALID_INPUT',
      ipcCorrId,
    });
    return;
  }
  try {
    const { ok, status, data } = await auditFetchJson(origin, secret, '/api/superadmin/audit-org-access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, action, reviewerUsername }),
    });
    if (!ok) {
      signaling._send(ws, {
        type: 'admin-audit-org-access-review-response',
        success: false,
        error: data.error || 'HTTP_ERROR',
        message: typeof data.error === 'string' ? data.error : `HTTP ${status}`,
        ipcCorrId,
      });
      return;
    }
    signaling._send(ws, {
      type: 'admin-audit-org-access-review-response',
      success: data.success !== false && !data.error,
      status: data.status,
      ipcCorrId,
    });
  } catch (err) {
    const detail = formatNetworkError(err);
    console.warn('[auditOrgAccessProxy] review fetch failed', { detail, target: `${origin}/api/superadmin/audit-org-access` });
    signaling._send(ws, {
      type: 'admin-audit-org-access-review-response',
      success: false,
      error: 'AUDIT_PROXY_FETCH_FAILED',
      message: detail,
      ipcCorrId,
    });
  }
}

module.exports = { handleList, handleReview };
