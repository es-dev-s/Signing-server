const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');
const SignalingDatabase = require('./database');
const auditOrgAccessProxy = require('./auditOrgAccessProxy');
const { isOnOfficeNetwork, getOfficeNetworkLabel } = require('./ipUtils');

/** Sanitize LAN IPs reported by the Electron admin app (used when the server only sees public/WAN). */
function parseWorkstationIps(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const x of raw) {
    if (typeof x !== 'string') continue;
    let s = x.trim().slice(0, 64);
    if (!s) continue;
    const z = s.indexOf('%');
    if (z !== -1) s = s.slice(0, z);
    s = s.replace(/^\[|\]$/g, '');
    if (s.length < 3) continue;
    if (!/^[\d.:a-fA-F]+$/i.test(s)) continue;
    out.push(s);
    if (out.length >= 32) break;
  }
  return out;
}

// Load general app env first (tokens, auth, ports, etc).
// TURN is loaded separately from .env.turn/.env.trun.
dotenv.config({ path: path.join(__dirname, '.env') });
dotenv.config({ path: path.join(__dirname, '.env.local') });

function setEnvIfMissing(key, value) {
  if (!value) return;
  if (process.env[key]) return;
  process.env[key] = value;
}

function hasRequiredTurnEnv() {
  const keys = [
    'TURN_STUN_URL',
    'TURN_UDP_URL',
    'TURN_TCP_URL',
    'TURN_TLS_URL',
    'TURN_TLSTCP_URL',
    'TURN_USERNAME',
    'TURN_CREDENTIAL',
  ];
  return keys.every((k) => !!process.env[k]);
}

function tryLoadLegacyTurnSnippet(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw || !raw.includes('iceServers')) return false;

    const urls = [...raw.matchAll(/urls\s*:\s*["']([^"']+)["']/g)].map((m) => m[1]).filter(Boolean);
    const usernameMatch = raw.match(/username\s*:\s*["']([^"']+)["']/);
    const credentialMatch = raw.match(/credential\s*:\s*["']([^"']+)["']/);
    const username = usernameMatch?.[1];
    const credential = credentialMatch?.[1];

    setEnvIfMissing('TURN_STUN_URL', urls.find((u) => u.startsWith('stun:')));
    setEnvIfMissing('TURN_UDP_URL', urls.find((u) => u.startsWith('turn:') && !u.startsWith('turns:') && !u.includes('transport=tcp')));
    setEnvIfMissing('TURN_TCP_URL', urls.find((u) => u.startsWith('turn:') && u.includes('transport=tcp')));
    setEnvIfMissing('TURN_TLS_URL', urls.find((u) => u.startsWith('turn:') && u.includes(':443') && !u.includes('transport=tcp')));
    setEnvIfMissing('TURN_TLSTCP_URL', urls.find((u) => u.startsWith('turns:')));
    setEnvIfMissing('TURN_USERNAME', username);
    setEnvIfMissing('TURN_CREDENTIAL', credential);

    return urls.length > 0 || !!username || !!credential;
  } catch {
    return false;
  }
}

function loadTurnEnv() {
  const candidates = [
    path.join(__dirname, '.env.turn'),
    path.join(__dirname, '.env.trun'),
  ];

  for (const filePath of candidates) {
    if (!fs.existsSync(filePath)) continue;
    dotenv.config({ path: filePath });
    if (hasRequiredTurnEnv()) {
      console.log(`Loaded TURN environment from ${path.basename(filePath)}`);
      return;
    }
    if (tryLoadLegacyTurnSnippet(filePath)) {
      console.log(`Loaded TURN environment from legacy ${path.basename(filePath)} format`);
      return;
    }
  }
}

loadTurnEnv();

const PORT = parseInt(process.env.PORT, 10) || 8085;
// App-level liveness (JSON heartbeat from clients). Loose timeouts: proxies and OS sleep cause jitter.
const HEARTBEAT_CHECK_MS = parseInt(process.env.HEARTBEAT_CHECK_INTERVAL_MS, 10) || 8000;
const HEARTBEAT_TIMEOUT = parseInt(process.env.CLIENT_HEARTBEAT_TIMEOUT_MS, 10) || 90000;
// WebSocket ping/pong keeps connections alive through Railway and other reverse proxies.
const WS_PING_INTERVAL_MS = parseInt(process.env.WS_PING_INTERVAL_MS, 10) || 25000;

const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS, 10) || 2000;
const MAX_PER_IP = parseInt(process.env.MAX_PER_IP, 10) || 2000; // Increased because Railway proxy masks IPs
const SESSION_CLEANUP_INTERVAL = 30 * 60 * 1000; // 30 minutes
/** How often to purge old `browser_tab_events` (extension/BrowserScope snapshots). */
const BROWSER_TAB_RETENTION_INTERVAL_MS =
  parseInt(process.env.BROWSER_TAB_RETENTION_INTERVAL_MS, 10) || 6 * 60 * 60 * 1000;
/** How often to purge old `taskbar_events` (open-app / taskbar telemetry). Defaults to same cadence as browser tabs. */
const TASKBAR_RETENTION_INTERVAL_MS =
  parseInt(process.env.TASKBAR_RETENTION_INTERVAL_MS, 10) || BROWSER_TAB_RETENTION_INTERVAL_MS;
const ENFORCE_TLS = process.env.ENFORCE_TLS === '1' || process.env.ENFORCE_TLS === 'true';
if (!ENFORCE_TLS) {
  console.warn(
    '[SECURITY WARNING] ENFORCE_TLS is not enabled. ' +
    'Set ENFORCE_TLS=true in production to require WSS connections.'
  );
}
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const INGEST_TOKEN_SECRET = process.env.INGEST_TOKEN_SECRET || process.env.CALL_EVENTS_SECRET || null;
const INGEST_TOKEN_TTL_MS = parseInt(process.env.INGEST_TOKEN_TTL_MS, 10) || 15 * 60 * 1000;
console.log(`[Ingest] INGEST_TOKEN_SECRET present: ${!!INGEST_TOKEN_SECRET}`);
/**
 * Dev-only escape hatch (OFF by default).
 * When true, /api/call-events will accept unauthenticated uploads if the payload includes { deviceId }.
 * This is meant only for local testing when INGEST_TOKEN_SECRET isn't configured.
 */
const ALLOW_CALL_EVENTS_WITHOUT_TOKEN =
  process.env.ALLOW_CALL_EVENTS_WITHOUT_TOKEN === '1' ||
  process.env.ALLOW_CALL_EVENTS_WITHOUT_TOKEN === 'true';
// Taskbar + browser extension tab telemetry (ingest + WS broadcast to audit admins).
// Default ON so real-time BrowserScope → audit works without extra Railway env.
// Set ENABLE_APP_ACTIVITY_TELEMETRY=0 or false to disable.
const _appTelRaw = String(process.env.ENABLE_APP_ACTIVITY_TELEMETRY ?? '').trim().toLowerCase();
const ENABLE_APP_ACTIVITY_TELEMETRY =
  _appTelRaw === '0' || _appTelRaw === 'false' || _appTelRaw === 'off' || _appTelRaw === 'no'
    ? false
    : true;
console.log(`[Telemetry] ENABLE_APP_ACTIVITY_TELEMETRY=${ENABLE_APP_ACTIVITY_TELEMETRY} (browser tabs + taskbar ingest/broadcast)`);
// Real-time fast lane: when false, browser-tab ingest still broadcasts to admins but skips DB writes.
const _tabPersistRaw = String(process.env.BROWSER_TAB_PERSIST_TO_DB ?? '1').trim().toLowerCase();
const BROWSER_TAB_PERSIST_TO_DB =
  _tabPersistRaw === '0' || _tabPersistRaw === 'false' || _tabPersistRaw === 'off' || _tabPersistRaw === 'no'
    ? false
    : true;
console.log(`[Telemetry] BROWSER_TAB_PERSIST_TO_DB=${BROWSER_TAB_PERSIST_TO_DB} (when false: WS live-only, no browser_tab_events writes)`);

const MAX_MESSAGE_BYTES = 64 * 1024;
const MAX_HTTP_BODY_BYTES = 256 * 1024;
// When a client reconnects repeatedly (dev hot reloads, double launches, etc),
// two processes can "fight" for the same deviceId and cause rapid disconnect storms.
// This guard prefers the currently-online socket and rejects fast successive takeovers.
const DEVICE_TAKEOVER_COOLDOWN_MS = parseInt(process.env.DEVICE_TAKEOVER_COOLDOWN_MS, 10) || 3000;

function normalizeIceServersFromJson(parsed) {
  if (!Array.isArray(parsed) || parsed.length === 0) return null;
  const out = [];
  for (const entry of parsed) {
    if (!entry || typeof entry !== 'object') continue;
    const urlsRaw = entry.urls;
    const urls = Array.isArray(urlsRaw)
      ? urlsRaw.filter((u) => typeof u === 'string' && u.trim().length > 0)
      : typeof urlsRaw === 'string' && urlsRaw.trim().length > 0
        ? [urlsRaw.trim()]
        : [];
    if (urls.length === 0) continue;
    const row = { urls: urls.length === 1 ? urls[0] : urls };
    if (typeof entry.username === 'string' && entry.username.trim()) row.username = entry.username.trim();
    if (typeof entry.credential === 'string' && entry.credential.trim()) row.credential = entry.credential.trim();
    out.push(row);
  }
  return out.length > 0 ? out : null;
}

/** Strip browser-blocked :53 URLs from Cloudflare API iceServers before sending to clients. */
function filterPort53FromCloudflareIceServers(entries) {
  const out = [];
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    const urlsRaw = entry.urls;
    const list = Array.isArray(urlsRaw)
      ? urlsRaw.filter((u) => typeof u === 'string' && u.trim().length > 0)
      : typeof urlsRaw === 'string' && urlsRaw.trim().length > 0
        ? [urlsRaw.trim()]
        : [];
    const filtered = list.filter((u) => !u.includes(':53'));
    if (filtered.length === 0) continue;
    const row = { urls: filtered.length === 1 ? filtered[0] : filtered };
    if (typeof entry.username === 'string' && entry.username.trim()) row.username = entry.username.trim();
    if (typeof entry.credential === 'string' && entry.credential.trim()) row.credential = entry.credential.trim();
    out.push(row);
  }
  return out;
}

/**
 * Fetches short-lived Cloudflare TURN/STUN iceServers via API. Returns [] if unset, failed, or misconfigured.
 */
async function fetchCloudflareIceServers() {
  const keyId = (process.env.CLOUDFLARE_TURN_KEY_ID || '').trim();
  const apiToken = (process.env.CLOUDFLARE_TURN_KEY_API_TOKEN || '').trim();
  if (!keyId || !apiToken) return [];
  try {
    const body = JSON.stringify({ ttl: 86400 });
    const pathOnly = `/v1/turn/keys/${encodeURIComponent(keyId)}/credentials/generate-ice-servers`;
    const result = await new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: 'rtc.live.cloudflare.com',
          path: pathOnly,
          method: 'POST',
          headers: {
            Authorization: `Bearer ${apiToken}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body, 'utf8'),
          },
        },
        (res) => {
          const chunks = [];
          res.on('data', (d) => chunks.push(d));
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') });
          });
        },
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    if (result.statusCode < 200 || result.statusCode >= 300) {
      console.warn('[ICE][Cloudflare] API error', result.statusCode, result.body.slice(0, 240));
      return [];
    }
    let parsed;
    try {
      parsed = JSON.parse(result.body);
    } catch (e) {
      console.warn('[ICE][Cloudflare] JSON parse failed:', e?.message || e);
      return [];
    }
    const raw = Array.isArray(parsed.iceServers) ? parsed.iceServers : null;
    if (!raw) return [];
    return filterPort53FromCloudflareIceServers(raw);
  } catch (e) {
    console.warn('[ICE][Cloudflare] request failed:', e?.message || e);
    return [];
  }
}

function buildIceServers(turnUsername = process.env.TURN_USERNAME, turnCredential = process.env.TURN_CREDENTIAL, logConfig = true) {
  const jsonEnv = process.env.ICE_SERVERS_JSON || process.env.ANYWHERE_ICE_SERVERS_JSON;
  if (jsonEnv && String(jsonEnv).trim()) {
    try {
      const parsed = JSON.parse(jsonEnv);
      const normalized = normalizeIceServersFromJson(parsed);
      if (normalized) {
        if (logConfig) {
          console.log('✅ ICE config loaded from ICE_SERVERS_JSON / ANYWHERE_ICE_SERVERS_JSON');
        }
        return normalized;
      }
    } catch (e) {
      if (logConfig) {
        console.error('❌ ICE_SERVERS_JSON parse failed:', e?.message || e);
      }
    }
  }

  const turnStunUrl = process.env.TURN_STUN_URL;
  const turnUdpUrl = process.env.TURN_UDP_URL;
  const turnTcpUrl = process.env.TURN_TCP_URL;
  const turnTlsTcpUrl = process.env.TURN_TLSTCP_URL;
  const iceServers = [
    ...(turnStunUrl ? [{ urls: turnStunUrl }] : []),
    ...(turnUdpUrl ? [{ urls: turnUdpUrl, username: turnUsername, credential: turnCredential }] : []),
    ...(turnTcpUrl ? [{ urls: turnTcpUrl, username: turnUsername, credential: turnCredential }] : []),
    ...(turnTlsTcpUrl ? [{ urls: turnTlsTcpUrl, username: turnUsername, credential: turnCredential }] : []),
  ];

  const invalidRows = iceServers.filter((entry) => {
    if (!entry || !entry.urls) return true;
    const urlsList = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
    const hasRelay = urlsList.some((u) => String(u).startsWith('turn:') || String(u).startsWith('turns:'));
    if (hasRelay && (!entry.username || !entry.credential)) return true;
    return false;
  });

  if (invalidRows.length > 0) {
    console.error('========================================');
    console.error('FATAL: ICE configuration invalid (missing urls or relay credentials).');
    console.error('Check TURN_STUN_URL, TURN_UDP_URL, TURN_TCP_URL, TURN_TLSTCP_URL, TURN_USERNAME, TURN_CREDENTIAL.');
    console.error('========================================');
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
  }

  if (logConfig) {
    console.log('✅ ICE config loaded (default path — home first, no public Google STUN):');
    console.log('   STUN (home):', turnStunUrl || '(missing)');
    console.log('   TURN UDP:', turnUdpUrl || '(missing)');
    console.log('   TURN TCP:', turnTcpUrl || '(missing)');
    console.log('   TURNS TCP:', turnTlsTcpUrl || '(missing)');
    console.log('   TURN username present:', !!turnUsername);
    console.log('   TURN credential present:', !!turnCredential);
    console.log(
      '   Cloudflare API (per connection):',
      (process.env.CLOUDFLARE_TURN_KEY_ID || '').trim() && (process.env.CLOUDFLARE_TURN_KEY_API_TOKEN || '').trim()
        ? 'enabled when keys set'
        : '(not configured)',
    );
  }

  return iceServers;
}
function mintTurnCredentials(ttlSeconds = 86400) {
  const secret = process.env.TURN_SECRET;
  if (!secret) {
    return {
      username: process.env.TURN_USERNAME || null,
      credential: process.env.TURN_CREDENTIAL || null,
    };
  }
  const expiry = Math.floor(Date.now() / 1000) + ttlSeconds;
  const username = `${expiry}:screenshare`;
  const credential = crypto
    .createHmac('sha256', secret)
    .update(username)
    .digest('base64');
  return { username, credential };
}
const ICE_SERVERS = buildIceServers();
if (process.env.NODE_ENV !== 'production') {
  void (async () => {
    const cf = await fetchCloudflareIceServers();
    const merged = [...ICE_SERVERS, ...cf];
    console.log(
      '[ICE][dev] merged iceServers preview (home → Cloudflare, credentials redacted):',
      merged.map((entry) => ({
        urls: entry.urls,
        username: entry.username ? '(set)' : undefined,
        credential: entry.credential ? '(set)' : undefined,
      })),
    );
  })();
}
const isProduction = process.env.NODE_ENV === 'production';
const hasTurn = ICE_SERVERS.some((s) =>
  (Array.isArray(s.urls) ? s.urls : [s.urls])
    .some((u) => String(u).startsWith('turn:') || String(u).startsWith('turns:'))
);
if (isProduction && !hasTurn) {
  console.error('FATAL: Production mode requires TURN server. Set TURN env vars (Railway) or .env.turn/.env.trun credentials.');
  process.exit(1);
}

function safeJsonSize(raw) {
  try {
    return Buffer.byteLength(raw);
  } catch {
    return MAX_MESSAGE_BYTES + 1;
  }
}

function asNonEmptyString(v, maxLen = 200) {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (!t) return null;
  if (t.length > maxLen) return null;
  return t;
}

function asToken(v) {
  const t = asNonEmptyString(v, 200);
  if (!t) return null;
  return t;
}

function isOpen(ws) {
  return ws && ws.readyState === 1; // WebSocket.OPEN
}

function isLocalHost(hostHeader) {
  const h = (hostHeader || '').toLowerCase();
  return h.startsWith('localhost') || h.startsWith('127.0.0.1') || h.startsWith('[::1]');
}

function isOriginAllowed(origin) {
  if (!origin) return true; // Electron/Node ws clients omit Origin; allow when absent.
  if (ALLOWED_ORIGINS.length === 0) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

function extractWsConnectToken(req) {
  try {
    const parsed = new URL(req.url || '/', 'ws://127.0.0.1');
    const fromQuery = parsed.searchParams.get('token');
    if (fromQuery && String(fromQuery).trim()) return String(fromQuery).trim();
  } catch {
    // ignore parse failures; header fallback below
  }
  const fromHeader = req.headers['x-ws-token'];
  if (Array.isArray(fromHeader)) return fromHeader[0] ? String(fromHeader[0]).trim() : null;
  if (typeof fromHeader === 'string' && fromHeader.trim()) return fromHeader.trim();
  return null;
}

function signIngestToken(payload) {
  if (!INGEST_TOKEN_SECRET) return null;
  const exp = Date.now() + INGEST_TOKEN_TTL_MS;
  const body = Buffer.from(JSON.stringify({ ...payload, exp }), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', INGEST_TOKEN_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyIngestToken(token) {
  if (!INGEST_TOKEN_SECRET) return { error: 'NO_SECRET' };
  if (!token || typeof token !== 'string') return { error: 'MISSING_TOKEN' };
  
  const parts = token.split('.');
  if (parts.length !== 2) return { error: 'INVALID_PARTS', len: parts.length };
  
  const [body, sig] = parts;
  const expected = crypto.createHmac('sha256', INGEST_TOKEN_SECRET).update(body).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return { error: 'LENGTH_MISMATCH', sig: sigBuf.length, exp: expBuf.length };
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return { error: 'SIGNATURE_MISMATCH' };
  
  try {
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!parsed || typeof parsed !== 'object') return { error: 'NOT_OBJECT' };
    
    // Coerce to number because Postgres BIGINT ids are returned as strings by the pg plugin
    const clientId = Number(parsed.clientId);
    const orgId = Number(parsed.orgId);
    
    if (!Number.isFinite(clientId) || clientId <= 0) return { error: 'INVALID_CLIENT_ID', id: parsed.clientId };
    if (!Number.isFinite(orgId) || orgId <= 0) return { error: 'INVALID_ORG_ID', org: parsed.orgId };
    if (typeof parsed.exp !== 'number' || parsed.exp < Date.now()) return { error: 'EXPIRED', exp: parsed.exp, now: Date.now() };
    
    // Return coerced numbers to be safe downstream
    return { payload: { ...parsed, clientId, orgId } };
  } catch (err) {
    return { error: 'CATCH_ERROR', msg: err.message };
  }
}

class TokenBucket {
  constructor({ capacity, refillPerSec }) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.tokens = capacity;
    this.last = Date.now();
  }
  take(cost = 1) {
    const now = Date.now();
    const elapsed = (now - this.last) / 1000;
    this.last = now;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillPerSec);
    if (this.tokens < cost) return false;
    this.tokens -= cost;
    return true;
  }
}

class SignalingServer {
  constructor() {
    const wipeDb = process.env.SIGNALING_WIPE_DB === '1' || process.env.SIGNALING_WIPE_DB === 'true';
    if (wipeDb) console.log('⚠️  SIGNALING_WIPE_DB set — wiping database; bootstrap admin will seed only if enabled via env');
    this.db = new SignalingDatabase(undefined, { wipe: wipeDb });
    this.clients = new Map();     // socketId -> { ws, kind, client, admin, bucket, ip }
    this.ipCount = new Map();     // ip -> active connection count
    this.lastDeviceTakeoverAt = new Map(); // deviceId -> timestamp ms
    this.wss = null;
    this.httpServer = null;
    this.heartbeatTimer = null;
    this.pingTimer = null;
    this.sessionCleanupTimer = null;
    this.remoteAccessExpiryTimer = null;
    this.browserTabRetentionTimer = null;
    this.taskbarRetentionTimer = null;
    /** Latest browser-tab snapshot per client (used for fast live-only mode and in-memory fallback). */
    this.latestBrowserTabByClientId = new Map();
    /** adminSocketId -> Set<clientSocketId> — tear down client WebRTC when admin stops or disconnects */
    this.adminViewerLinks = new Map();
    /** client socket metadata (published screen sources) is held on each live connection. */
  }

  async start() {
    // Ensure DB is ready before accepting traffic.
    try {
      await this.db.resetAllOnStartup();
    } catch (err) {
      console.error('FATAL: DB resetAllOnStartup failed:', err?.message || err);
      process.exit(1);
    }

    this.httpServer = http.createServer((req, res) => {
      this._handleHttpRequest(req, res).catch((err) => {
        console.error('[HTTP API]', err?.message || err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'INTERNAL_ERROR', message: String(err?.message || err) }));
        }
      });
    });

    this.wss = new WebSocketServer({
      server: this.httpServer,
      verifyClient: (info, callback) => {
        const expected = process.env.WS_CONNECT_TOKEN;
        const provided = extractWsConnectToken(info.req);
        if (!expected || provided !== expected) {
          callback(false, 401, 'Unauthorized');
          return;
        }
        callback(true);
      },
    });
    this.wss.on('error', (err) => {
      console.error('❌ Signaling server error:', err?.message || err);
    });

    this.wss.on('connection', (ws, req) => {
      const origin = req.headers.origin;
      const host = req.headers.host || '';
      const forwardedProto = (req.headers['x-forwarded-proto'] || '').toLowerCase();

      if (!isOriginAllowed(origin)) {
        console.warn(`⛔ Connection rejected from disallowed origin: ${origin}`);
        ws.close(1008, 'Origin not allowed');
        return;
      }

      if (ENFORCE_TLS && !isLocalHost(host)) {
        const tlsOk = forwardedProto === 'https' || forwardedProto === 'wss';
        if (!tlsOk) {
          console.warn(`⛔ Connection rejected (TLS required). host=${host} proto=${forwardedProto || 'n/a'}`);
          ws.close(1008, 'TLS required');
          return;
        }
      }

      // ─── Connection limits ───
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
      if (this.clients.size >= MAX_CONNECTIONS) {
        console.warn(`⛔ Connection rejected (max ${MAX_CONNECTIONS} reached) from ${ip}`);
        ws.close(1013, 'Server at capacity');
        return;
      }
      const currentIpCount = this.ipCount.get(ip) || 0;
      if (currentIpCount >= MAX_PER_IP) {
        console.warn(`⛔ Connection rejected (max ${MAX_PER_IP}/IP reached) from ${ip}`);
        ws.close(1013, 'Too many connections from this IP');
        return;
      }
      this.ipCount.set(ip, currentIpCount + 1);

      const socketId = this._generateId();
      ws.isAlive = true;
      this.clients.set(socketId, {
        ws,
        kind: null,
        client: null,
        admin: null,
        bucket: new TokenBucket({ capacity: 60, refillPerSec: 30 }),
        ip,
        ipStatusSent: false,
        workstationIps: [],
        screenSources: [],
        screenSourcesSignature: '',
      });
      console.log(`🔌 New connection: ${socketId} (${ip}, total: ${this.clients.size})`);

      ws.on('pong', () => {
        ws.isAlive = true;
        const conn = this.clients.get(socketId);
        if (conn?.kind === 'client') {
          this.db.updateClientHeartbeat(socketId).catch(() => {});
        }
      });

      ws.on('message', (raw) => {
        ws.isAlive = true;
        if (safeJsonSize(raw) > MAX_MESSAGE_BYTES) {
          this._send(ws, { type: 'error', error: 'MESSAGE_TOO_LARGE', message: 'Message too large' });
          return;
        }
        try {
          const msg = JSON.parse(raw.toString());
          void this._handleMessage(socketId, ws, msg).catch((err) => {
            console.error('[WS message handler]', err?.message || err);
            try {
              this._send(ws, { type: 'error', error: 'INTERNAL_ERROR', message: 'Server error' });
            } catch {
              /* ignore */
            }
          });
        } catch (err) {
          const preview = (() => {
            try {
              return raw.toString().slice(0, 300);
            } catch {
              return '<unprintable>';
            }
          })();
          console.error(`❌ Invalid message from ${socketId}:`, err.message, 'raw_preview=', preview);
          this._send(ws, { type: 'error', error: 'INVALID_MESSAGE', message: 'Could not parse message' });
        }
      });

      ws.on('close', () => {
        void this._handleDisconnect(socketId);
      });

      ws.on('error', (err) => {
        console.error(`❌ WebSocket error for ${socketId}:`, err.message);
      });

      // Send welcome with socket ID + WebRTC ICE config (home lab + optional Cloudflare API iceServers).
      void (async () => {
        try {
          const { username, credential } = mintTurnCredentials(86400);
          const homeIceServers = buildIceServers(username, credential, false);
          const cloudflareIceServers = await fetchCloudflareIceServers();
          const iceServersForPeer = [...homeIceServers, ...cloudflareIceServers];
          this._send(ws, { type: 'welcome', socketId: socketId, iceServers: iceServersForPeer });
        } catch (err) {
          console.warn('[welcome] ICE merge failed, sending home-only:', err?.message || err);
          const { username, credential } = mintTurnCredentials(86400);
          const homeIceServers = buildIceServers(username, credential, false);
          this._send(ws, { type: 'welcome', socketId: socketId, iceServers: homeIceServers });
        }
      })();
    });

    this.httpServer.listen(PORT, () => {
      console.log(`✅ Signaling server (HTTP + WebSocket) on port ${PORT}`);
    });
    this.httpServer.on('error', (err) => {
      if (err?.code === 'EADDRINUSE') {
        console.error('[signaling] Port 8085 already in use. Kill existing process:');
        console.error('  Windows: netstat -ano | findstr :8085  then  taskkill /PID <pid> /F');
        console.error('  Mac/Linux: lsof -ti:8085 | xargs kill -9');
        process.exit(1);
      }
      console.error('❌ HTTP server error:', err?.message || err);
    });

    this.pingTimer = setInterval(() => this._transportPing(), WS_PING_INTERVAL_MS);
    this.heartbeatTimer = setInterval(() => { void this._checkHeartbeats(); }, HEARTBEAT_CHECK_MS);

    // Periodic session cleanup (expired tokens)
    this.sessionCleanupTimer = setInterval(() => {
      this.db.purgeExpiredSessions().catch((err) => {
        console.error('Session cleanup error:', err?.message || err);
      });
    }, SESSION_CLEANUP_INTERVAL);

    this.remoteAccessExpiryTimer = setInterval(() => {
      this.db.expireRemoteAccessRequests().catch((err) => {
        console.error('Remote access expiry error:', err?.message || err);
      });
      this.db.expireStreamRelayRequests().catch((err) => {
        console.error('Stream relay expiry error:', err?.message || err);
      });
    }, 5 * 60 * 1000);

    // Extension / BrowserScope tab snapshots: keep only recent rows in `browser_tab_events` (see BROWSER_TAB_RETENTION_DAYS).
    void this.db.purgeBrowserTabEventsExpired().catch((err) => {
      console.error('Browser tab retention (startup):', err?.message || err);
    });
    this.browserTabRetentionTimer = setInterval(() => {
      void this.db.purgeBrowserTabEventsExpired().catch((err) => {
        console.error('Browser tab retention:', err?.message || err);
      });
    }, BROWSER_TAB_RETENTION_INTERVAL_MS);

    // Taskbar / open-app events: same rolling retention by ingest time (see TASKBAR_RETENTION_DAYS).
    void this.db.purgeTaskbarEventsExpired().catch((err) => {
      console.error('Taskbar retention (startup):', err?.message || err);
    });
    this.taskbarRetentionTimer = setInterval(() => {
      void this.db.purgeTaskbarEventsExpired().catch((err) => {
        console.error('Taskbar retention:', err?.message || err);
      });
    }, TASKBAR_RETENTION_INTERVAL_MS);

    // Crash protection:
    // - Dev: keep alive for iteration.
    // - Prod: crash so the supervisor (Railway/systemd/pm2) can restart cleanly.
    process.on('uncaughtException', (err) => {
      console.error('🔥 UNCAUGHT EXCEPTION:', err);
      if (isProduction) process.exit(1);
    });
    process.on('unhandledRejection', (err) => {
      console.error('🔥 UNHANDLED REJECTION:', err);
      if (isProduction) process.exit(1);
    });

    // Graceful shutdown
    process.on('SIGINT', () => {
      this.httpServer.close(() => { void this.shutdown(); });
    });
    process.on('SIGTERM', () => {
      this.httpServer.close(() => { void this.shutdown(); });
    });
  }

  async _readHttpBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      req.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_HTTP_BODY_BYTES) {
          reject(new Error('PAYLOAD_TOO_LARGE'));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  _httpJson(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(body);
  }

  _broadcastCallEventsToAdmins(clientId, count, lastEvent) {
    // Fire-and-forget async; WS broadcast doesn't need to block request handler.
    void (async () => {
      const client = await this.db.getClientById(clientId);
      if (!client) return;
      for (const [, conn] of this.clients) {
        if (conn.kind !== 'admin' || !isOpen(conn.ws)) continue;
        const role = conn.admin?.role;
        const adminOrgId = conn.admin?.orgId;
        const interested =
          role === 'super_admin' ||
          role === 'it_ops' ||
          (role === 'org_admin' && adminOrgId === client.org_id);
        if (!interested) continue;
        this._send(conn.ws, {
          type: 'call-events-update',
          success: true,
          clientId,
          accepted: count,
          clientName: client.full_name || null,
          eventType: lastEvent?.type || null,
          platform: lastEvent?.platform || null,
        });
      }
    })().catch(() => {});
  }

  _broadcastTaskbarEventsToAdmins(clientId, count, latestOpenApps) {
    void (async () => {
      const client = await this.db.getClientById(clientId);
      if (!client) return;
      for (const [, conn] of this.clients) {
        if (conn.kind !== 'admin' || !isOpen(conn.ws)) continue;
        const role = conn.admin?.role;
        const adminOrgId = conn.admin?.orgId;
        const interested =
          role === 'super_admin' ||
          role === 'it_ops' ||
          (role === 'org_admin' && adminOrgId === client.org_id);
        if (!interested) continue;
        this._send(conn.ws, {
          type: 'taskbar-events-update',
          success: true,
          clientId,
          accepted: count,
          openApps: latestOpenApps || [],
        });
      }
    })().catch(() => {});
  }

  _broadcastBrowserTabEventsToAdmins(clientId, count, latestTabs, activeTabId, browserName, recentInteractions) {
    void (async () => {
      const client = await this.db.getClientById(clientId);
      if (!client) return;
      const ri = Array.isArray(recentInteractions) ? recentInteractions : [];
      for (const [, conn] of this.clients) {
        if (conn.kind !== 'admin' || !isOpen(conn.ws)) continue;
        const role = conn.admin?.role;
        const adminOrgId = conn.admin?.orgId;
        const interested =
          role === 'super_admin' ||
          role === 'it_ops' ||
          (role === 'org_admin' && adminOrgId === client.org_id);
        if (!interested) continue;
        this._send(conn.ws, {
          type: 'browser-tab-events-update',
          success: true,
          clientId,
          accepted: count,
          browserName: browserName || 'Chromium',
          activeTabId: activeTabId ?? null,
          tabs: latestTabs || [],
          recentInteractions: ri,
        });
      }
    })().catch(() => {});
  }

  async _httpPostCallEvents(req, res) {
    const auth = asToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    const ingest = verifyIngestToken(auth);
    // If ingest token auth fails, optionally allow a strict local-dev fallback.
    // Production should set INGEST_TOKEN_SECRET and keep this disabled.

    let raw;
    try {
      raw = await this._readHttpBody(req);
    } catch (err) {
      if (err.message === 'PAYLOAD_TOO_LARGE') {
        this._httpJson(res, 413, { error: 'PAYLOAD_TOO_LARGE' });
        return;
      }
      throw err;
    }

    let body;
    try {
      body = JSON.parse(raw.length ? raw.toString('utf8') : '{}');
    } catch {
      this._httpJson(res, 400, { error: 'INVALID_JSON' });
      return;
    }

    // Authenticated path (recommended / default).
    if (ingest && ingest.payload) {
    const clientId = ingest.payload.clientId;
    const clientRow = await this.db.getClientById(clientId);
      if (!clientRow || clientRow.disabled) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Unknown or disabled client' });
        return;
      }
      if (Number(clientRow.org_id) !== ingest.payload.orgId) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Token/org mismatch' });
        return;
      }
      body.__resolvedClientId = clientId;
    } else if (ALLOW_CALL_EVENTS_WITHOUT_TOKEN) {
      const deviceId = asNonEmptyString(body?.deviceId, 200);
      if (!deviceId) {
        this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: 'Missing ingest token (dev fallback requires deviceId)' });
        return;
      }
      const clientId = await this.db.getClientIdByDeviceId(deviceId);
      if (!clientId) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Unknown or disabled client (deviceId not enrolled)' });
        return;
      }
      body.__resolvedClientId = clientId;
    } else {
      console.log('[Ingest] Call Events: Token Verification Failed', ingest);
      const hint = !INGEST_TOKEN_SECRET
        ? 'Server is missing INGEST_TOKEN_SECRET. Set it (Railway env) to enable call-event ingest tokens.'
        : `Invalid or expired ingest token: ${JSON.stringify(ingest || {})}`;
      this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: hint });
      return;
    }

    const clientId = Number(body.__resolvedClientId);
    if (!Number.isFinite(clientId) || clientId <= 0) {
      this._httpJson(res, 500, { error: 'SERVER_ERROR', message: 'Resolved clientId missing' });
      return;
    }

    const events = body.events;
    if (!Array.isArray(events) || events.length === 0) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'events must be a non-empty array' });
      return;
    }
    if (events.length > 100) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'At most 100 events per request' });
      return;
    }

    const receivedAtMs = Date.now();
    const rows = [];
    try {
      for (const e of events) {
        const t = asNonEmptyString(e?.type, 32);
        if (!['call_start', 'call_end'].includes(t)) {
          throw new Error(`Invalid type: ${e?.type}`);
        }
        const platform = asNonEmptyString(e?.platform, 120);
        if (!platform) throw new Error('platform required');
        const tsRaw = asNonEmptyString(e?.timestamp, 80);
        if (!tsRaw) throw new Error('timestamp required');
        const tms = Date.parse(tsRaw);
        if (!Number.isFinite(tms)) throw new Error('timestamp must be ISO-8601');
        const occurredAtIso = new Date(tms).toISOString();
        let durationMs = null;
        if (e.duration_ms != null) {
          const d = Number(e.duration_ms);
          if (!Number.isFinite(d) || d < 0 || d > 24 * 60 * 60 * 1000) {
            throw new Error('duration_ms invalid');
          }
          durationMs = Math.round(d);
        }
        rows.push({
          clientId,
          type: t,
          platform,
          occurredAtIso,
          durationMs,
          receivedAtMs,
        });
      }
    } catch (err) {
      this._httpJson(res, 400, { error: 'VALIDATION_ERROR', message: err.message });
      return;
    }

    const accepted = await this.db.insertCallEvents(rows);
    // Pass the last event so admins get type/platform for toast notifications.
    const lastEvent = rows.length > 0 ? rows[rows.length - 1] : null;
    console.log(`[Received from Client ---] Call events: ${accepted} event(s) ingested for clientId=${clientId} | lastType=${lastEvent?.type || 'n/a'} | platform=${lastEvent?.platform || 'n/a'}`);
    this._broadcastCallEventsToAdmins(clientId, accepted, lastEvent);
    this._httpJson(res, 200, { ok: true, accepted });
  }

  async _httpPostTaskbarEvents(req, res) {
    if (!ENABLE_APP_ACTIVITY_TELEMETRY) {
      // Drain request body for keep-alive correctness, then no-op.
      try { await this._readHttpBody(req); } catch {}
      this._httpJson(res, 200, { ok: true, accepted: 0, disabled: true });
      return;
    }
    const auth = asToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    const ingest = verifyIngestToken(auth);

    let raw;
    try {
      raw = await this._readHttpBody(req);
    } catch (err) {
      if (err.message === 'PAYLOAD_TOO_LARGE') {
        this._httpJson(res, 413, { error: 'PAYLOAD_TOO_LARGE' });
        return;
      }
      throw err;
    }

    let body;
    try {
      body = JSON.parse(raw.length ? raw.toString('utf8') : '{}');
    } catch {
      this._httpJson(res, 400, { error: 'INVALID_JSON' });
      return;
    }

    if (ingest && ingest.payload) {
      const clientId = ingest.payload.clientId;
    const clientRow = await this.db.getClientById(clientId);
      if (!clientRow || clientRow.disabled) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Unknown or disabled client' });
        return;
      }
      if (Number(clientRow.org_id) !== ingest.payload.orgId) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Token/org mismatch' });
        return;
      }
      body.__resolvedClientId = clientId;
    } else if (ALLOW_CALL_EVENTS_WITHOUT_TOKEN) {
      const deviceId = asNonEmptyString(body?.deviceId, 200);
      if (!deviceId) {
        this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: 'Missing ingest token (dev fallback requires deviceId)' });
        return;
      }
      const clientId = await this.db.getClientIdByDeviceId(deviceId);
      if (!clientId) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Unknown or disabled client (deviceId not enrolled)' });
        return;
      }
      body.__resolvedClientId = clientId;
    } else {
      console.log('[Ingest] Taskbar Events: Token Verification Failed', ingest);
      const hint = !INGEST_TOKEN_SECRET
        ? 'Server is missing INGEST_TOKEN_SECRET. Set it (Railway env) to enable ingest tokens.'
        : `Invalid or expired ingest token: ${JSON.stringify(ingest || {})}`;
      this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: hint });
      return;
    }

    const clientId = Number(body.__resolvedClientId);
    if (!Number.isFinite(clientId) || clientId <= 0) {
      this._httpJson(res, 500, { error: 'SERVER_ERROR', message: 'Resolved clientId missing' });
      return;
    }

    const events = body.events;
    if (!Array.isArray(events) || events.length === 0) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'events must be a non-empty array' });
      return;
    }
    if (events.length > 100) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'At most 100 events per request' });
      return;
    }

    const receivedAtMs = Date.now();
    const rows = [];

    const normalizeApp = (v) => {
      if (!v || typeof v !== 'object') return null;
      const processName = asNonEmptyString(v.processName ?? v.process_name ?? v.name, 200);
      const windowTitle = asNonEmptyString(v.windowTitle ?? v.window_title, 400) || '';
      const pidRaw = Number(v.processId ?? v.process_id ?? v.pid);
      const processId = Number.isFinite(pidRaw) && pidRaw >= 0 && pidRaw <= 2_147_483_647 ? Math.round(pidRaw) : null;
      if (!processName && !windowTitle) return null;
      return { processName: processName || '(unknown)', windowTitle, processId };
    };

    try {
      for (const e of events) {
        const tsRaw = asNonEmptyString(e?.timestamp, 80);
        if (!tsRaw) throw new Error('timestamp required');
        const tms = Date.parse(tsRaw);
        if (!Number.isFinite(tms)) throw new Error('timestamp must be ISO-8601');
        const occurredAtIso = new Date(tms).toISOString();

        const openedRaw = Array.isArray(e?.opened) ? e.opened : [];
        const closedRaw = Array.isArray(e?.closed) ? e.closed : [];
        const openAppsRaw = Array.isArray(e?.openApps ?? e?.open_apps) ? (e.openApps ?? e.open_apps) : [];

        const opened = openedRaw.map(normalizeApp).filter(Boolean).slice(0, 50);
        const closed = closedRaw.map(normalizeApp).filter(Boolean).slice(0, 50);
        const openApps = openAppsRaw.map(normalizeApp).filter(Boolean).slice(0, 50);

        rows.push({
          clientId,
          occurredAtIso,
          receivedAtMs,
          openedJson: JSON.stringify(opened),
          closedJson: JSON.stringify(closed),
          openAppsJson: JSON.stringify(openApps),
        });
      }
    } catch (err) {
      this._httpJson(res, 400, { error: 'VALIDATION_ERROR', message: err.message });
      return;
    }

    const accepted = await this.db.insertTaskbarEvents(rows);
    const latestOpenApps = rows.length > 0 ? JSON.parse(rows[rows.length - 1].openAppsJson) : [];
    console.log(`[Received from Client ---] Taskbar events: ${accepted} event(s) ingested for clientId=${clientId} | openApps=${latestOpenApps.length}`);
    // Pass the latest openApps snapshot to broadcast so admins get live data inline (no HTTP roundtrip needed).
    this._broadcastTaskbarEventsToAdmins(clientId, accepted, latestOpenApps);
    this._httpJson(res, 200, { ok: true, accepted });
  }

  async _httpGetTaskbarEvents(req, res) {
    if (!ENABLE_APP_ACTIVITY_TELEMETRY) {
      this._httpJson(res, 200, { success: true, events: [], page: 1, limit: 0, hasMore: false, disabled: true });
      return;
    }
    const auth = asToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!auth) {
      this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: 'Bearer admin session token required' });
      return;
    }
    const admin = await this.db.getAdminBySessionToken(auth);
    if (!admin) {
      this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Invalid or expired session' });
      return;
    }

    const accessTb = await this._checkAdminSensitiveHttpAccess(req, admin);
    if (!accessTb.allowed) {
      this._httpJson(res, 403, {
        error: 'ACCESS_RESTRICTED',
        code: 'NOT_IN_OFFICE',
        message: 'Office network or approved remote access required for this data.',
        adminIp: accessTb.adminIp,
      });
      return;
    }

    let pathname;
    let searchParams;
    try {
      const u = new URL(req.url || '/', 'http://127.0.0.1');
      pathname = u.pathname;
      searchParams = u.searchParams;
    } catch {
      this._httpJson(res, 400, { error: 'BAD_REQUEST' });
      return;
    }
    if (pathname !== '/api/taskbar-events') {
      this._httpJson(res, 404, { error: 'NOT_FOUND' });
      return;
    }

    const clientIdRaw = searchParams.get('clientId');
    const clientId = clientIdRaw != null && clientIdRaw !== '' ? Number(clientIdRaw) : null;
    if (clientId != null && !Number.isFinite(clientId)) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'clientId must be a number' });
      return;
    }

    if (admin.role === 'org_admin' && clientId != null) {
      const row = await this.db.getClientById(clientId);
      if (!row || row.org_id !== admin.org_id) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Client not in your organization' });
        return;
      }
    }

    const features = await this.db.getAdminUiFeatures();
    if (admin.role === 'org_admin' && !features.member_call_detection) {
      this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Taskbar activity is disabled for team leads' });
      return;
    }

    const page = Number(searchParams.get('page') || '1');
    const limit = Number(searchParams.get('limit') || '50');
    const rows = await this.db.listTaskbarEventsForAdmin({
      adminRole: admin.role,
      adminOrgId: admin.org_id,
      clientId,
      page,
      limit,
    });

    const parseJson = (text) => {
      try {
        const arr = JSON.parse(text || '[]');
        return Array.isArray(arr) ? arr : [];
      } catch {
        return [];
      }
    };

    const events = rows.map((r) => ({
      id: r.id,
      clientId: r.clientId,
      timestamp: r.timestamp,
      opened: parseJson(r.openedJson),
      closed: parseJson(r.closedJson),
      openApps: parseJson(r.openAppsJson),
      receivedAt: r.receivedAt,
    }));

    this._httpJson(res, 200, {
      success: true,
      events,
      page: Number.isFinite(page) && page > 0 ? page : 1,
      limit: Number.isFinite(limit) ? limit : 50,
      hasMore: events.length === (Number.isFinite(limit) ? Math.min(Math.max(limit, 1), 200) : 50),
    });
  }

  async _httpPostBrowserTabEvents(req, res) {
    if (!ENABLE_APP_ACTIVITY_TELEMETRY) {
      // Drain request body for keep-alive correctness, then no-op.
      try { await this._readHttpBody(req); } catch {}
      this._httpJson(res, 200, { ok: true, accepted: 0, disabled: true });
      return;
    }
    const auth = asToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    const ingest = verifyIngestToken(auth);

    let raw;
    try {
      raw = await this._readHttpBody(req);
    } catch (err) {
      if (err.message === 'PAYLOAD_TOO_LARGE') {
        this._httpJson(res, 413, { error: 'PAYLOAD_TOO_LARGE' });
        return;
      }
      throw err;
    }

    let body;
    try {
      body = JSON.parse(raw.length ? raw.toString('utf8') : '{}');
    } catch {
      this._httpJson(res, 400, { error: 'INVALID_JSON' });
      return;
    }

    if (ingest && ingest.payload) {
      const clientId = ingest.payload.clientId;
      const clientRow = await this.db.getClientById(clientId);
      if (!clientRow || clientRow.disabled) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Unknown or disabled client' });
        return;
      }
      if (Number(clientRow.org_id) !== ingest.payload.orgId) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Token/org mismatch' });
        return;
      }
      body.__resolvedClientId = clientId;
    } else if (ALLOW_CALL_EVENTS_WITHOUT_TOKEN) {
      const deviceId = asNonEmptyString(body?.deviceId, 200);
      if (!deviceId) {
        this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: 'Missing ingest token (dev fallback requires deviceId)' });
        return;
      }
      const clientId = await this.db.getClientIdByDeviceId(deviceId);
      if (!clientId) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Unknown or disabled client (deviceId not enrolled)' });
        return;
      }
      body.__resolvedClientId = clientId;
    } else {
      console.log('[Ingest] Browser Tab Events: Token Verification Failed', ingest);
      const hint = !INGEST_TOKEN_SECRET
        ? 'Server is missing INGEST_TOKEN_SECRET. Set it (Railway env) to enable ingest tokens.'
        : `Invalid or expired ingest token: ${JSON.stringify(ingest || {})}`;
      this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: hint });
      return;
    }

    const clientId = Number(body.__resolvedClientId);
    if (!Number.isFinite(clientId) || clientId <= 0) {
      this._httpJson(res, 500, { error: 'SERVER_ERROR', message: 'Resolved clientId missing' });
      return;
    }

    const events = body.events;
    if (!Array.isArray(events) || events.length === 0) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'events must be a non-empty array' });
      return;
    }
    if (events.length > 100) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'At most 100 events per request' });
      return;
    }

    const receivedAtMs = Date.now();
    const rows = [];

    const normalizeTab = (v) => {
      if (!v || typeof v !== 'object') return null;
      const title = asNonEmptyString(v.title, 600) || '';
      const url = asNonEmptyString(v.url, 3000) || '';
      const domain = asNonEmptyString(v.domain, 300) || '';
      const favIconUrl = asNonEmptyString(v.favIconUrl ?? v.fav_icon_url, 3000) || '';
      const tabIdRaw = Number(v.tabId ?? v.tab_id);
      const windowIdRaw = Number(v.windowId ?? v.window_id);
      const activeMsRaw = Number(v.activeMs ?? v.active_ms ?? 0);
      const foregroundMsRaw = Number(v.foregroundMs ?? v.foreground_ms ?? 0);
      const switchCountRaw = Number(v.switchCount ?? v.switch_count ?? 0);
      const createdMsRaw = Number(v.createdMs ?? v.created_ms ?? Date.now());
      const lastSeenMsRaw = Number(v.lastSeenMs ?? v.last_seen_ms ?? Date.now());
      const lastActiveMsRaw = Number(v.lastActiveMs ?? v.last_active_ms ?? 0);
      const tabId = Number.isFinite(tabIdRaw) ? Math.round(tabIdRaw) : null;
      const windowId = Number.isFinite(windowIdRaw) ? Math.round(windowIdRaw) : null;
      const activeMs = Number.isFinite(activeMsRaw) && activeMsRaw >= 0 ? Math.min(Math.round(activeMsRaw), 31_536_000_000) : 0;
      const foregroundMs = Number.isFinite(foregroundMsRaw) && foregroundMsRaw >= 0 ? Math.min(Math.round(foregroundMsRaw), 31_536_000_000) : 0;
      const switchCount = Number.isFinite(switchCountRaw) && switchCountRaw >= 0 ? Math.min(Math.round(switchCountRaw), 1_000_000_000) : 0;
      const createdMs = Number.isFinite(createdMsRaw) ? Math.round(createdMsRaw) : Date.now();
      const lastSeenMs = Number.isFinite(lastSeenMsRaw) ? Math.round(lastSeenMsRaw) : Date.now();
      const lastActiveMs = Number.isFinite(lastActiveMsRaw) ? Math.round(lastActiveMsRaw) : 0;
      const isActive = v.isActive === true;
      const isPinned = v.isPinned === true;
      const isAudible = v.isAudible === true;
      const isMuted = v.isMuted === true;
      if (!title && !url && !domain) return null;
      const dwellIdleMsRaw = Number(v.dwellIdleMs ?? v.dwell_idle_ms ?? 0);
      const keystrokesRaw = Number(v.keystrokes ?? 0);
      const scrollPxRaw = Number(v.scrollPx ?? v.scroll_px ?? 0);
      const mousePxRaw = Number(v.mousePx ?? v.mouse_px ?? 0);
      const clicksRaw = Number(v.clicks ?? 0);
      const out = { tabId, windowId, title, url, domain, favIconUrl, isPinned, isAudible, isMuted, isActive, activeMs, foregroundMs, switchCount, createdMs, lastSeenMs, lastActiveMs };
      if (Number.isFinite(dwellIdleMsRaw) && dwellIdleMsRaw >= 0) out.dwellIdleMs = Math.min(Math.round(dwellIdleMsRaw), 31_536_000_000);
      if (Number.isFinite(keystrokesRaw) && keystrokesRaw >= 0) out.keystrokes = Math.min(Math.round(keystrokesRaw), 1_000_000_000);
      if (Number.isFinite(scrollPxRaw) && scrollPxRaw >= 0) out.scrollPx = Math.round(scrollPxRaw);
      if (Number.isFinite(mousePxRaw) && mousePxRaw >= 0) out.mousePx = Math.round(mousePxRaw);
      if (Number.isFinite(clicksRaw) && clicksRaw >= 0) out.clicks = Math.min(Math.round(clicksRaw), 1_000_000_000);
      return out;
    };

    try {
      for (const e of events) {
        const tsRaw = asNonEmptyString(e?.timestamp, 80);
        if (!tsRaw) throw new Error('timestamp required');
        const tms = Date.parse(tsRaw);
        if (!Number.isFinite(tms)) throw new Error('timestamp must be ISO-8601');
        const occurredAtIso = new Date(tms).toISOString();

        const browserName = asNonEmptyString(e?.browserName ?? e?.browser_name, 120) || 'Chromium';
        const activeTabIdRaw = Number(e?.activeTabId ?? e?.active_tab_id);
        const activeTabId = Number.isFinite(activeTabIdRaw) ? Math.round(activeTabIdRaw) : null;
        const reason = asNonEmptyString(e?.reason, 80) || 'update';
        let session = e?.session && typeof e.session === 'object' ? { ...e.session } : {};
        const riTop = Array.isArray(e?.recentInteractions) ? e.recentInteractions : Array.isArray(e?.recent_interactions) ? e.recent_interactions : null;
        if (riTop && riTop.length > 0) {
          const trimmed = [];
          for (const x of riTop.slice(0, 80)) {
            if (!x || typeof x !== 'object') continue;
            const o = x;
            const ts = Number(o.ts);
            // Keep full interaction text for audit detail view; cap high to avoid unbounded payloads.
            const detail = typeof o.detail === 'string' ? o.detail.slice(0, 20000) : '';
            const eventType = typeof o.eventType === 'string' ? o.eventType.slice(0, 128) : typeof o.event_type === 'string' ? o.event_type.slice(0, 128) : 'unknown';
            const tabIdRaw = o.tabId ?? o.tab_id;
            const tabId = Number.isFinite(Number(tabIdRaw)) ? Math.round(Number(tabIdRaw)) : null;
            const url = typeof o.url === 'string' ? o.url.slice(0, 1200) : '';
            const title = typeof o.title === 'string' ? o.title.slice(0, 400) : '';
            if (Number.isFinite(ts) && ts > 0) trimmed.push({ ts, eventType, tabId, detail, url, title });
          }
          session = { ...session, recentInteractions: trimmed };
        }
        const switchLogRaw = Array.isArray(e?.switchLog ?? e?.switch_log) ? (e.switchLog ?? e.switch_log) : [];
        const tabsRaw = Array.isArray(e?.tabs) ? e.tabs : [];
        const tabs = tabsRaw.map(normalizeTab).filter(Boolean).slice(0, 200);
        const switchLog = switchLogRaw
          .filter((s) => s && typeof s === 'object')
          .slice(-250)
          .map((s) => ({
            atMs: Number.isFinite(Number(s.atMs ?? s.at_ms)) ? Math.round(Number(s.atMs ?? s.at_ms)) : Date.now(),
            fromTabId: Number.isFinite(Number(s.fromTabId ?? s.from_tab_id)) ? Math.round(Number(s.fromTabId ?? s.from_tab_id)) : null,
            toTabId: Number.isFinite(Number(s.toTabId ?? s.to_tab_id)) ? Math.round(Number(s.toTabId ?? s.to_tab_id)) : null,
            reason: asNonEmptyString(s.reason, 80) || 'switch',
          }));

        rows.push({
          clientId,
          occurredAtIso,
          receivedAtMs,
          browserName,
          activeTabId,
          reason,
          sessionJson: JSON.stringify(Object.keys(session).length ? session : {}),
          switchLogJson: JSON.stringify(switchLog),
          tabsJson: JSON.stringify(tabs),
        });
      }
    } catch (err) {
      this._httpJson(res, 400, { error: 'VALIDATION_ERROR', message: err.message });
      return;
    }

    const latestTabs = rows.length > 0 ? JSON.parse(rows[rows.length - 1].tabsJson) : [];
    const latestActiveTabId = rows.length > 0 ? rows[rows.length - 1].activeTabId : null;
    const latestBrowser = rows.length > 0 ? rows[rows.length - 1].browserName : 'Chromium';
    let latestSession = {};
    let latestRecentInteractions = [];
    if (rows.length > 0) {
      try {
        const lastSess = JSON.parse(rows[rows.length - 1].sessionJson || '{}');
        latestSession = lastSess && typeof lastSess === 'object' ? lastSess : {};
        if (Array.isArray(lastSess.recentInteractions)) latestRecentInteractions = lastSess.recentInteractions;
      } catch {
        latestSession = {};
      }
    }
    const latestOccurredAt = rows.length > 0 ? rows[rows.length - 1].occurredAtIso : new Date(receivedAtMs).toISOString();
    const latestReason = rows.length > 0 ? rows[rows.length - 1].reason : 'update';
    const latestSnapshot = {
      id: 0,
      clientId,
      timestamp: latestOccurredAt,
      receivedAt: new Date(receivedAtMs).toISOString(),
      browserName: latestBrowser,
      activeTabId: latestActiveTabId,
      reason: latestReason,
      session: latestSession,
      switchLog: rows.length > 0 ? JSON.parse(rows[rows.length - 1].switchLogJson || '[]') : [],
      tabs: latestTabs,
    };
    this.latestBrowserTabByClientId.set(clientId, latestSnapshot);

    // Fast path: broadcast immediately so admin UI updates are not delayed by DB writes.
    this._broadcastBrowserTabEventsToAdmins(clientId, rows.length, latestTabs, latestActiveTabId, latestBrowser, latestRecentInteractions);

    let accepted = rows.length;
    if (BROWSER_TAB_PERSIST_TO_DB) {
      accepted = await this.db.insertBrowserTabEvents(rows);
    }
    console.log(
      `[Received from Client ---] Browser tab events: ${accepted} event(s) ${BROWSER_TAB_PERSIST_TO_DB ? 'persisted' : 'live-only'} for clientId=${clientId} | tabs=${latestTabs.length}`,
    );
    this._httpJson(res, 200, { ok: true, accepted, persisted: BROWSER_TAB_PERSIST_TO_DB });
  }

  async _httpGetBrowserTabEvents(req, res) {
    if (!ENABLE_APP_ACTIVITY_TELEMETRY) {
      this._httpJson(res, 200, { success: true, events: [], page: 1, limit: 0, hasMore: false, disabled: true });
      return;
    }
    const auth = asToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!auth) {
      this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: 'Bearer admin session token required' });
      return;
    }
    const admin = await this.db.getAdminBySessionToken(auth);
    if (!admin) {
      this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Invalid or expired session' });
      return;
    }

    const accessBr = await this._checkAdminSensitiveHttpAccess(req, admin);
    if (!accessBr.allowed) {
      this._httpJson(res, 403, {
        error: 'ACCESS_RESTRICTED',
        code: 'NOT_IN_OFFICE',
        message: 'Office network or approved remote access required for this data.',
        adminIp: accessBr.adminIp,
      });
      return;
    }

    let pathname;
    let searchParams;
    try {
      const u = new URL(req.url || '/', 'http://127.0.0.1');
      pathname = u.pathname;
      searchParams = u.searchParams;
    } catch {
      this._httpJson(res, 400, { error: 'BAD_REQUEST' });
      return;
    }
    if (pathname !== '/api/browser-tab-events') {
      this._httpJson(res, 404, { error: 'NOT_FOUND' });
      return;
    }

    const clientIdRaw = searchParams.get('clientId');
    const clientId = clientIdRaw != null && clientIdRaw !== '' ? Number(clientIdRaw) : null;
    if (clientId != null && !Number.isFinite(clientId)) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'clientId must be a number' });
      return;
    }

    if (admin.role === 'org_admin' && clientId != null) {
      const row = await this.db.getClientById(clientId);
      if (!row || row.org_id !== admin.org_id) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Client not in your organization' });
        return;
      }
    }

    const features = await this.db.getAdminUiFeatures();
    if (admin.role === 'org_admin' && !features.member_call_detection) {
      this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Browser tab activity is disabled for team leads' });
      return;
    }

    const page = Number(searchParams.get('page') || '1');
    const limit = Number(searchParams.get('limit') || '50');
    const sinceRaw = searchParams.get('sinceReceivedAt');
    const sinceReceivedAtMs =
      sinceRaw != null && sinceRaw !== '' ? Number(sinceRaw) : null;
    if (sinceReceivedAtMs != null && !Number.isFinite(sinceReceivedAtMs)) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'sinceReceivedAt must be a number (epoch ms)' });
      return;
    }

    if (!BROWSER_TAB_PERSIST_TO_DB) {
      if (clientId == null) {
        this._httpJson(res, 200, {
          success: true,
          events: [],
          page: 1,
          limit: 0,
          hasMore: false,
          liveOnly: true,
        });
        return;
      }
      const snap = this.latestBrowserTabByClientId.get(clientId);
      this._httpJson(res, 200, {
        success: true,
        events: snap ? [snap] : [],
        page: 1,
        limit: 1,
        hasMore: false,
        liveOnly: true,
      });
      return;
    }

    const rows = await this.db.listBrowserTabEventsForAdmin({
      adminRole: admin.role,
      adminOrgId: admin.org_id,
      clientId,
      page,
      limit,
      sinceReceivedAtMs,
    });

    const parseJson = (text) => {
      try {
        const arr = JSON.parse(text || '[]');
        return Array.isArray(arr) ? arr : [];
      } catch {
        return [];
      }
    };

    const events = rows.map((r) => ({
      id: r.id,
      clientId: r.clientId,
      timestamp: r.timestamp,
      receivedAt: r.receivedAt,
      browserName: r.browserName,
      activeTabId: r.activeTabId,
      reason: r.reason,
      session: parseJson(r.sessionJson),
      switchLog: parseJson(r.switchLogJson),
      tabs: parseJson(r.tabsJson),
    }));

    const limCap =
      sinceReceivedAtMs != null && Number.isFinite(sinceReceivedAtMs) ? 4000 : 200;
    const effectiveLimit = Number.isFinite(limit) ? Math.min(Math.max(limit, 1), limCap) : Math.min(50, limCap);
    this._httpJson(res, 200, {
      success: true,
      events,
      page: Number.isFinite(page) && page > 0 ? page : 1,
      limit: effectiveLimit,
      hasMore: events.length >= effectiveLimit,
    });
  }

  async _httpGetCallEvents(req, res) {
    const auth = asToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!auth) {
      this._httpJson(res, 401, { error: 'UNAUTHORIZED', message: 'Bearer admin session token required' });
      return;
    }
    const admin = await this.db.getAdminBySessionToken(auth);
    if (!admin) {
      this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Invalid or expired session' });
      return;
    }

    const accessCall = await this._checkAdminSensitiveHttpAccess(req, admin);
    if (!accessCall.allowed) {
      this._httpJson(res, 403, {
        error: 'ACCESS_RESTRICTED',
        code: 'NOT_IN_OFFICE',
        message: 'Office network or approved remote access required for this data.',
        adminIp: accessCall.adminIp,
      });
      return;
    }

    let pathname;
    let searchParams;
    try {
      const u = new URL(req.url || '/', 'http://127.0.0.1');
      pathname = u.pathname;
      searchParams = u.searchParams;
    } catch {
      this._httpJson(res, 400, { error: 'BAD_REQUEST' });
      return;
    }
    if (pathname !== '/api/call-events') {
      this._httpJson(res, 404, { error: 'NOT_FOUND' });
      return;
    }

    const clientIdRaw = searchParams.get('clientId');
    const clientId = clientIdRaw != null && clientIdRaw !== '' ? Number(clientIdRaw) : null;
    if (clientId != null && !Number.isFinite(clientId)) {
      this._httpJson(res, 400, { error: 'INVALID_INPUT', message: 'clientId must be a number' });
      return;
    }

    if (admin.role === 'org_admin' && clientId != null) {
      const row = await this.db.getClientById(clientId);
      if (!row || row.org_id !== admin.org_id) {
        this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Client not in your organization' });
        return;
      }
    }

    const features = await this.db.getAdminUiFeatures();
    if (admin.role === 'org_admin' && !features.member_call_detection) {
      this._httpJson(res, 403, { error: 'FORBIDDEN', message: 'Call detection is disabled for team leads' });
      return;
    }

    const page = Number(searchParams.get('page') || '1');
    const limit = Number(searchParams.get('limit') || '50');
    const events = await this.db.listCallEventsForAdmin({
      adminRole: admin.role,
      adminOrgId: admin.org_id,
      clientId,
      page,
      limit,
    });

    this._httpJson(res, 200, {
      success: true,
      events,
      page: Number.isFinite(page) && page > 0 ? page : 1,
      limit: Number.isFinite(limit) ? limit : 50,
      hasMore: events.length === (Number.isFinite(limit) ? Math.min(Math.max(limit, 1), 200) : 50),
    });
  }

  async _handleHttpRequest(req, res) {
    const host = req.headers.host || '';
    const proto = (req.headers['x-forwarded-proto'] || '').toLowerCase();
    const origin = req.headers.origin;

    if (!isOriginAllowed(origin)) {
      this._httpJson(res, 403, { error: 'FORBIDDEN_ORIGIN', message: 'Origin not allowed' });
      return;
    }

    if (ENFORCE_TLS && !isLocalHost(host)) {
      if (proto !== 'https') {
        this._httpJson(res, 400, { error: 'TLS_REQUIRED', message: 'HTTPS is required for HTTP API calls' });
        return;
      }
    }

    let pathname;
    try {
      pathname = new URL(req.url || '/', 'http://127.0.0.1').pathname;
    } catch {
      this._httpJson(res, 400, { error: 'BAD_REQUEST' });
      return;
    }

    if (req.method === 'GET' && (pathname === '/' || pathname === '/health')) {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: true, service: 'anywhere-signaling' }));
      return;
    }

    if (req.method === 'POST' && pathname === '/api/call-events') {
      await this._httpPostCallEvents(req, res);
      return;
    }
    if (req.method === 'GET' && pathname === '/api/call-events') {
      await this._httpGetCallEvents(req, res);
      return;
    }
    if (req.method === 'POST' && pathname === '/api/taskbar-events') {
      await this._httpPostTaskbarEvents(req, res);
      return;
    }
    if (req.method === 'GET' && pathname === '/api/taskbar-events') {
      await this._httpGetTaskbarEvents(req, res);
      return;
    }
    if (req.method === 'POST' && pathname === '/api/browser-tab-events') {
      await this._httpPostBrowserTabEvents(req, res);
      return;
    }
    if (req.method === 'GET' && pathname === '/api/browser-tab-events') {
      await this._httpGetBrowserTabEvents(req, res);
      return;
    }

    this._httpJson(res, 404, { error: 'NOT_FOUND' });
  }

  async _handleMessage(socketId, ws, msg) {
    const conn = this.clients.get(socketId);
    if (!conn) return;

    const type = asNonEmptyString(msg?.type, 64);
    // Heartbeats must never be dropped by rate limiting (keeps client rows accurate).
    if (type !== 'heartbeat' && !conn.bucket.take(1)) {
      this._send(ws, { type: 'error', error: 'RATE_LIMITED', message: 'Too many messages' });
      return;
    }

    if (!type) {
      this._send(ws, { type: 'error', error: 'INVALID_TYPE', message: 'Missing message type' });
      return;
    }

    switch (type) {
      // ─── Public (no auth): org names for login / enrollment pickers ───
      case 'public-list-orgs':
        await this._handlePublicListOrgs(ws);
        return;

      // ─── New auth protocol ───
      case 'client-auth':
        await this._handleClientAuth(socketId, ws, msg);
        return;
      case 'admin-register':
        await this._handleAdminRegister(socketId, ws, msg);
        return;
      case 'admin-login':
        await this._handleAdminLogin(socketId, ws, msg);
        return;
      case 'admin-logout':
        await this._handleAdminLogout(socketId, ws, msg);
        return;
      case 'admin-get-orgs':
        await this._handleAdminGetOrgs(socketId, ws, msg);
        return;
      case 'admin-get-org-leads':
        await this._handleAdminGetOrgLeads(socketId, ws, msg);
        return;
      case 'admin-get-clients':
        await this._handleAdminGetClients(socketId, ws, msg);
        return;
      case 'admin-get-org-summaries':
        await this._handleAdminGetOrgSummaries(socketId, ws, msg);
        return;
      case 'admin-get-transfer-requests':
        await this._handleAdminGetTransferRequests(socketId, ws, msg);
        return;
      case 'admin-create-transfer-request':
        await this._handleAdminCreateTransferRequest(socketId, ws, msg);
        return;
      case 'admin-respond-transfer-request':
        await this._handleAdminRespondTransferRequest(socketId, ws, msg);
        return;
      case 'admin-update-client-org':
        await this._handleAdminUpdateClientOrg(socketId, ws, msg);
        return;
      case 'admin-remove-client':
        await this._handleAdminRemoveClient(socketId, ws, msg);
        return;
      case 'admin-get-ui-features':
        await this._handleAdminGetUiFeatures(socketId, ws, msg);
        return;
      case 'admin-set-ui-features':
        await this._handleAdminSetUiFeatures(socketId, ws, msg);
        return;

      // ─── Audit dashboard (super-admin proxy over WS; server forwards to audit HTTP) ───
      case 'admin-audit-org-access-list':
        await auditOrgAccessProxy.handleList(this, socketId, ws, msg);
        return;
      case 'admin-audit-org-access-review':
        await auditOrgAccessProxy.handleReview(this, socketId, ws, msg);
        return;

      // ─── WebRTC relay ───
      case 'offer':
      case 'answer':
      case 'ice-candidate':
      case 'client-ready':
      case 'request-offer':
      case 'enable-client-media':
      case 'client-screen-sources':
        await this._relaySignaling(socketId, msg);
        return;
      case 'ice-path-report':
        await this._handleIcePathReport(socketId, ws, msg);
        return;

      case 'remote-access-request':
        await this._handleRemoteAccessRequest(socketId, ws, msg);
        return;
      case 'approve-remote-access':
        await this._handleApproveRemoteAccess(socketId, ws, msg);
        return;
      case 'deny-remote-access':
        await this._handleDenyRemoteAccess(socketId, ws, msg);
        return;
      case 'get-my-remote-access-requests':
        await this._handleGetMyRemoteAccessRequests(socketId, ws, msg);
        return;
      case 'get-pending-remote-access-requests':
        await this._handleGetPendingRemoteAccessRequests(socketId, ws, msg);
        return;

      case 'stream-relay-request':
        await this._handleStreamRelayRequest(socketId, ws, msg);
        return;
      case 'approve-stream-relay':
        await this._handleApproveStreamRelay(socketId, ws, msg);
        return;
      case 'deny-stream-relay':
        await this._handleDenyStreamRelay(socketId, ws, msg);
        return;
      case 'get-my-stream-relay-requests':
        await this._handleGetMyStreamRelayRequests(socketId, ws, msg);
        return;
      case 'get-pending-stream-relay-requests':
        await this._handleGetPendingStreamRelayRequests(socketId, ws, msg);
        return;
      case 'get-active-stream-relay':
        await this._handleGetActiveStreamRelay(socketId, ws, msg);
        return;

      // ─── Liveness ───
      case 'heartbeat':
        await this.db.updateClientHeartbeat(socketId);
        this._send(ws, { type: 'heartbeat-ack' });
        return;

      // ─── Backward compat (legacy clients/admin) ───
      case 'register':
        await this._handleLegacyRegister(socketId, ws, msg);
        return;
      case 'get-clients':
        await this._handleLegacyGetClients(socketId, ws);
        return;
      case 'query-client':
        await this._handleLegacyQueryClient(socketId, ws, msg);
        return;
      case 'connect-to-client':
        // If token provided, treat as v2 admin connect; otherwise legacy.
        if (msg && msg.token) {
          this._handleAdminConnectToClient(socketId, ws, msg);
        } else {
          await this._handleLegacyConnectToClient(socketId, ws, msg);
        }
        return;
      case 'admin-stop-viewing':
        void this._handleAdminStopViewing(socketId, ws, msg);
        return;
      case 'admin-focus-client-app':
        void this._handleAdminFocusClientApp(socketId, ws, msg);
        return;
      case 'start-sharing':
      case 'stop-sharing':
        // No-op in v2 (clients are treated as sharing after auth).
        return;

      case 'disconnect':
        void this._handleDisconnect(socketId);
        return;

      default:
        this._send(ws, { type: 'error', error: 'UNKNOWN_TYPE', message: `Unknown message type: ${type}` });
    }
  }

  async _handlePublicListOrgs(ws) {
    const orgs = await this.db.getOrganizationsWithAdmins();
    this._send(ws, { type: 'public-list-orgs-response', success: true, orgs });
  }

  // ─── Client auth (v2) ───
  async _handleClientAuth(socketId, ws, msg) {
    const deviceId = asNonEmptyString(msg.deviceId, 200);
    const orgName = asNonEmptyString(msg.orgName, 200);
    const fullName = asNonEmptyString(msg.fullName, 200);
    if (!deviceId || !orgName || !fullName) {
      console.warn('[ClientAuth] Rejected: missing fields', {
        hasDeviceId: !!deviceId,
        orgNameLen: orgName ? orgName.length : 0,
        fullNameLen: fullName ? fullName.length : 0,
      });
      this._send(ws, { type: 'client-auth-response', success: false, error: 'INVALID_INPUT', message: 'deviceId, orgName, fullName required' });
      return;
    }

    const prevSocketId = await this.db.getSocketIdForDevice(deviceId);

    // If a device is already connected, avoid rapid "takeover fights" that cause storms.
    if (prevSocketId && prevSocketId !== socketId) {
      const oldConn = this.clients.get(prevSocketId);
      const now = Date.now();
      const last = this.lastDeviceTakeoverAt.get(deviceId) || 0;
      const recentlyTookOver = now - last < DEVICE_TAKEOVER_COOLDOWN_MS;

      if (oldConn?.ws && isOpen(oldConn.ws) && recentlyTookOver) {
        this._send(ws, {
          type: 'client-auth-response',
          success: false,
          error: 'DUPLICATE_DEVICE',
          message: 'Device is already connected (duplicate instance detected). Close the other instance and retry.',
        });
        try {
          ws.close(4001, 'Duplicate device connection');
        } catch {
          /* ignore */
        }
        return;
      }
      // Allow takeover, but remember the moment so we can suppress rapid ping-pong.
      this.lastDeviceTakeoverAt.set(deviceId, now);
    }

    const res = await this.db.upsertClientAuth({ deviceId, orgName, fullName, socketId });
    if (!res.success) {
      this._send(ws, { type: 'client-auth-response', success: false, error: res.error, message: res.message });
      return;
    }

    const conn = this.clients.get(socketId);
    if (conn) {
      conn.kind = 'client';
      conn.client = { id: res.client.id, orgId: res.client.org_id, fullName: res.client.full_name, deviceId };
      conn.admin = null;
    }
    const ingestToken = signIngestToken({ clientId: res.client.id, orgId: res.client.org_id });
    if (!ingestToken) {
      console.error('[ClientAuth] Could not mint ingest token. Set INGEST_TOKEN_SECRET.');
    }

    this._send(ws, {
      type: 'client-auth-response',
      success: true,
      client: { id: res.client.id, orgId: res.client.org_id, fullName: res.client.full_name, status: res.client.status },
      ingestToken,
    });

    if (prevSocketId && prevSocketId !== socketId) {
      const oldConn = this.clients.get(prevSocketId);
      if (oldConn?.ws && isOpen(oldConn.ws)) {
        console.log(`🔁 Closing duplicate client socket ${prevSocketId} (device reconnected as ${socketId})`);
        try {
          oldConn.ws.close(4000, 'Replaced by new connection');
        } catch {
          /* ignore */
        }
      }
    }

    void this._broadcastClientsListToAdmins(res.client.org_id);
    if (res.extraBroadcastOrgId != null) {
      void this._broadcastClientsListToAdmins(res.extraBroadcastOrgId);
    }
  }

  // ─── Admin register/login (v2) ───
  async _handleAdminRegister(socketId, ws, msg) {
    const orgName = asNonEmptyString(msg.orgName, 200);
    const username = asNonEmptyString(msg.username, 200);
    const fullName = asNonEmptyString(msg.fullName, 200);
    const password = asNonEmptyString(msg.password, 500);
    const requestedRole = msg.role == null ? 'org_admin' : asNonEmptyString(msg.role, 32);

    if (!orgName || !username || !fullName || !password) {
      this._send(ws, { type: 'admin-register-response', success: false, error: 'INVALID_INPUT', message: 'Missing required fields' });
      return;
    }

    // Only a logged-in super-admin may create accounts (no anonymous / bootstrap registration).
    const token = asToken(msg.token);
    const actor = token ? await this.db.getAdminBySessionToken(token) : null;
    if (!actor || actor.role !== 'super_admin') {
      this._send(ws, { type: 'admin-register-response', success: false, error: 'UNAUTHORIZED', message: 'Super-admin token required' });
      return;
    }

    const org = await this.db.ensureOrganization(orgName);
    const role = ['org_admin', 'it_ops'].includes(requestedRole) ? requestedRole : 'org_admin';
    const created = await this.db.createAdmin({ orgId: org.id, username, fullName, password, role });
    if (!created.success) {
      this._send(ws, { type: 'admin-register-response', success: false, error: created.error, message: created.message });
      return;
    }
    this._send(ws, { type: 'admin-register-response', success: true, role, org: { id: org.id, name: org.name } });
  }

  async _handleAdminLogin(socketId, ws, msg) {
    const orgName = asNonEmptyString(msg.orgName, 200);
    const username = asNonEmptyString(msg.username, 200);
    const password = asNonEmptyString(msg.password, 500);
    if (!orgName || !username || !password) {
      this._send(ws, { type: 'admin-login-response', success: false, error: 'INVALID_INPUT', message: 'Missing required fields' });
      return;
    }

    const org = await this.db.getOrganizationByName(orgName);
    if (!org) {
      this._send(ws, { type: 'admin-login-response', success: false, error: 'UNKNOWN_ORG', message: 'Unknown organization' });
      return;
    }
    const admin = await this.db.getAdminByOrgAndUsername(org.id, username);
    if (!admin || !this.db.verifyAdminPassword(admin, password)) {
      this._send(ws, { type: 'admin-login-response', success: false, error: 'INVALID_CREDENTIALS', message: 'Invalid credentials' });
      return;
    }

    const session = await this.db.createAdminSession(admin.id);
    const conn = this.clients.get(socketId);
    if (conn) {
      conn.kind = 'admin';
      conn.admin = { adminId: admin.id, orgId: admin.org_id, username: admin.username, fullName: admin.full_name, role: admin.role, token: session.token };
      conn.client = null;
      conn.ipStatusSent = false;
      conn.workstationIps = parseWorkstationIps(msg.workstationIps);
    }

    this._send(ws, {
      type: 'admin-login-response',
      success: true,
      token: session.token,
      expiresAt: session.expiresAt,
      admin: { id: admin.id, orgId: admin.org_id, username: admin.username, fullName: admin.full_name, role: admin.role },
      org: { id: org.id, name: org.name },
      adminUiFeatures: await this.db.getAdminUiFeatures(),
    });
    this._maybeSendAdminIpStatus(socketId, {
      admin_id: admin.id,
      org_id: admin.org_id,
      role: admin.role,
      username: admin.username,
    });
  }

  async _handleAdminLogout(socketId, ws, msg) {
    const token = asToken(msg.token);
    if (token) {
      await this.db.revokeAdminSession(token);
    }
    const conn = this.clients.get(socketId);
    if (conn) {
      conn.admin = null;
      if (!conn.client) conn.kind = 'unknown';
    }
    this._send(ws, { type: 'admin-logout-response', success: true });
  }

  async _requireAdmin(socketId, ws, msg) {
    const token = asToken(msg.token);
    if (!token) {
      this._send(ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Missing session token' });
      return null;
    }
    const admin = await this.db.getAdminBySessionToken(token);
    if (!admin) {
      this._send(ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Invalid or expired session' });
      return null;
    }
    // Auto-tag connection with admin identity (critical for reconnection and relay auth)
    const conn = this.clients.get(socketId);
    if (conn && conn.kind !== 'admin') {
      conn.kind = 'admin';
      conn.admin = {
        adminId: admin.admin_id,
        orgId: admin.org_id,
        username: admin.username,
        fullName: admin.full_name,
        role: admin.role,
        token,
      };
      conn.client = null;
      console.log(`🔑 Connection ${socketId} tagged as admin (${admin.role}:${admin.username})`);
    }
    const extraIps = parseWorkstationIps(msg.workstationIps);
    if (conn && extraIps.length) {
      conn.workstationIps = extraIps;
    }
    this._maybeSendAdminIpStatus(socketId, admin);
    return admin;
  }

  async _handleAdminGetOrgs(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    // super_admin, org_admin, and it_ops can list orgs (it_ops for ops dashboard).
    if (admin.role !== 'super_admin' && admin.role !== 'org_admin' && admin.role !== 'it_ops') {
      this._send(ws, { type: 'admin-get-orgs-response', success: false, error: 'FORBIDDEN', message: 'Forbidden' });
      return;
    }
    let orgs = await this.db.getOrganizations();
    if (admin.role === 'org_admin') {
      orgs = orgs.filter((o) => o.id === admin.org_id);
    }
    this._send(ws, { type: 'admin-get-orgs-response', success: true, orgs });
  }

  async _handleAdminGetClients(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;

    // super_admin can query any org by orgId; org_admin restricted.
    let targetOrgId = admin.org_id;
    if (admin.role === 'super_admin' && msg.orgId != null) {
      const asNum = Number(msg.orgId);
      if (Number.isFinite(asNum)) targetOrgId = asNum;
    }

    let rows = [];
    if (admin.role === 'it_ops') {
      // IT-Ops: full overview of all orgs and their clients (for ops dashboard).
      if (msg.orgId == null) {
        rows = await this.db.getAllClientsGrouped();
      } else {
        const requestedOrgId = Number(msg.orgId);
        if (Number.isFinite(requestedOrgId)) rows = await this.db.getClientsForOrg(requestedOrgId);
        else rows = await this.db.getClientsForOrg(targetOrgId);
      }
    } else if (admin.role === 'super_admin' && msg.orgId == null) {
      rows = await this.db.getAllClientsGrouped();
    } else {
      rows = await this.db.getClientsForOrg(targetOrgId);
    }

    const clients = rows.map((c) => this._mapAdminClientRow(c));

    this._send(ws, { type: 'admin-get-clients-response', success: true, clients, orgId: targetOrgId });
  }

  async _handleAdminGetOrgSummaries(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    // Team leads need all org names/counts for transfer targets; other roles use the same summary list.
    const orgs = await this.db.getOrganizationSummaries();
    this._send(ws, { type: 'admin-get-org-summaries-response', success: true, orgs });
  }

  async _handleAdminGetOrgLeads(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;

    if (admin.role !== 'super_admin' && admin.role !== 'org_admin' && admin.role !== 'it_ops') {
      this._send(ws, { type: 'admin-get-org-leads-response', success: false, error: 'FORBIDDEN', message: 'Forbidden' });
      return;
    }

    const orgId = admin.role === 'org_admin' ? admin.org_id : null;
    const leads = await this.db.getOrgLeads({ orgId });
    this._send(ws, { type: 'admin-get-org-leads-response', success: true, orgLeads: leads });
  }

  async _handleAdminGetTransferRequests(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    const requests = await this.db.listTransferRequests({ adminRole: admin.role, adminOrgId: admin.org_id });
    this._send(ws, { type: 'admin-get-transfer-requests-response', success: true, requests });
  }

  _broadcastTransferEvent(event) {
    const fromOrgId = event.fromOrgId;
    const toOrgId = event.toOrgId;
    for (const [, conn] of this.clients) {
      const isAdmin = conn.kind === 'admin';
      if (!isAdmin || !isOpen(conn.ws)) continue;
      const role = conn.admin?.role;
      const orgId = conn.admin?.orgId;
      const interested =
        role === 'super_admin' ||
        role === 'it_ops' ||
        (orgId != null && (orgId === fromOrgId || orgId === toOrgId));
      if (!interested) continue;
      this._send(conn.ws, { type: 'transfer-event', success: true, event });
    }
  }

  async _handleAdminCreateTransferRequest(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    // Team leads (org_admin) may request moves for clients in their org; super_admin for any client; IT-Ops is read-only.
    if (admin.role === 'it_ops') {
      this._send(ws, { type: 'admin-create-transfer-request-response', success: false, error: 'FORBIDDEN', message: 'Forbidden' });
      return;
    }

    const clientId = Number(msg.clientId);
    const toOrgId = Number(msg.toOrgId);
    if (!Number.isFinite(clientId) || !Number.isFinite(toOrgId)) {
      this._send(ws, { type: 'admin-create-transfer-request-response', success: false, error: 'INVALID_INPUT', message: 'clientId and toOrgId required' });
      return;
    }

    const client = await this.db.getClientById(clientId);
    if (!client || client.disabled) {
      this._send(ws, { type: 'admin-create-transfer-request-response', success: false, error: 'NOT_FOUND', message: 'Client not found' });
      return;
    }

    if (admin.role === 'org_admin' && client.org_id !== admin.org_id) {
      this._send(ws, { type: 'admin-create-transfer-request-response', success: false, error: 'FORBIDDEN', message: 'Client not in your organization' });
      return;
    }

    const uiFeatures = await this.db.getAdminUiFeatures();
    if (admin.role === 'org_admin' && !uiFeatures.transfer_tab) {
      this._send(ws, { type: 'admin-create-transfer-request-response', success: false, error: 'FORBIDDEN', message: 'Transfer workflow is disabled for team leads' });
      return;
    }

    const created = await this.db.createTransferRequest({
      clientId: client.id,
      fromOrgId: client.org_id,
      toOrgId,
      requestedByAdminId: admin.admin_id,
    });
    if (!created.success) {
      this._send(ws, { type: 'admin-create-transfer-request-response', success: false, error: created.error, message: created.message });
      return;
    }

    this._send(ws, { type: 'admin-create-transfer-request-response', success: true, requestId: created.requestId, deduped: !!created.deduped });

    const fromOrgName = (await this.db.getOrganizationNameById(client.org_id)) || `Org ${client.org_id}`;
    const toOrgName = (await this.db.getOrganizationNameById(toOrgId)) || `Org ${toOrgId}`;

    this._broadcastTransferEvent({
      kind: 'transfer-requested',
      requestId: created.requestId,
      clientId: client.id,
      clientName: client.full_name,
      fromOrgId: client.org_id,
      fromOrgName,
      toOrgId,
      toOrgName,
      status: 'pending',
      at: Date.now(),
    });
  }

  async _handleAdminRespondTransferRequest(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    if (admin.role === 'it_ops') {
      this._send(ws, { type: 'admin-respond-transfer-request-response', success: false, error: 'FORBIDDEN', message: 'Forbidden' });
      return;
    }

    const requestId = Number(msg.requestId);
    const action = asNonEmptyString(msg.action, 32);
    if (!Number.isFinite(requestId) || !action || !['approve', 'reject'].includes(action)) {
      this._send(ws, { type: 'admin-respond-transfer-request-response', success: false, error: 'INVALID_INPUT', message: 'requestId and action required' });
      return;
    }

    const req = await this.db.getTransferRequestById(requestId);
    if (!req) {
      this._send(ws, { type: 'admin-respond-transfer-request-response', success: false, error: 'NOT_FOUND', message: 'Request not found' });
      return;
    }
    if (req.status !== 'pending') {
      this._send(ws, { type: 'admin-respond-transfer-request-response', success: false, error: 'INVALID_STATE', message: 'Request already resolved' });
      return;
    }

    const canAct =
      admin.role === 'super_admin' ||
      (admin.role === 'org_admin' && admin.org_id === req.to_org_id);
    if (!canAct) {
      this._send(ws, { type: 'admin-respond-transfer-request-response', success: false, error: 'FORBIDDEN', message: 'Forbidden' });
      return;
    }

    const uiFeatures2 = await this.db.getAdminUiFeatures();
    if (admin.role === 'org_admin' && !uiFeatures2.transfer_tab) {
      this._send(ws, { type: 'admin-respond-transfer-request-response', success: false, error: 'FORBIDDEN', message: 'Transfer workflow is disabled for team leads' });
      return;
    }

    const nextStatus = action === 'approve' ? 'approved' : 'rejected';
    await this.db.updateTransferRequestStatus({ requestId, status: nextStatus, approvedByAdminId: admin.admin_id });
    if (nextStatus === 'approved') {
      // Apply immediately so the client appears under the new org/team across all dashboards.
      await this.db.setClientOrgNow(req.client_id, req.to_org_id);

      // If the client is currently connected, update in-memory orgId too
      // to keep signaling/authorization consistent.
      const clientConn = this._findClientConnectionByClientId(req.client_id);
      if (clientConn?.kind === 'client' && clientConn.client) {
        clientConn.client.orgId = req.to_org_id;
      }
    }

    this._send(ws, { type: 'admin-respond-transfer-request-response', success: true, requestId, status: nextStatus });

    const fromOrgName = (await this.db.getOrganizationNameById(req.from_org_id)) || `Org ${req.from_org_id}`;
    const toOrgName = (await this.db.getOrganizationNameById(req.to_org_id)) || `Org ${req.to_org_id}`;

    this._broadcastTransferEvent({
      kind: 'transfer-updated',
      requestId,
      clientId: req.client_id,
      clientName: req.client_full_name,
      fromOrgId: req.from_org_id,
      fromOrgName,
      toOrgId: req.to_org_id,
      toOrgName,
      status: nextStatus,
      byAdminId: admin.admin_id,
      byAdminName: admin.full_name,
      at: Date.now(),
    });
  }

  async _handleAdminUpdateClientOrg(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    if (admin.role !== 'super_admin') {
      this._send(ws, { type: 'admin-update-client-org-response', success: false, error: 'FORBIDDEN', message: 'Forbidden' });
      return;
    }
    const clientId = Number(msg.clientId);
    const orgId = Number(msg.orgId);
    if (!Number.isFinite(clientId) || !Number.isFinite(orgId)) {
      this._send(ws, { type: 'admin-update-client-org-response', success: false, error: 'INVALID_INPUT', message: 'clientId and orgId required' });
      return;
    }
    await this.db.setClientPendingOrg(clientId, orgId);
    this._send(ws, { type: 'admin-update-client-org-response', success: true, message: 'Client org will update on next login' });
  }

  async _handleAdminRemoveClient(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    if (admin.role !== 'super_admin' && admin.role !== 'org_admin') {
      this._send(ws, { type: 'admin-remove-client-response', success: false, error: 'FORBIDDEN', message: 'Forbidden' });
      return;
    }
    const clientId = Number(msg.clientId);
    if (!Number.isFinite(clientId)) {
      this._send(ws, { type: 'admin-remove-client-response', success: false, error: 'INVALID_INPUT', message: 'clientId required' });
      return;
    }
    const row = await this.db.getClientById(clientId);
    if (!row) {
      this._send(ws, { type: 'admin-remove-client-response', success: false, error: 'NOT_FOUND', message: 'Client not found' });
      return;
    }
    if (admin.role === 'org_admin') {
      if (row.org_id !== admin.org_id) {
        this._send(ws, { type: 'admin-remove-client-response', success: false, error: 'FORBIDDEN', message: 'Client not in your organization' });
        return;
      }
    }
    await this.db.disableClient(clientId);
    if (row.org_id) {
      void this._broadcastClientsListToAdmins(row.org_id);
    }
    // Force immediate logout on the client app side.
    if (row.socket_id) {
      const clientConn = this.clients.get(row.socket_id);
      if (clientConn && clientConn.kind === 'client' && isOpen(clientConn.ws)) {
        this._send(clientConn.ws, {
          type: 'client-auth-response',
          success: false,
          error: 'CLIENT_DISABLED',
          message: 'This device was removed by an administrator.',
        });
        this._send(clientConn.ws, {
          type: 'client-disabled',
          success: true,
          message: 'This device was removed by an administrator.',
        });
        try {
          clientConn.ws.close();
        } catch {
          /* ignore */
        }
      }
    }
    this._send(ws, { type: 'admin-remove-client-response', success: true });
  }

  async _broadcastAdminUiFeatures() {
    const features = await this.db.getAdminUiFeatures();
    for (const [, conn] of this.clients) {
      if (conn.kind !== 'admin' || !isOpen(conn.ws)) continue;
      this._send(conn.ws, { type: 'admin-ui-features-updated', success: true, adminUiFeatures: features });
    }
  }

  async _handleAdminGetUiFeatures(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    if (admin.role !== 'super_admin' && admin.role !== 'org_admin' && admin.role !== 'it_ops') {
      this._send(ws, { type: 'admin-get-ui-features-response', success: false, error: 'FORBIDDEN', message: 'Forbidden' });
      return;
    }
    this._send(ws, { type: 'admin-get-ui-features-response', success: true, adminUiFeatures: await this.db.getAdminUiFeatures() });
  }

  async _handleAdminSetUiFeatures(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    if (admin.role !== 'super_admin') {
      this._send(ws, { type: 'admin-set-ui-features-response', success: false, error: 'FORBIDDEN', message: 'Super-admin only' });
      return;
    }
    const patch = msg && typeof msg.features === 'object' && msg.features !== null ? msg.features : null;
    if (!patch) {
      this._send(ws, { type: 'admin-set-ui-features-response', success: false, error: 'INVALID_INPUT', message: 'features object required' });
      return;
    }
    const next = await this.db.setAdminUiFeaturesPatch(patch);
    this._send(ws, { type: 'admin-set-ui-features-response', success: true, adminUiFeatures: next });
    await this._broadcastAdminUiFeatures();
  }

  async _handleAdminConnectToClient(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;

    const access = await this._checkAdminSensitiveAccess(socketId, admin);
    if (!access.allowed) {
      this._send(ws, {
        type: 'access-restricted',
        code: 'NOT_IN_OFFICE',
        message: 'You are not connected to the office network.',
        adminIp: access.adminIp,
      });
      return;
    }

    // Allow selecting by clientId (preferred) or fullName.
    const clientId = msg.clientId != null ? Number(msg.clientId) : null;
    const clientFullName = clientId == null ? asNonEmptyString(msg.clientFullName, 200) : null;

    let client = null;
    if (clientId != null && Number.isFinite(clientId)) {
      // We need socket_id for the client; keep query internal.
      const row = await this.db.getClientById(clientId);
      client = row && !row.disabled ? row : null;
    } else if (clientFullName) {
      const row = await this.db.getClientByOrgAndFullName(admin.org_id, clientFullName);
      client = row && !row.disabled ? row : null;
    }

    if (!client || client.status === 'offline' || !client.socket_id) {
      this._send(ws, { type: 'connect-response', success: false, error: 'CLIENT_UNAVAILABLE', message: 'Client unavailable' });
      return;
    }

    // Stream policy gates disabled: allow any authenticated admin to connect to any online client.

    const clientConn = this.clients.get(client.socket_id);
    if (!clientConn || clientConn.kind !== 'client' || !isOpen(clientConn.ws)) {
      this._send(ws, { type: 'connect-response', success: false, error: 'CLIENT_UNAVAILABLE', message: 'Client connection not found' });
      return;
    }

    const sessionId = await this.db.createSession(client.org_id, client.id, admin.admin_id);
    if (!this.adminViewerLinks.has(socketId)) this.adminViewerLinks.set(socketId, new Set());
    this.adminViewerLinks.get(socketId).add(client.socket_id);
    this._send(clientConn.ws, {
      type: 'prepare-peer',
      agentName: admin.full_name,
      agentSocketId: socketId,
      sessionId,
    });
    this._send(ws, {
      type: 'start-offer',
      success: true,
      sessionId,
      clientId: client.id,
      clientFullName: client.full_name,
      clientSocketId: client.socket_id,
    });
    this._send(ws, {
      type: 'connect-response',
      success: true,
      message: `Connecting to "${client.full_name}"...`,
      sessionId,
      clientId: client.id,
      clientFullName: client.full_name,
      clientSocketId: client.socket_id,
    });
  }

  async _handleAdminStopViewing(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;
    const clientSocketId = asNonEmptyString(msg.clientSocketId, 200);
    if (!clientSocketId) {
      this._send(ws, { type: 'admin-stop-viewing-response', success: false, error: 'INVALID_INPUT', message: 'clientSocketId required' });
      return;
    }
    const set = this.adminViewerLinks.get(socketId);
    if (set) set.delete(clientSocketId);
    const clientConn = this.clients.get(clientSocketId);
    const adminConn = this.clients.get(socketId);
    const agentName = adminConn?.admin?.fullName || admin.full_name || 'Admin';
    if (clientConn && clientConn.kind === 'client' && isOpen(clientConn.ws)) {
      this._send(clientConn.ws, { type: 'agent-disconnected', agentSocketId: socketId, agentName });
    }
    this._send(ws, { type: 'admin-stop-viewing-response', success: true });
  }

  /**
   * Ask the member's desktop app to show and focus its window (e.g. user minimized it during share).
   * Only allowed while this admin socket has an active viewer link to that client (same as streaming).
   */
  async _handleAdminFocusClientApp(socketId, ws, msg) {
    const admin = await this._requireAdmin(socketId, ws, msg);
    if (!admin) return;

    const access = await this._checkAdminSensitiveAccess(socketId, admin);
    if (!access.allowed) {
      this._send(ws, {
        type: 'access-restricted',
        code: 'NOT_IN_OFFICE',
        message: 'You are not connected to the office network.',
        adminIp: access.adminIp,
      });
      return;
    }

    const clientId = msg.clientId != null ? Number(msg.clientId) : NaN;
    if (!Number.isFinite(clientId) || clientId <= 0) {
      this._send(ws, {
        type: 'admin-focus-client-app-response',
        success: false,
        error: 'INVALID_INPUT',
        message: 'clientId required',
      });
      return;
    }

    const row = await this.db.getClientById(clientId);
    const client = row && !row.disabled ? row : null;
    if (!client || client.status === 'offline' || !client.socket_id) {
      this._send(ws, {
        type: 'admin-focus-client-app-response',
        success: false,
        error: 'CLIENT_UNAVAILABLE',
        message: 'Client unavailable',
      });
      return;
    }

    const set = this.adminViewerLinks.get(socketId);
    if (!set || !set.has(client.socket_id)) {
      this._send(ws, {
        type: 'admin-focus-client-app-response',
        success: false,
        error: 'NOT_VIEWING',
        message: 'Open this member’s stream first, then use Bring to front.',
      });
      return;
    }

    const clientConn = this.clients.get(client.socket_id);
    if (!clientConn || clientConn.kind !== 'client' || !isOpen(clientConn.ws)) {
      this._send(ws, {
        type: 'admin-focus-client-app-response',
        success: false,
        error: 'CLIENT_UNAVAILABLE',
        message: 'Client connection not found',
      });
      return;
    }

    this._send(clientConn.ws, { type: 'focus-client-app' });
    this._send(ws, { type: 'admin-focus-client-app-response', success: true });
  }

  async _handleIcePathReport(socketId, ws, msg) {
    const conn = this.clients.get(socketId);
    const sessionIdRaw = Number(msg.sessionId);
    const clientIdFromConn = conn?.kind === 'client' && conn.client ? Number(conn.client.id) : null;
    const clientIdFromMsg = Number(msg.clientId);
    let resolvedClientId =
      Number.isFinite(clientIdFromConn) && clientIdFromConn > 0
        ? clientIdFromConn
        : Number.isFinite(clientIdFromMsg) && clientIdFromMsg > 0
          ? clientIdFromMsg
          : null;

    // Admin-side fallback: sometimes clientId is sent as fullName string.
    if (!resolvedClientId && conn?.kind === 'admin' && conn.admin) {
      const fullName = asNonEmptyString(msg.clientId, 200);
      if (fullName) {
        const clientRow = await this.db.getClientByOrgAndFullName(conn.admin.orgId, fullName);
        const cid = Number(clientRow?.id);
        if (Number.isFinite(cid) && cid > 0) resolvedClientId = cid;
      }
    }

    // Fallback for admin-side reports that may not carry numeric clientId:
    // resolve client_id from the active session itself.
    let row = null;
    if (Number.isFinite(sessionIdRaw) && sessionIdRaw > 0 && resolvedClientId) {
      row = await this.db.getViewingSessionForClient(sessionIdRaw, resolvedClientId);
    } else if (Number.isFinite(sessionIdRaw) && sessionIdRaw > 0) {
      row = await this.db.getViewingSessionById(sessionIdRaw);
      const cid = Number(row?.client_id);
      if (Number.isFinite(cid) && cid > 0) resolvedClientId = cid;
    } else if (resolvedClientId && conn?.kind === 'admin' && conn.admin?.adminId) {
      // Last-resort path for admin reports with no sessionId.
      row = await this.db.getLatestActiveViewingSession(conn.admin.adminId, resolvedClientId);
    }

    if (!row || !resolvedClientId) {
      return;
    }
    const orgId = conn?.client?.orgId ?? conn?.admin?.orgId ?? null;
    this.db.recordIcePathReport({
      socketId,
      orgId,
      candidateType: msg.candidateType,
      phase: msg.phase,
      clientId: resolvedClientId,
      sessionId: Number(row.id),
      rtt: msg.rtt,
      localType: msg.localType,
      remoteType: msg.remoteType,
      usingTurn: msg.usingTurn,
      timeToIceMs: msg.timeToIceMs,
      adminId: row.admin_id,
    }).catch(() => {});
    this._send(ws, { type: 'ice-path-report-ack', sessionId: Number(row.id), success: true });
  }

  // ─── Legacy handlers (keep existing dashboards running during transition) ───
  async _handleLegacyRegister(socketId, ws, msg) {
    const name = asNonEmptyString(msg.name, 200);
    const role = asNonEmptyString(msg.role, 32);
    if (!name || !role || !['client', 'agent'].includes(role)) {
      this._send(ws, { type: 'register-response', success: false, error: 'INVALID_INPUT', message: 'Invalid legacy register' });
      return;
    }
    const conn = this.clients.get(socketId);
    if (role === 'client') {
      // Map legacy client to default org with a pseudo device id derived from socket+name (not stable).
      const pseudoDevice = `legacy-${crypto.createHash('sha256').update(`${name}:${socketId}`).digest('hex').slice(0, 32)}`;
      const res = await this.db.upsertClientAuth({ deviceId: pseudoDevice, orgName: 'default', fullName: name, socketId });
      if (!res.success) {
        this._send(ws, { type: 'register-response', success: false, error: res.error, message: res.message });
        return;
      }
      if (conn) {
        conn.kind = 'client';
        conn.client = { id: res.client.id, orgId: res.client.org_id, fullName: res.client.full_name, deviceId: pseudoDevice };
      }
      this._send(ws, { type: 'register-response', success: true, name, role: 'client' });
      void this._broadcastClientsListToAdmins(res.client.org_id);
      return;
    }

    // Legacy agent: treat as unauthenticated admin in default org (limited).
    if (conn) {
      conn.kind = 'legacy_agent';
      conn.admin = { admin_id: null, org_id: null, username: name.toLowerCase(), full_name: name, role: 'legacy' };
    }
    this._send(ws, { type: 'register-response', success: true, name, role: 'agent' });
  }

  async _handleLegacyGetClients(socketId, ws) {
    // Old agents expect flat {name,status}. Provide default org clients.
    const conn = this.clients.get(socketId);
    if (!conn) return;
    const defaultOrg = await this.db.ensureOrganization('default');
    const clients = (await this.db.getClientsForOrg(defaultOrg.id))
      .map(c => ({ name: c.full_name, status: c.status }));
    this._send(ws, { type: 'clients-list', success: true, clients });
  }

  async _handleLegacyQueryClient(socketId, ws, msg) {
    const clientName = asNonEmptyString(msg.clientName, 200);
    if (!clientName) {
      this._send(ws, { type: 'query-response', success: false, error: 'INVALID_NAME', message: 'Client name is required' });
      return;
    }
    const orgId = (await this.db.ensureOrganization('default')).id;
    const client = await this.db.findOnlineClientByOrgAndFullName(orgId, clientName);
    if (!client) {
      this._send(ws, { type: 'query-response', success: false, error: 'NOT_FOUND', message: `Client "${clientName}" not found` });
      return;
    }
    this._send(ws, { type: 'query-response', success: true, client: { name: client.full_name, status: client.status } });
  }

  async _handleLegacyConnectToClient(socketId, ws, msg) {
    const clientName = asNonEmptyString(msg.clientName, 200);
    const agentName = asNonEmptyString(msg.agentName, 200) || 'legacy-agent';
    const orgId = (await this.db.ensureOrganization('default')).id;
    const client = await this.db.findOnlineClientByOrgAndFullName(orgId, clientName);
    if (!client || client.status === 'offline') {
      this._send(ws, { type: 'connect-response', success: false, error: 'CLIENT_UNAVAILABLE', message: 'Client unavailable' });
      return;
    }
    const clientConn = this._findClientConnectionByClientId(client.id);
    if (!clientConn) {
      this._send(ws, { type: 'connect-response', success: false, error: 'CLIENT_UNAVAILABLE', message: 'Client connection not found' });
      return;
    }
    const sessionId = await this.db.createSession(orgId, client.id, null);
    this._send(clientConn.ws, { type: 'agent-connect-request', agentName, agentSocketId: socketId, sessionId });
    this._send(ws, { type: 'connect-response', success: true, message: `Connecting to "${clientName}"...`, sessionId });
  }

  // ─── Relay WebRTC signaling messages ───
  async _relaySignaling(socketId, msg) {
    const { targetSocketId, targetName, ...payload } = msg;

    let target = null;
    const msgType = asNonEmptyString(payload?.type, 64);
    const fromConn = this.clients.get(socketId);
    if (msgType === 'client-screen-sources' && fromConn?.kind === 'client') {
      const list = Array.isArray(payload.sources) ? payload.sources : [];
      const mapped = list
        .filter((s) => s && typeof s === 'object')
        .map((s) => ({
          id: typeof s.id === 'string' ? s.id : '',
          name: typeof s.name === 'string' ? s.name : '',
          index: Number.isFinite(Number(s.index)) ? Math.trunc(Number(s.index)) : null,
        }))
        .filter((s) => s.id && s.name)
        .slice(0, 8);
      const sig = mapped.map((s) => `${s.index == null ? '' : s.index}:${s.id}`).join('|');
      const changed = fromConn.screenSourcesSignature !== sig;
      fromConn.screenSources = mapped;
      fromConn.screenSourcesSignature = sig;
      if (changed && fromConn.client?.orgId) {
        void this._broadcastClientsListToAdmins(fromConn.client.orgId);
      }
    }

    if (targetSocketId) {
      target = this.clients.get(targetSocketId);
    } else if (targetName) {
      // Find by name (for reconnection scenarios where socketId changed)
      target = this._findConnectionByName(targetName);
    }

    if (msgType === 'client-screen-sources' && !target) {
      return;
    }

    if (target && isOpen(target.ws)) {
      if (!fromConn) return;

      const fromClient = fromConn.kind === 'client' ? fromConn.client : null;
      const fromAdmin = fromConn.kind === 'admin' ? fromConn.admin : null;

      if (fromAdmin) {
        const adminRow = await this.db.getAdminBySessionToken(fromAdmin.token);
        if (!adminRow) {
          this._send(fromConn.ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Session invalid' });
          return;
        }
        const acc = await this._checkAdminSensitiveAccess(socketId, adminRow);
        if (!acc.allowed) {
          this._send(fromConn.ws, {
            type: 'access-restricted',
            code: 'NOT_IN_OFFICE',
            message: 'You are not connected to the office network.',
            adminIp: acc.adminIp,
          });
          return;
        }
      }
      const toClient = target.kind === 'client' ? target.client : null;
      const toAdmin = target.kind === 'admin' ? target.admin : null;

      // Stream policy gates disabled: permit relay once both peers are connected.

      // Streaming session gate disabled: allow WebRTC signaling flow once peers are authorized.

      const fromName = fromClient?.fullName || fromAdmin?.fullName || null;
      fromConn.signalSeq = (fromConn.signalSeq || 0) + 1;
      const relayPayload = {
        ...payload,
        seq: fromConn.signalSeq,
        timestamp: Date.now(),
        fromSocketId: socketId,
        fromName,
      };
      console.log(JSON.stringify({
        t: relayPayload.timestamp,
        type: relayPayload.type,
        from: socketId,
        to: targetSocketId || targetName || null,
        seq: relayPayload.seq,
        bytes: JSON.stringify(relayPayload).length,
      }));
      this._send(target.ws, relayPayload);
    } else {
      const conn = this.clients.get(socketId);
      if (conn) {
        this._send(conn.ws, {
          type: 'error',
          error: 'TARGET_UNAVAILABLE',
          message: 'Target peer is not available'
        });
      }
    }
  }

  // ─── Handle disconnect ───
  async _handleDisconnect(socketId) {
    const conn = this.clients.get(socketId);
    if (!conn) return;

    console.log(`🔌 Disconnected: ${socketId} (${conn.kind || 'unknown'})`);

    // Clean up IP tracking
    if (conn.ip) {
      const currentIpCount = this.ipCount.get(conn.ip) || 0;
      if (currentIpCount > 1) {
        this.ipCount.set(conn.ip, currentIpCount - 1);
      } else {
        this.ipCount.delete(conn.ip);
      }
    }

    if (conn.kind === 'client') {
      const client = await this.db.setClientOfflineBySocket(socketId);
      if (client) {
        void this._notifyAdminsOfClientEvent(client.org_id, client.full_name, 'client-disconnected');
        void this._broadcastClientsListToAdmins(client.org_id);
      }
    }

    if (conn.kind === 'admin') {
      const links = this.adminViewerLinks.get(socketId);
      if (links && links.size > 0) {
        const name = conn.admin?.fullName || 'Admin';
        for (const cid of links) {
          const cc = this.clients.get(cid);
          if (cc && cc.kind === 'client' && isOpen(cc.ws)) {
            this._send(cc.ws, { type: 'agent-disconnected', agentSocketId: socketId, agentName: name });
          }
        }
      }
      this.adminViewerLinks.delete(socketId);
    }

    this.clients.delete(socketId);
  }

  /** RFC 6455 ping/pong — survives reverse proxies that drop idle JSON-only sockets. */
  _transportPing() {
    for (const [socketId, conn] of this.clients) {
      const ws = conn.ws;
      if (!ws || !isOpen(ws)) continue;
      if (ws.isAlive === false) {
        console.warn(`💀 WebSocket ping timeout: ${socketId}`);
        try {
          ws.terminate();
        } catch {
          /* ignore */
        }
        continue;
      }
      ws.isAlive = false;
      try {
        ws.ping();
      } catch (err) {
        console.warn(`⚠️ ping failed for ${socketId}:`, err?.message || err);
      }
    }
  }

  async _checkHeartbeats() {
    try {
      const stale = await this.db.cleanupStaleClients(HEARTBEAT_TIMEOUT);
      if (stale.length > 0) {
        for (const client of stale) {
          console.log(`💀 Stale client detected: "${client.full_name}"`);

          // Close the stale WS if still open
          if (client.socket_id) {
            const conn = this.clients.get(client.socket_id);
            if (conn && isOpen(conn.ws)) {
              conn.ws.close();
            }
            this.clients.delete(client.socket_id);
          }

          void this._notifyAdminsOfClientEvent(client.org_id, client.full_name, 'client-disconnected');
        }
        // Broadcast per-org updates.
        const orgIds = [...new Set(stale.map(s => s.org_id))];
        for (const orgId of orgIds) void this._broadcastClientsListToAdmins(orgId);
      }
    } catch (err) {
      console.error('Session cleanup error:', err?.message || err);
    }
  }

  _screenSourcesForClientId(clientId) {
    const cid = Number(clientId);
    if (!Number.isFinite(cid) || cid <= 0) return [];
    for (const [, conn] of this.clients) {
      if (conn?.kind !== 'client') continue;
      if (!conn.client || Number(conn.client.id) !== cid) continue;
      const raw = Array.isArray(conn.screenSources) ? conn.screenSources : [];
      return raw
        .filter((s) => s && typeof s === 'object')
        .map((s) => ({
          id: typeof s.id === 'string' ? s.id : '',
          name: typeof s.name === 'string' ? s.name : '',
          index: Number.isFinite(Number(s.index)) ? Math.trunc(Number(s.index)) : null,
        }))
        .filter((s) => s.id && s.name)
        .slice(0, 8);
    }
    return [];
  }

  _mapAdminClientRow(c) {
    const id = c.id;
    return {
      id,
      fullName: c.full_name || c.fullName,
      status: c.status || 'offline',
      orgId: c.org_id != null ? c.org_id : c.orgId,
      orgName: c.org_name != null ? c.org_name : (c.orgName != null ? c.orgName : null),
      claimedOrgName: c.claimed_org_name != null ? c.claimed_org_name : (c.claimedOrgName != null ? c.claimedOrgName : null),
      lastHeartbeatMs: c.last_heartbeat != null ? Number(c.last_heartbeat) : null,
      lastOnlineMs: c.last_online_at != null ? Number(c.last_online_at) : null,
      lastOfflineMs: c.last_offline_at != null ? Number(c.last_offline_at) : null,
      screenSources: this._screenSourcesForClientId(id),
    };
  }

  async _broadcastClientsListToAdmins(orgId) {
    try {
      const rows = await this.db.getClientsForOrg(orgId);
      const clients = rows.map((c) => this._mapAdminClientRow(c));
      let defaultOrgId = null;
      for (const [, conn] of this.clients) {
        const isAdmin = conn.kind === 'admin' || conn.kind === 'legacy_agent';
        if (!isAdmin || !isOpen(conn.ws)) continue;

        // legacy agents only see default org.
        if (conn.kind === 'legacy_agent') {
          if (defaultOrgId == null) {
            defaultOrgId = (await this.db.ensureOrganization('default')).id;
          }
          if (orgId !== defaultOrgId) continue;
          this._send(conn.ws, { type: 'clients-list', success: true, clients: clients.map(c => ({ name: c.fullName, status: c.status })) });
          continue;
        }

        // v2 admins: org admins only get their org; super_admin might be subscribed via polling.
        const adminOrgId = conn.admin?.orgId;
        const adminRole = conn.admin?.role;
        if ((adminRole === 'org_admin' || adminRole === 'it_ops') && adminOrgId !== orgId) continue;

        const clientsForRole = adminRole === 'it_ops'
          ? clients.filter(c => c.status === 'sharing')
          : clients;

        this._send(conn.ws, { type: 'admin-clients-updated', success: true, orgId, clients: clientsForRole });
      }
    } catch (err) {
      // Prevent DB connectivity spikes from escalating into unhandled rejections / process exits.
      console.error('[broadcast-clients] failed:', err?.message || err);
    }
  }

  _httpClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  }

  _socketClientIp(socketId) {
    const conn = this.clients.get(socketId);
    return conn?.ip || null;
  }

  _ipv4Subnet24(ip) {
    if (!ip || typeof ip !== 'string') return null;
    const clean = ip.replace(/^::ffff:/i, '').trim();
    const m = clean.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!m) return null;
    const parts = m.slice(1).map((x) => Number(x));
    if (parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
    return `${parts[0]}.${parts[1]}.${parts[2]}`;
  }

  _ipv6Subnet64(ip) {
    if (!ip || typeof ip !== 'string') return null;
    const clean = ip.trim().replace(/^\[|\]$/g, '');
    if (!clean.includes(':')) return null;
    const noZone = clean.includes('%') ? clean.slice(0, clean.indexOf('%')) : clean;
    const parts = noZone.split(':');
    if (parts.length < 4) return null;
    return parts.slice(0, 4).join(':').toLowerCase();
  }

  _sameNetworkForAdminClient(adminSocketId, clientSocketId) {
    const adminConn = this.clients.get(adminSocketId);
    const clientConn = this.clients.get(clientSocketId);
    if (!adminConn || !clientConn) return { sameNetwork: false, reason: 'MISSING_CONNECTION' };

    const adminIp = adminConn.ip || '';
    const clientIp = clientConn.ip || '';
    const adminWorkstationIps = adminConn.workstationIps || [];

    if (adminIp && clientIp && adminIp === clientIp) {
      return { sameNetwork: true, reason: 'SAME_PUBLIC_IP' };
    }

    const adminOffice = getOfficeNetworkLabel(adminIp, adminWorkstationIps);
    const clientOffice = getOfficeNetworkLabel(clientIp, []);
    if (adminOffice && clientOffice && adminOffice === clientOffice) {
      return { sameNetwork: true, reason: 'SAME_OFFICE_RANGE', adminOffice, clientOffice };
    }

    const admin24 = this._ipv4Subnet24(adminIp) || this._ipv4Subnet24(adminWorkstationIps[0] || '');
    const client24 = this._ipv4Subnet24(clientIp);
    if (admin24 && client24 && admin24 === client24) {
      return { sameNetwork: true, reason: 'SAME_IPV4_SUBNET24' };
    }

    const admin64 = this._ipv6Subnet64(adminIp) || this._ipv6Subnet64(adminWorkstationIps[0] || '');
    const client64 = this._ipv6Subnet64(clientIp);
    if (admin64 && client64 && admin64 === client64) {
      return { sameNetwork: true, reason: 'SAME_IPV6_SUBNET64' };
    }

    return { sameNetwork: false, reason: 'NETWORK_MISMATCH', adminIp, clientIp };
  }

  async _checkAdminSensitiveAccessByIp(ip, adminRow, workstationIps = []) {
    if (!adminRow) return { allowed: false, reason: 'UNAUTHORIZED', adminIp: ip };
    void workstationIps;
    // Access/location gate is disabled: any authenticated admin is allowed.
    return { allowed: true, bypassed: true, adminIp: ip };
  }

  async _checkAdminSensitiveAccess(socketId, adminRow) {
    const ip = this._socketClientIp(socketId);
    const conn = this.clients.get(socketId);
    const workstationIps = conn?.workstationIps || [];
    return this._checkAdminSensitiveAccessByIp(ip, adminRow, workstationIps);
  }

  async _checkAdminSensitiveHttpAccess(req, adminRow) {
    const ip = this._httpClientIp(req);
    return this._checkAdminSensitiveAccessByIp(ip, adminRow, []);
  }

  async _sendAdminIpStatus(ws, socketId, adminRow) {
    const conn = this.clients.get(socketId);
    const ip = conn?.ip || 'unknown';
    const workstationIps = conn?.workstationIps || [];
    const grant =
      adminRow.role === 'super_admin' ? null : await this.db.getActiveRemoteAccess(adminRow.admin_id);
    this._send(ws, {
      type: 'admin-ip-status',
      isOffice: isOnOfficeNetwork(ip, workstationIps),
      officeName: getOfficeNetworkLabel(ip, workstationIps),
      adminIp: ip,
      role: adminRow.role,
      activeRemoteGrant: grant
        ? {
            expiresAt: grant.expires_at,
            durationHours: grant.duration_hours,
            grantId: grant.id,
          }
        : null,
    });
  }

  _maybeSendAdminIpStatus(socketId, adminRow) {
    const conn = this.clients.get(socketId);
    if (!conn || !conn.ws || !adminRow) return;
    if (conn.ipStatusSent) return;
    conn.ipStatusSent = true;
    void this._sendAdminIpStatus(conn.ws, socketId, adminRow).catch((err) =>
      console.error('[admin-ip-status]', err?.message || err)
    );
  }

  _notifyAdminById(adminId, message) {
    const aid = Number(adminId);
    if (!Number.isFinite(aid)) return;
    for (const [, conn] of this.clients) {
      if (conn.kind !== 'admin' || !conn.admin || !isOpen(conn.ws)) continue;
      if (Number(conn.admin.adminId) !== aid) continue;
      this._send(conn.ws, { ...message });
    }
  }

  _broadcastNewRemoteAccessToSuperAdmins(payload) {
    for (const [, conn] of this.clients) {
      if (conn.kind !== 'admin' || !conn.admin || conn.admin.role !== 'super_admin' || !isOpen(conn.ws)) continue;
      this._send(conn.ws, payload);
    }
  }

  _broadcastNewStreamRelayToSuperAdmins(payload) {
    for (const [, conn] of this.clients) {
      if (conn.kind !== 'admin' || !conn.admin || conn.admin.role !== 'super_admin' || !isOpen(conn.ws)) continue;
      this._send(conn.ws, payload);
    }
  }

  async _handleStreamRelayRequest(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;

    if (adminRow.role !== 'org_admin') {
      this._send(ws, {
        type: 'stream-relay-request-response',
        success: false,
        reason: 'NOT_APPLICABLE',
        message: 'Only team leads may request relay streaming.',
        ipcCorrId,
      });
      return;
    }
    const active = await this.db.getActiveStreamRelay(adminRow.admin_id);
    if (active) {
      this._send(ws, {
        type: 'stream-relay-request-response',
        success: false,
        reason: 'ALREADY_ACTIVE',
        message: 'You already have an approved relay window.',
        ipcCorrId,
      });
      return;
    }
    const ip = this._socketClientIp(socketId);
    const reason = String(msg.reason || '').trim().slice(0, 500);
    const durationHours = Math.max(1, Math.min(72, parseInt(msg.durationHours, 10) || 4));
    if (!reason) {
      this._send(ws, {
        type: 'stream-relay-request-response',
        success: false,
        reason: 'REASON_REQUIRED',
        ipcCorrId,
      });
      return;
    }
    const request = await this.db.createStreamRelayRequest({
      adminId: adminRow.admin_id,
      orgId: adminRow.org_id,
      requesterIp: ip || 'unknown',
      reason,
      durationHours,
    });
    this._send(ws, {
      type: 'stream-relay-request-response',
      success: true,
      requestId: request.id,
      message: 'Your request has been submitted to the Super Admin.',
      ipcCorrId,
    });
    this._broadcastNewStreamRelayToSuperAdmins({
      type: 'new-stream-relay-request',
      request: {
        id: request.id,
        orgId: adminRow.org_id,
        requesterName: adminRow.username,
        requesterRole: adminRow.role,
        requesterIp: ip,
        reason,
        durationHours,
        createdAt: request.created_at,
      },
    });
  }

  async _handleApproveStreamRelay(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    if (adminRow.role !== 'super_admin') {
      this._send(ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Super admin only', ipcCorrId });
      return;
    }
    const requestId = Number(msg.requestId);
    if (!Number.isFinite(requestId)) {
      this._send(ws, {
        type: 'approve-stream-relay-response',
        success: false,
        reason: 'INVALID_INPUT',
        ipcCorrId,
      });
      return;
    }
    const updated = await this.db.approveStreamRelayRequest({
      requestId,
      approvedByAdminId: adminRow.admin_id,
    });
    if (!updated) {
      this._send(ws, {
        type: 'approve-stream-relay-response',
        success: false,
        reason: 'NOT_FOUND_OR_ALREADY_HANDLED',
        ipcCorrId,
      });
      return;
    }
    this._send(ws, { type: 'approve-stream-relay-response', success: true, request: updated, ipcCorrId });
    this._notifyAdminById(updated.admin_id, {
      type: 'stream-relay-approved',
      expiresAt: updated.expires_at,
      durationHours: updated.duration_hours,
      message: `Relay streaming (TURN) approved for ${updated.duration_hours} hour(s). Reconnect to the member to use it.`,
    });
  }

  async _handleDenyStreamRelay(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    if (adminRow.role !== 'super_admin') {
      this._send(ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Super admin only', ipcCorrId });
      return;
    }
    const requestId = Number(msg.requestId);
    if (!Number.isFinite(requestId)) {
      this._send(ws, { type: 'deny-stream-relay-response', success: false, reason: 'INVALID_INPUT', ipcCorrId });
      return;
    }
    const updated = await this.db.denyStreamRelayRequest({
      requestId,
      approvedByAdminId: adminRow.admin_id,
    });
    this._send(ws, { type: 'deny-stream-relay-response', success: true, ipcCorrId });
    if (updated) {
      this._notifyAdminById(updated.admin_id, {
        type: 'stream-relay-denied',
        message: 'Your stream relay request was denied by the Super Admin.',
      });
    }
  }

  async _handleGetMyStreamRelayRequests(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    const requests = await this.db.getMyStreamRelayRequests(adminRow.admin_id);
    this._send(ws, { type: 'my-stream-relay-requests', requests, ipcCorrId });
  }

  async _handleGetPendingStreamRelayRequests(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    if (adminRow.role !== 'super_admin') {
      this._send(ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Super admin only', ipcCorrId });
      return;
    }
    const requests = await this.db.getAllPendingStreamRelayRequests();
    this._send(ws, { type: 'pending-stream-relay-requests', requests, ipcCorrId });
  }

  async _handleGetActiveStreamRelay(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    const row =
      adminRow.role === 'org_admin' || adminRow.role === 'it_ops'
        ? await this.db.getActiveStreamRelay(adminRow.admin_id)
        : null;
    this._send(ws, { type: 'active-stream-relay', active: row, ipcCorrId });
  }

  async _handleRemoteAccessRequest(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;

    if (adminRow.role === 'super_admin') {
      this._send(ws, {
        type: 'remote-access-request-response',
        success: false,
        reason: 'NOT_APPLICABLE',
        message: 'Super admins are not restricted by location.',
        ipcCorrId,
      });
      return;
    }
    const ip = this._socketClientIp(socketId);
    const conn = this.clients.get(socketId);
    const workstationIps = conn?.workstationIps || [];
    if (isOnOfficeNetwork(ip, workstationIps)) {
      this._send(ws, {
        type: 'remote-access-request-response',
        success: false,
        reason: 'ALREADY_IN_OFFICE',
        ipcCorrId,
      });
      return;
    }
    const reason = String(msg.reason || '').trim().slice(0, 500);
    const durationHours = Math.max(1, Math.min(72, parseInt(msg.durationHours, 10) || 4));
    if (!reason) {
      this._send(ws, {
        type: 'remote-access-request-response',
        success: false,
        reason: 'REASON_REQUIRED',
        ipcCorrId,
      });
      return;
    }
    const request = await this.db.createRemoteAccessRequest({
      adminId: adminRow.admin_id,
      orgId: adminRow.org_id,
      requesterIp: ip || 'unknown',
      reason,
      durationHours,
    });
    this._send(ws, {
      type: 'remote-access-request-response',
      success: true,
      requestId: request.id,
      message: 'Your request has been submitted to the Super Admin.',
      ipcCorrId,
    });
    this._broadcastNewRemoteAccessToSuperAdmins({
      type: 'new-remote-access-request',
      request: {
        id: request.id,
        orgId: adminRow.org_id,
        requesterName: adminRow.username,
        requesterRole: adminRow.role,
        requesterIp: ip,
        reason,
        durationHours,
        createdAt: request.created_at,
      },
    });
  }

  async _handleApproveRemoteAccess(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    if (adminRow.role !== 'super_admin') {
      this._send(ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Super admin only', ipcCorrId });
      return;
    }
    const requestId = Number(msg.requestId);
    if (!Number.isFinite(requestId)) {
      this._send(ws, {
        type: 'approve-remote-access-response',
        success: false,
        reason: 'INVALID_INPUT',
        ipcCorrId,
      });
      return;
    }
    const updated = await this.db.approveRemoteAccessRequest({
      requestId,
      approvedByAdminId: adminRow.admin_id,
    });
    if (!updated) {
      this._send(ws, {
        type: 'approve-remote-access-response',
        success: false,
        reason: 'NOT_FOUND_OR_ALREADY_HANDLED',
        ipcCorrId,
      });
      return;
    }
    this._send(ws, { type: 'approve-remote-access-response', success: true, request: updated, ipcCorrId });
    this._notifyAdminById(updated.admin_id, {
      type: 'remote-access-approved',
      expiresAt: updated.expires_at,
      durationHours: updated.duration_hours,
      message: `Your remote access has been approved for ${updated.duration_hours} hour(s).`,
    });
  }

  async _handleDenyRemoteAccess(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    if (adminRow.role !== 'super_admin') {
      this._send(ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Super admin only', ipcCorrId });
      return;
    }
    const requestId = Number(msg.requestId);
    if (!Number.isFinite(requestId)) {
      this._send(ws, { type: 'deny-remote-access-response', success: false, reason: 'INVALID_INPUT', ipcCorrId });
      return;
    }
    const updated = await this.db.denyRemoteAccessRequest({
      requestId,
      approvedByAdminId: adminRow.admin_id,
    });
    this._send(ws, { type: 'deny-remote-access-response', success: true, ipcCorrId });
    if (updated) {
      this._notifyAdminById(updated.admin_id, {
        type: 'remote-access-denied',
        message: 'Your remote access request was denied by the Super Admin.',
      });
    }
  }

  async _handleGetMyRemoteAccessRequests(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    const requests = await this.db.getMyRemoteAccessRequests(adminRow.admin_id);
    this._send(ws, { type: 'my-remote-access-requests', requests, ipcCorrId });
  }

  async _handleGetPendingRemoteAccessRequests(socketId, ws, msg) {
    const ipcCorrId = typeof msg.ipcCorrId === 'string' ? msg.ipcCorrId : undefined;
    const adminRow = await this._requireAdmin(socketId, ws, msg);
    if (!adminRow) return;
    if (adminRow.role !== 'super_admin') {
      this._send(ws, { type: 'error', error: 'UNAUTHORIZED', message: 'Super admin only', ipcCorrId });
      return;
    }
    const requests = await this.db.getAllPendingRemoteAccessRequests();
    this._send(ws, { type: 'pending-remote-access-requests', requests, ipcCorrId });
  }

  async _notifyAdminsOfClientEvent(orgId, clientFullName, eventType) {
    // Resolve clientId for admins that key data by numeric ID
    const clientRow = await this.db.getClientByOrgAndFullName(orgId, clientFullName);
    const clientId = clientRow?.id ?? null;
    for (const [, conn] of this.clients) {
      const isAdmin = conn.kind === 'admin' || conn.kind === 'legacy_agent';
      if (!isAdmin || !isOpen(conn.ws)) continue;

      if (conn.kind === 'legacy_agent') {
        const defaultOrgId = (await this.db.ensureOrganization('default')).id;
        if (orgId !== defaultOrgId) continue;
        this._send(conn.ws, { type: eventType, clientName: clientFullName, clientId });
        continue;
      }

      if ((conn.admin?.role === 'org_admin' || conn.admin?.role === 'it_ops') && conn.admin?.orgId !== orgId) continue;
      this._send(conn.ws, { type: eventType, orgId, clientFullName, clientId });
    }
  }

  // ─── Helpers ───

  _send(ws, data) {
    if (isOpen(ws)) {
      ws.send(JSON.stringify(data));
    }
  }

  _generateId() {
    return crypto.randomBytes(12).toString('hex');
  }

  _findClientConnectionByClientId(clientId) {
    for (const [, conn] of this.clients) {
      if (conn.kind === 'client' && conn.client?.id === clientId) return conn;
    }
    return null;
  }

  _findConnectionByName(name) {
    for (const [, conn] of this.clients) {
      if (conn.kind === 'client' && conn.client?.fullName === name) return conn;
      if (conn.kind === 'admin' && conn.admin?.fullName === name) return conn;
    }
    return null;
  }

  async shutdown() {
    console.log('\n🛑 Shutting down signaling server...');
    if (this.pingTimer) clearInterval(this.pingTimer);
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.sessionCleanupTimer) clearInterval(this.sessionCleanupTimer);
    if (this.browserTabRetentionTimer) clearInterval(this.browserTabRetentionTimer);
    if (this.taskbarRetentionTimer) clearInterval(this.taskbarRetentionTimer);
    if (this.remoteAccessExpiryTimer) clearInterval(this.remoteAccessExpiryTimer);

    // Close all connections
    for (const [, conn] of this.clients) {
      if (isOpen(conn.ws)) {
        this._send(conn.ws, { type: 'server-shutdown' });
        conn.ws.close();
      }
    }

    if (this.wss) {
      try {
        this.wss.close();
      } catch {
        /* ignore */
      }
    }
    if (this.httpServer) {
      try {
        this.httpServer.close();
      } catch {
        /* ignore */
      }
      this.httpServer = null;
    }

    try {
      await this.db.resetAllOnStartup(); // Clean state
      await this.db.close();
    } catch {
      // ignore if already closed
    }
    
    console.log('✅ Shutdown complete. Exiting process.');
    process.exit(0);
  }
}

// ─── Start ───
console.log(`🌐 ICE config loaded (${ICE_SERVERS.length} server entries)`);
const server = new SignalingServer();
server.start().catch((err) => {
  console.error('FATAL: server.start() failed:', err?.message || err);
  if (err && err.stack) console.error(err.stack);
  process.exit(1);
});
