const crypto = require('crypto');
const { Pool } = require('pg');

function nowMs() {
  return Date.now();
}

function normalizeOrgName(input) {
  if (typeof input !== 'string') return null;
  const v = input.trim();
  if (!v) return null;
  // Keep it simple + stable for uniqueness.
  return v.toLowerCase();
}

function normalizeDisplayName(input) {
  if (typeof input !== 'string') return null;
  const v = input.trim().replace(/\s+/g, ' ');
  if (!v) return null;
  return v;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  // Keep parameters strong but within Node's default memory limits on Windows.
  const N = 1 << 14;
  const r = 8;
  const p = 1;
  const derivedKey = crypto.scryptSync(password, salt, 32, { N, r, p, maxmem: 64 * 1024 * 1024 });
  // Format: scrypt$N$r$p$saltB64$hashB64
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${derivedKey.toString('base64')}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split('$');
    // Expected format: scrypt$N$r$p$saltB64$hashB64
    if (parts.length !== 6) return false;
    const [, N, r, p, saltB64, hashB64] = parts;
    const salt = Buffer.from(saltB64, 'base64');
    const hash = Buffer.from(hashB64, 'base64');
    const derived = crypto.scryptSync(password, salt, hash.length, {
      N: Number(N),
      r: Number(r),
      p: Number(p),
      maxmem: 64 * 1024 * 1024,
    });
    return crypto.timingSafeEqual(hash, derived);
  } catch {
    return false;
  }
}

class SignalingDatabase {
  constructor(dbPath, opts = {}) {
    void dbPath;
    this._bootstrapping = true;

    const connStr =
      process.env.SUPABASE_DATABASE_URL ||
      process.env.DATABASE_URL ||
      null;
    if (!connStr) {
      throw new Error('Missing required env var: SUPABASE_DATABASE_URL (or DATABASE_URL)');
    }

    const isSupabase = /supabase\.co/i.test(connStr);
    const requireSsl =
      process.env.PGSSLMODE === 'require' ||
      process.env.SUPABASE_REQUIRE_SSL === '1' ||
      process.env.SUPABASE_REQUIRE_SSL === 'true' ||
      isSupabase ||
      (process.env.NODE_ENV === 'production');

    const connectTimeoutMs = Number(process.env.PG_CONNECT_TIMEOUT_MS || 10000);
    const idleTimeoutMs = Number(process.env.PG_IDLE_TIMEOUT_MS || 30000);

    this.pool = new Pool({
      connectionString: connStr,
      ssl: requireSsl ? { rejectUnauthorized: false } : undefined,
      max: Number(process.env.PG_POOL_MAX || 10),
      connectionTimeoutMillis: connectTimeoutMs,
      idleTimeoutMillis: idleTimeoutMs,
    });

    this.pool.on('error', (err) => {
      console.error('[DB pool error]', err?.message || err);
    });

    const healthCheckOnly = opts?.healthCheck === true;
    this._ready = (healthCheckOnly ? this._testConnection() : this._init(opts))
      .finally(() => {
        this._bootstrapping = false;
      });
  }

  async _init(opts) {
    await this._testConnection();
    if (opts?.wipe) await this.wipeAllUserData();
    await this._ensureDefaultOrg();
    await this._ensureOrgLogoColumn();
    await this._ensureClientsClaimedOrgColumn();
    await this._ensureTelemetryTables();
    await this._ensureRemoteAccessTable();
    await this._ensureStreamRelayTable();
    await this._ensureIcePathReportsTable();
    await this.seedDefaultSuperAdminIfEmpty();
  }

  async _testConnection() {
    const t0 = nowMs();
    try {
      await this.pool.query('SELECT 1');
      console.log(`✅ Database connection healthy (${nowMs() - t0} ms)`);
    } catch (err) {
      const hint = err?.message && err.message.toLowerCase().includes('ssl')
        ? 'Hint: set SUPABASE_REQUIRE_SSL=true or PGSSLMODE=require when using Supabase.'
        : '';
      console.error('❌ Database connection failed:', err?.message || err, hint);
      throw err;
    }
  }

  async _ensureDefaultOrg() {
    // Runtime expects default org to exist (legacy/backward compat paths).
    await this.pool.query(
      `INSERT INTO organizations (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`,
      ['default']
    );
  }

  async _ensureOrgLogoColumn() {
    await this._q(`ALTER TABLE organizations ADD COLUMN IF NOT EXISTS logo_url TEXT NULL`);
  }

  async _ensureClientsClaimedOrgColumn() {
    await this._q(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS claimed_org_name TEXT NULL`);
  }

  async _ensureTelemetryTables() {
    await this._q(`
      CREATE TABLE IF NOT EXISTS browser_tab_events (
        id BIGSERIAL PRIMARY KEY,
        client_id BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        occurred_at TEXT NOT NULL,
        received_at BIGINT NOT NULL,
        browser_name TEXT NULL,
        active_tab_id BIGINT NULL,
        reason TEXT NULL,
        session_json TEXT NULL,
        switch_log_json TEXT NULL,
        tabs_json TEXT NULL
      )
    `);
    await this._q(`ALTER TABLE browser_tab_events ADD COLUMN IF NOT EXISTS reason TEXT NULL`);
    await this._q(`ALTER TABLE browser_tab_events ADD COLUMN IF NOT EXISTS session_json TEXT NULL`);
    await this._q(`ALTER TABLE browser_tab_events ADD COLUMN IF NOT EXISTS switch_log_json TEXT NULL`);
    await this._q('CREATE INDEX IF NOT EXISTS idx_browser_tab_events_client ON browser_tab_events(client_id)');
    await this._q('CREATE INDEX IF NOT EXISTS idx_browser_tab_events_occurred ON browser_tab_events(occurred_at)');
    await this._q(
      'CREATE INDEX IF NOT EXISTS idx_browser_tab_events_received_at ON browser_tab_events(received_at)'
    );

    await this._q(`
      CREATE TABLE IF NOT EXISTS taskbar_events (
        id BIGSERIAL PRIMARY KEY,
        client_id BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        occurred_at TEXT NOT NULL,
        received_at BIGINT NOT NULL,
        opened_json TEXT NULL,
        closed_json TEXT NULL,
        open_apps_json TEXT NULL
      )
    `);
    await this._q('CREATE INDEX IF NOT EXISTS idx_taskbar_events_client ON taskbar_events(client_id)');
    await this._q('CREATE INDEX IF NOT EXISTS idx_taskbar_events_occurred ON taskbar_events(occurred_at)');
    await this._q(
      'CREATE INDEX IF NOT EXISTS idx_taskbar_events_received_at ON taskbar_events(received_at)'
    );
  }

  /**
   * BrowserScope / extension telemetry rows (`browser_tab_events` only).
   * Deletes by server ingest time `received_at` (epoch ms). Does not touch call_events, taskbar_events, clients, etc.
   *
   * Env: `BROWSER_TAB_RETENTION_DAYS` — default 7; set to 0 to disable automatic deletion.
   */
  async purgeBrowserTabEventsExpired() {
    const raw = process.env.BROWSER_TAB_RETENTION_DAYS;
    let days = 7;
    if (raw !== undefined && raw !== '') {
      const n = Number(raw);
      if (Number.isFinite(n)) days = Math.max(0, Math.min(366, Math.floor(n)));
    }
    if (days <= 0) return { deleted: 0, disabled: true, days: 0 };

    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const r = await this._q('DELETE FROM browser_tab_events WHERE received_at < $1', [cutoff]);
    const deleted = r.rowCount ?? 0;
    if (deleted > 0) {
      console.log(
        `[DB] browser_tab_events retention: removed ${deleted} row(s) with received_at older than ${days} day(s)`
      );
    }
    return { deleted, days, cutoff };
  }

  /**
   * Taskbar / open-app telemetry (`taskbar_events` only). High volume — use rolling retention like browser tabs.
   * Deletes by server ingest time `received_at` (epoch ms).
   *
   * Env: `TASKBAR_RETENTION_DAYS` — default 7 (same as browser tabs); set to 0 to disable automatic deletion.
   */
  async purgeTaskbarEventsExpired() {
    const raw = process.env.TASKBAR_RETENTION_DAYS;
    let days = 7;
    if (raw !== undefined && raw !== '') {
      const n = Number(raw);
      if (Number.isFinite(n)) days = Math.max(0, Math.min(366, Math.floor(n)));
    }
    if (days <= 0) return { deleted: 0, disabled: true, days: 0 };

    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const r = await this._q('DELETE FROM taskbar_events WHERE received_at < $1', [cutoff]);
    const deleted = r.rowCount ?? 0;
    if (deleted > 0) {
      console.log(
        `[DB] taskbar_events retention: removed ${deleted} row(s) with received_at older than ${days} day(s)`
      );
    }
    return { deleted, days, cutoff };
  }

  async _ensureRemoteAccessTable() {
    await this._q(`
      CREATE TABLE IF NOT EXISTS remote_access_requests (
        id BIGSERIAL PRIMARY KEY,
        admin_id BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
        org_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        requester_ip TEXT NOT NULL,
        reason TEXT NOT NULL,
        duration_hours INTEGER NOT NULL CHECK (duration_hours BETWEEN 1 AND 72),
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending','approved','denied','expired')),
        approved_by BIGINT REFERENCES admins(id),
        approved_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await this._q(
      'CREATE INDEX IF NOT EXISTS idx_rar_admin_status ON remote_access_requests(admin_id, status)'
    );
    await this._q('CREATE INDEX IF NOT EXISTS idx_rar_org_pending ON remote_access_requests(org_id, status)');
  }

  async _ensureStreamRelayTable() {
    await this._q(`
      CREATE TABLE IF NOT EXISTS stream_relay_requests (
        id BIGSERIAL PRIMARY KEY,
        admin_id BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
        org_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        requester_ip TEXT NOT NULL,
        reason TEXT NOT NULL,
        duration_hours INTEGER NOT NULL CHECK (duration_hours BETWEEN 1 AND 72),
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending','approved','denied','expired')),
        approved_by BIGINT REFERENCES admins(id),
        approved_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await this._q(
      'CREATE INDEX IF NOT EXISTS idx_srr_admin_status ON stream_relay_requests(admin_id, status)'
    );
    await this._q('CREATE INDEX IF NOT EXISTS idx_srr_pending ON stream_relay_requests(org_id, status)');
  }

  async _ensureIcePathReportsTable() {
    await this._q(`
      CREATE TABLE IF NOT EXISTS ice_path_reports (
        id BIGSERIAL PRIMARY KEY,
        session_id BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        client_id BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        admin_id BIGINT NULL REFERENCES admins(id) ON DELETE SET NULL,
        local_type TEXT NULL,
        remote_type TEXT NULL,
        using_turn BOOLEAN NOT NULL DEFAULT FALSE,
        time_to_ice_ms INTEGER NULL,
        candidate_type TEXT NULL,
        phase INTEGER NULL,
        rtt_ms INTEGER NULL,
        reported_at BIGINT NOT NULL
      )
    `);
    await this._q('CREATE INDEX IF NOT EXISTS idx_ice_path_reports_session ON ice_path_reports(session_id)');
    await this._q('CREATE INDEX IF NOT EXISTS idx_ice_path_reports_reported ON ice_path_reports(reported_at)');
    await this._q(`ALTER TABLE ice_path_reports ADD COLUMN IF NOT EXISTS candidate_type TEXT NULL`);
    await this._q(`ALTER TABLE ice_path_reports ADD COLUMN IF NOT EXISTS phase INTEGER NULL`);
    await this._q(`ALTER TABLE ice_path_reports ADD COLUMN IF NOT EXISTS rtt_ms INTEGER NULL`);
    await this._q(`ALTER TABLE ice_path_reports ADD COLUMN IF NOT EXISTS org_id TEXT NULL`);
    await this._q(`ALTER TABLE ice_path_reports ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`);
    await this._q('CREATE INDEX IF NOT EXISTS idx_ice_path_reports_created_at ON ice_path_reports(created_at)');
    await this._q('CREATE INDEX IF NOT EXISTS idx_ice_path_reports_org_id ON ice_path_reports(org_id)');
  }

  async _q(text, params = []) {
    if (!this._bootstrapping) {
      await this._ready;
    }
    return this.pool.query(text, params);
  }

  // ─── Organizations ───
  /** Lookup only; does not create (prevents anonymous org provisioning). */
  async getOrganizationByName(orgName) {
    const norm = normalizeOrgName(orgName);
    if (!norm) return null;
    const r = await this._q('SELECT id, name FROM organizations WHERE name = $1', [norm]);
    return r.rows[0] || null;
  }

  /** Orgs that already have at least one admin (for login / client team pickers). */
  async getOrganizationsWithAdmins() {
    const r = await this._q(
      `SELECT DISTINCT o.id, o.name
       FROM organizations o
       INNER JOIN admins a ON a.org_id = o.id
       ORDER BY o.name ASC`
    );
    return r.rows;
  }

  async wipeAllUserData() {
    const safeDelete = async (tableName) => {
      try {
        await this._q(`DELETE FROM ${tableName}`);
      } catch (e) {
        // Undefined table (e.g., freshly upgraded schema) should not block wipe.
        if (!(e && e.code === '42P01')) throw e;
      }
    };
    await this._q('BEGIN');
    try {
      await safeDelete('transfer_requests');
      await safeDelete('call_events');
      await safeDelete('taskbar_events');
      await safeDelete('browser_tab_events');
      await safeDelete('ice_path_reports');
      await safeDelete('admin_sessions');
      await safeDelete('admins');
      await safeDelete('sessions');
      await safeDelete('clients');
      await safeDelete('organizations');
      await this._q('COMMIT');
    } catch (e) {
      await this._q('ROLLBACK');
      throw e;
    }
  }

  /**
   * Fresh install: optionally create one super user from env. Disabled by default.
   */
  async seedDefaultSuperAdminIfEmpty() {
    if (await this.hasAnyAdmin()) return;
    const allowSeed = process.env.SEED_SUPER_ADMIN === 'true' || process.env.BOOTSTRAP_SUPER_ADMIN === 'true';
    if (!allowSeed) {
      console.warn('⚠️  No admins exist yet. Set SEED_SUPER_ADMIN=true and provide BOOTSTRAP_ADMIN_USERNAME/BOOTSTRAP_ADMIN_PASSWORD to create the first super admin.');
      return;
    }

    const orgName = process.env.BOOTSTRAP_ADMIN_ORG || 'acme';
    const username = process.env.BOOTSTRAP_ADMIN_USERNAME || 'root';
    const fullName = process.env.BOOTSTRAP_ADMIN_FULLNAME || 'Root';
    const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;

    if (!password || password.length < 12) {
      console.error('❌ Bootstrap super admin not created: BOOTSTRAP_ADMIN_PASSWORD must be set and at least 12 characters.');
      return;
    }

    const org = await this.ensureOrganization(orgName);
    const created = await this.createAdmin({
      orgId: org.id,
      username,
      fullName,
      password,
      role: 'super_admin',
    });
    if (created.success) {
      console.log(`✅ Seeded bootstrap super admin — team: ${org.name}, user: ${username}`);
    } else {
      console.error('❌ Seeding default super admin failed:', created.message || created.error);
    }
  }

  async ensureOrganization(orgName) {
    const norm = normalizeOrgName(orgName);
    if (!norm) throw new Error('INVALID_ORG');
    const r = await this._q('SELECT id, name FROM organizations WHERE name = $1', [norm]);
    if (r.rows[0]) return r.rows[0];
    const ins = await this._q(
      'INSERT INTO organizations (name) VALUES ($1) ON CONFLICT (name) DO NOTHING RETURNING id, name',
      [norm]
    );
    if (ins.rows[0]) return ins.rows[0];
    const again = await this._q('SELECT id, name FROM organizations WHERE name = $1', [norm]);
    return again.rows[0];
  }

  async getOrganizations() {
    const r = await this._q('SELECT id, name, logo_url FROM organizations ORDER BY name ASC');
    return r.rows.map((row) => ({
      id: Number(row.id),
      name: row.name,
      logoUrl: row.logo_url && String(row.logo_url).trim() ? String(row.logo_url).trim() : null,
    }));
  }

  async getOrganizationNameById(orgId) {
    if (!Number.isFinite(orgId)) return null;
    const r = await this._q('SELECT name FROM organizations WHERE id = $1', [orgId]);
    return r.rows[0]?.name || null;
  }

  // Returns one "team lead" (role=org_admin) per org.
  // If an org has no org_admin yet, lead_full_name/lead_username will be null.
  // For role-scoping, pass { orgId } to limit results to a single org.
  async getOrgLeads({ orgId } = {}) {
    const where = Number.isFinite(orgId) ? 'WHERE o.id = $1' : '';
    const params = Number.isFinite(orgId) ? [orgId] : [];

    const r = await this._q(`
      SELECT
        o.id AS org_id,
        (
          SELECT a.full_name
          FROM admins a
          WHERE a.org_id = o.id AND a.role = 'org_admin'
          ORDER BY a.created_at DESC, a.id DESC
          LIMIT 1
        ) AS lead_full_name,
        (
          SELECT a.username
          FROM admins a
          WHERE a.org_id = o.id AND a.role = 'org_admin'
          ORDER BY a.created_at DESC, a.id DESC
          LIMIT 1
        ) AS lead_username
      FROM organizations o
      ${where}
      ORDER BY o.name ASC
    `, params);
    return r.rows;
  }

  async getOrganizationSummaries() {
    const r = await this._q(`
      SELECT
        o.id,
        o.name,
        COUNT(c.id)::int AS total_clients,
        COALESCE(SUM(CASE WHEN c.status != 'offline' THEN 1 ELSE 0 END), 0)::int AS online_clients,
        COALESCE(SUM(CASE WHEN c.status = 'sharing' THEN 1 ELSE 0 END), 0)::int AS sharing_clients
      FROM organizations o
      LEFT JOIN clients c ON c.org_id = o.id AND c.disabled = 0
      GROUP BY o.id
      ORDER BY o.name ASC
    `);
    return r.rows;
  }

  async getOrganizationSummariesForOrg(orgId) {
    if (!Number.isFinite(orgId)) return [];
    const r = await this._q(`
      SELECT
        o.id,
        o.name,
        COUNT(c.id)::int AS total_clients,
        COALESCE(SUM(CASE WHEN c.status != 'offline' THEN 1 ELSE 0 END), 0)::int AS online_clients,
        COALESCE(SUM(CASE WHEN c.status = 'sharing' THEN 1 ELSE 0 END), 0)::int AS sharing_clients
      FROM organizations o
      LEFT JOIN clients c ON c.org_id = o.id AND c.disabled = 0
      WHERE o.id = ?
      GROUP BY o.id
    `.replace('WHERE o.id = ?', 'WHERE o.id = $1'), [orgId]);
    return r.rows;
  }

  // ─── Admins / Sessions ───
  async hasAnyAdmin() {
    const r = await this._q('SELECT COUNT(*)::int AS c FROM admins');
    return (r.rows[0]?.c || 0) > 0;
  }

  async createAdmin({ orgId, username, fullName, password, role }) {
    const u = normalizeOrgName(username);
    const fn = normalizeDisplayName(fullName);
    if (!u || !fn || typeof password !== 'string' || password.length < 8) {
      return { success: false, error: 'INVALID_INPUT', message: 'Invalid admin profile' };
    }
    if (!['super_admin', 'org_admin', 'it_ops'].includes(role)) {
      return { success: false, error: 'INVALID_ROLE', message: 'Invalid role' };
    }
    const pwHash = hashPassword(password);
    try {
      const r = await this._q(
        'INSERT INTO admins (org_id, username, full_name, password_hash, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [orgId ?? null, u, fn, pwHash, role]
      );
      return { success: true, adminId: r.rows[0]?.id };
    } catch (e) {
      return { success: false, error: 'USERNAME_TAKEN', message: 'Username already exists in this organization' };
    }
  }

  async getAdminByOrgAndUsername(orgId, username) {
    const u = normalizeOrgName(username);
    if (!u) return null;
    const r = await this._q(
      'SELECT id, org_id, username, full_name, password_hash, role FROM admins WHERE org_id IS NOT DISTINCT FROM $1 AND username = $2',
      [orgId ?? null, u]
    );
    return r.rows[0] || null;
  }

  verifyAdminPassword(adminRow, password) {
    if (!adminRow) return false;
    return verifyPassword(password, adminRow.password_hash);
  }

  async createAdminSession(adminId, ttlMs = 1000 * 60 * 60 * 24 * 365 * 50) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = nowMs() + ttlMs;
    await this._q('INSERT INTO admin_sessions (admin_id, token, expires_at) VALUES ($1, $2, $3)', [adminId, token, expiresAt]);
    return { token, expiresAt };
  }

  async revokeAdminSession(token) {
    if (typeof token !== 'string' || token.trim().length === 0) return;
    await this._q('DELETE FROM admin_sessions WHERE token = $1', [token.trim()]);
  }

  async getAdminBySessionToken(token) {
    const r = await this._q(`
      SELECT a.id as admin_id, a.org_id as org_id, a.username, a.full_name, a.role,
             s.token, s.expires_at
      FROM admin_sessions s
      JOIN admins a ON a.id = s.admin_id
      WHERE s.token = $1
    `, [token]);
    const row = r.rows[0];
    if (!row) return null;
    if (row.expires_at <= nowMs()) return null;
    return row;
  }

  async purgeExpiredSessions() {
    await this._q('DELETE FROM admin_sessions WHERE expires_at <= $1', [nowMs()]);
  }

  // ─── Clients ───
  async upsertClientAuth({ deviceId, orgName, fullName, socketId }) {
    const fn = normalizeDisplayName(fullName);
    if (!fn || typeof deviceId !== 'string' || deviceId.trim().length < 8) {
      return { success: false, error: 'INVALID_INPUT', message: 'Invalid client identity' };
    }
    const dev = deviceId.trim();
    const requestedRaw = typeof orgName === 'string' ? orgName.trim().slice(0, 200) : '';

    let org = await this.getOrganizationByName(orgName);
    const usedDefaultFallback = !org;
    if (!org) {
      org = await this.ensureOrganization('default');
    }

    // If client has pending org change, apply it at next login.
    const existingRes = await this._q('SELECT * FROM clients WHERE device_id = $1', [dev]);
    const existing = existingRes.rows[0] || null;
    if (existing && Number(existing.disabled) === 1) {
      return { success: false, error: 'CLIENT_DISABLED', message: 'Client has been disabled' };
    }

    const applyOrgId = existing?.pending_org_id ? existing.pending_org_id : org.id;
    const pendingOrgId = existing?.pending_org_id ? null : null;

    let claimedOrgName = null;
    if (existing?.pending_org_id) {
      claimedOrgName = null;
    } else if (usedDefaultFallback) {
      claimedOrgName = requestedRaw || null;
    } else {
      const reqNorm = normalizeOrgName(orgName);
      if (org.name === 'default' && reqNorm && reqNorm !== 'default') {
        claimedOrgName = requestedRaw || null;
      }
    }

    const prevOrgIdForBroadcast =
      existing && Number(existing.org_id) !== Number(applyOrgId) ? Number(existing.org_id) : null;

    try {
      await this._q('BEGIN');
      if (existing) {
        const wasDisconnected = existing.status === 'offline' || existing.socket_id == null;
        await this._q(
          `UPDATE clients
           SET org_id = $1, pending_org_id = $2, full_name = $3, status = $4, socket_id = $5, last_heartbeat = $6, claimed_org_name = $7
           WHERE device_id = $8`,
          [applyOrgId, pendingOrgId, fn, 'sharing', socketId, nowMs(), claimedOrgName, dev]
        );
        if (wasDisconnected) {
          await this._q('UPDATE clients SET last_online_at = $1 WHERE device_id = $2', [nowMs(), dev]);
        }
        const updatedRes = await this._q('SELECT id, org_id, full_name, status FROM clients WHERE device_id = $1', [dev]);
        await this._q('COMMIT');
        return { success: true, client: updatedRes.rows[0], extraBroadcastOrgId: prevOrgIdForBroadcast };
      }

      const t = nowMs();
      const insertRes = await this._q(
        `INSERT INTO clients (org_id, pending_org_id, full_name, device_id, status, socket_id, last_heartbeat, disabled, last_online_at, claimed_org_name)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, 0, $7, $8)
         RETURNING id, org_id, full_name, status`,
        [org.id, fn, dev, 'sharing', socketId, t, t, claimedOrgName]
      );
      await this._q('COMMIT');
      return { success: true, client: insertRes.rows[0], extraBroadcastOrgId: null };
    } catch (e) {
      try { await this._q('ROLLBACK'); } catch {}
      // Fallback path for name conflicts:
      // if same org/full_name exists but is offline, re-bind that record to this device.
      const byNameRes = await this._q(
        'SELECT id, status, socket_id, disabled FROM clients WHERE org_id = $1 AND full_name = $2',
        [org.id, fn]
      );
      const byName = byNameRes.rows[0] || null;

      if (byName && Number(byName.disabled) !== 1 && (byName.status === 'offline' || byName.socket_id == null)) {
        const wasDisconnected = byName.status === 'offline' || byName.socket_id == null;
        const t = nowMs();
        await this._q('BEGIN');
        await this._q(
          `UPDATE clients
           SET device_id = $1, status = $2, socket_id = $3, last_heartbeat = $4, pending_org_id = NULL, claimed_org_name = $5
           WHERE id = $6`,
          [dev, 'sharing', socketId, t, claimedOrgName, byName.id]
        );
        if (wasDisconnected) {
          await this._q('UPDATE clients SET last_online_at = $1 WHERE id = $2', [t, byName.id]);
        }
        const reboundRes = await this._q('SELECT id, org_id, full_name, status FROM clients WHERE id = $1', [byName.id]);
        await this._q('COMMIT');
        return { success: true, client: reboundRes.rows[0], extraBroadcastOrgId: null };
      }

      return { success: false, error: 'CONFLICT', message: 'Client identity conflict (name or device already registered)' };
    }
  }

  async setClientOfflineBySocket(socketId) {
    const r = await this._q('SELECT id, full_name, org_id FROM clients WHERE socket_id = $1', [socketId]);
    const client = r.rows[0] || null;
    if (!client) return null;
    const t = nowMs();
    await this._q('BEGIN');
    try {
      await this._q('UPDATE clients SET status = $1, socket_id = NULL, last_offline_at = $2 WHERE socket_id = $3', ['offline', t, socketId]);
      await this._q(
        `UPDATE sessions SET status = $1, ended_at = $2
         WHERE client_id = $3 AND status IN ($4, $5)`,
        ['ended', nowMs(), client.id, 'pending', 'active']
      );
      await this._q('COMMIT');
    } catch (e) {
      await this._q('ROLLBACK');
      throw e;
    }
    return client;
  }

  async updateClientHeartbeat(socketId) {
    await this._q('UPDATE clients SET last_heartbeat = $1 WHERE socket_id = $2', [nowMs(), socketId]);
  }

  /** Previous WebSocket id for this device, if any (used to close duplicate tabs/reconnects). */
  async getSocketIdForDevice(deviceId) {
    if (typeof deviceId !== 'string' || deviceId.trim().length < 8) return null;
    const r = await this._q('SELECT socket_id FROM clients WHERE device_id = $1', [deviceId.trim()]);
    return r.rows[0]?.socket_id || null;
  }

  async cleanupStaleClients(timeoutMs = 10000) {
    const cutoff = nowMs() - timeoutMs;
    const staleRes = await this._q(
      `SELECT id, full_name, socket_id, org_id
       FROM clients
       WHERE status != $1 AND last_heartbeat < $2 AND last_heartbeat > 0`,
      ['offline', cutoff]
    );
    const stale = staleRes.rows;
    if (stale.length === 0) return [];

    const gone = nowMs();
    await this._q('BEGIN');
    try {
      await this._q(
        `UPDATE clients
         SET status = $1, socket_id = NULL, last_offline_at = $2
         WHERE status != $3 AND last_heartbeat < $4 AND last_heartbeat > 0`,
        ['offline', gone, 'offline', cutoff]
      );
      for (const c of stale) {
        await this._q(
          `UPDATE sessions SET status = $1, ended_at = $2 WHERE client_id = $3 AND status IN ($4, $5)`,
          ['ended', nowMs(), c.id, 'pending', 'active']
        );
      }
      await this._q('COMMIT');
    } catch (e) {
      await this._q('ROLLBACK');
      throw e;
    }
    return stale;
  }

  async getClientsForOrg(orgId) {
    const r = await this._q(
      `SELECT c.id, c.full_name, c.status, c.org_id, o.name as org_name,
              c.claimed_org_name, c.last_heartbeat, c.last_online_at, c.last_offline_at
       FROM clients c
       JOIN organizations o ON o.id = c.org_id
       WHERE c.org_id = ? AND c.disabled = 0
       ORDER BY
         CASE c.status WHEN 'sharing' THEN 0 WHEN 'online' THEN 1 ELSE 2 END,
         c.full_name ASC`
        .replace('WHERE c.org_id = ? AND', 'WHERE c.org_id = $1 AND'),
      [orgId]
    );
    return r.rows;
  }

  async getAllClientsGrouped() {
    const r = await this._q(
      `SELECT c.id, c.full_name, c.status, o.name as org_name, c.org_id,
              c.claimed_org_name, c.last_heartbeat, c.last_online_at, c.last_offline_at
       FROM clients c
       JOIN organizations o ON o.id = c.org_id
       WHERE c.disabled = 0
       ORDER BY o.name ASC,
         CASE c.status WHEN 'sharing' THEN 0 WHEN 'online' THEN 1 ELSE 2 END,
         c.full_name ASC`
    );
    return r.rows;
  }

  async findOnlineClientByOrgAndFullName(orgId, fullName) {
    const fn = normalizeDisplayName(fullName);
    if (!fn) return null;
    const r = await this._q(
      `SELECT id, full_name, status, socket_id, org_id
       FROM clients
       WHERE org_id = ? AND full_name = ? AND disabled = 0`
        .replace('WHERE org_id = ? AND full_name = ?', 'WHERE org_id = $1 AND full_name = $2'),
      [orgId, fn]
    );
    return r.rows[0] || null;
  }

  async getClientById(clientId) {
    if (!Number.isFinite(clientId)) return null;
    const r = await this._q(
      'SELECT id, org_id, full_name, status, socket_id, disabled FROM clients WHERE id = $1',
      [clientId]
    );
    return r.rows[0] || null;
  }

  /** Resolve numeric client id from stable device UUID (client REST ingest auth). */
  async getClientIdByDeviceId(deviceId) {
    if (typeof deviceId !== 'string' || deviceId.trim().length < 8) return null;
    const r = await this._q('SELECT id, disabled FROM clients WHERE device_id = $1', [deviceId.trim()]);
    const row = r.rows[0];
    if (!row || Number(row.disabled) === 1) return null;
    return row.id;
  }

  /**
   * @param {Array<{ clientId: number, type: string, platform: string, occurredAtIso: string, durationMs: number|null, receivedAtMs: number }>} rows
   */
  async insertCallEvents(rows) {
    if (!Array.isArray(rows) || rows.length === 0) return 0;
    await this._q('BEGIN');
    try {
      for (const r of rows) {
        await this._q(
          `INSERT INTO call_events (client_id, type, platform, occurred_at, duration_ms, received_at)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [r.clientId, r.type, r.platform, r.occurredAtIso, r.durationMs, r.receivedAtMs]
        );
      }
      await this._q('COMMIT');
      return rows.length;
    } catch (e) {
      await this._q('ROLLBACK');
      throw e;
    }
  }

  /**
   * @param {Array<{ clientId: number, occurredAtIso: string, openedJson: string, closedJson: string, openAppsJson: string, receivedAtMs: number }>} rows
   */
  async insertTaskbarEvents(rows) {
    if (!Array.isArray(rows) || rows.length === 0) return 0;
    /** One multi-row INSERT per chunk — far fewer round trips than per-row INSERTs inside a transaction. */
    const CHUNK = 400;
    let total = 0;
    for (let offset = 0; offset < rows.length; offset += CHUNK) {
      const chunk = rows.slice(offset, offset + CHUNK);
      const placeholders = [];
      const params = [];
      let p = 1;
      for (const r of chunk) {
        placeholders.push(
          `($${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++})`
        );
        params.push(
          r.clientId,
          r.occurredAtIso,
          r.receivedAtMs,
          r.openedJson,
          r.closedJson,
          r.openAppsJson
        );
      }
      await this._q(
        `INSERT INTO taskbar_events (client_id, occurred_at, received_at, opened_json, closed_json, open_apps_json)
         VALUES ${placeholders.join(', ')}`,
        params
      );
      total += chunk.length;
    }
    return total;
  }

  /**
   * @param {Array<{ clientId: number, occurredAtIso: string, receivedAtMs: number, browserName: string, activeTabId: number|null, reason: string, sessionJson: string, switchLogJson: string, tabsJson: string }>} rows
   */
  async insertBrowserTabEvents(rows) {
    if (!Array.isArray(rows) || rows.length === 0) return 0;
    await this._q('BEGIN');
    try {
      for (const r of rows) {
        await this._q(
          `INSERT INTO browser_tab_events (client_id, occurred_at, received_at, browser_name, active_tab_id, reason, session_json, switch_log_json, tabs_json)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [r.clientId, r.occurredAtIso, r.receivedAtMs, r.browserName, r.activeTabId, r.reason, r.sessionJson, r.switchLogJson, r.tabsJson]
        );
      }
      await this._q('COMMIT');
      return rows.length;
    } catch (e) {
      await this._q('ROLLBACK');
      throw e;
    }
  }

  /**
   * @param {{ adminRole: string, adminOrgId: number|null, clientId?: number|null, page: number, limit: number }}
   */
  async listCallEventsForAdmin({ adminRole, adminOrgId, clientId, page, limit }) {
    const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
    const pg = Math.max(Number(page) || 1, 1);
    const offset = (pg - 1) * lim;

    let where = 'WHERE 1=1';
    const params = [];

    if (clientId != null && Number.isFinite(Number(clientId))) {
      where += ` AND ce.client_id = $${params.length + 1}`;
      params.push(Number(clientId));
    }

    if (adminRole === 'org_admin' && adminOrgId != null && Number.isFinite(adminOrgId)) {
      where += ` AND c.org_id = $${params.length + 1}`;
      params.push(adminOrgId);
    }

    const q = `
      SELECT
        ce.id,
        ce.client_id AS clientId,
        ce.type,
        ce.platform,
        ce.occurred_at AS timestamp,
        ce.duration_ms AS duration_ms,
        ce.received_at AS receivedAt
      FROM call_events ce
      INNER JOIN clients c ON c.id = ce.client_id AND c.disabled = 0
      ${where}
      ORDER BY ce.id DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;
    const r = await this._q(q, [...params, lim, offset]);
    return r.rows.map((row) => ({
      id: row.id,
      clientId: row.clientid ?? row.clientId,
      type: row.type,
      platform: row.platform,
      timestamp: row.timestamp,
      duration_ms: row.duration_ms == null ? null : row.duration_ms,
      receivedAt: row.receivedat ?? row.receivedAt,
    }));
  }

  async listTaskbarEventsForAdmin({ adminRole, adminOrgId, clientId, page, limit }) {
    const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
    const pg = Math.max(Number(page) || 1, 1);
    const offset = (pg - 1) * lim;

    let where = 'WHERE 1=1';
    const params = [];

    if (clientId != null && Number.isFinite(Number(clientId))) {
      where += ` AND te.client_id = $${params.length + 1}`;
      params.push(Number(clientId));
    }

    if (adminRole === 'org_admin' && adminOrgId != null && Number.isFinite(adminOrgId)) {
      where += ` AND c.org_id = $${params.length + 1}`;
      params.push(adminOrgId);
    }

    const q = `
      SELECT
        te.id,
        te.client_id AS clientId,
        te.occurred_at AS timestamp,
        te.received_at AS receivedAt,
        te.opened_json AS openedJson,
        te.closed_json AS closedJson,
        te.open_apps_json AS openAppsJson
      FROM taskbar_events te
      INNER JOIN clients c ON c.id = te.client_id AND c.disabled = 0
      ${where}
      ORDER BY te.id DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;
    const r = await this._q(q, [...params, lim, offset]);
    return r.rows.map((row) => ({
      id: row.id,
      clientId: row.clientid ?? row.clientId,
      timestamp: row.timestamp,
      openedJson: row.openedjson ?? row.openedJson,
      closedJson: row.closedjson ?? row.closedJson,
      openAppsJson: row.openappsjson ?? row.openAppsJson,
      receivedAt: row.receivedat ?? row.receivedAt,
    }));
  }

  async listBrowserTabEventsForAdmin({
    adminRole,
    adminOrgId,
    clientId,
    page,
    limit,
    sinceReceivedAtMs,
  }) {
    const hasSince =
      sinceReceivedAtMs != null && Number.isFinite(Number(sinceReceivedAtMs));
    const maxLim = hasSince ? 4000 : 200;
    const lim = Math.min(Math.max(Number(limit) || 50, 1), maxLim);
    const pg = Math.max(Number(page) || 1, 1);
    const offset = (pg - 1) * lim;

    let where = 'WHERE 1=1';
    const params = [];

    if (clientId != null && Number.isFinite(Number(clientId))) {
      where += ` AND bte.client_id = $${params.length + 1}`;
      params.push(Number(clientId));
    }

    if (adminRole === 'org_admin' && adminOrgId != null && Number.isFinite(adminOrgId)) {
      where += ` AND c.org_id = $${params.length + 1}`;
      params.push(adminOrgId);
    }

    if (hasSince) {
      where += ` AND bte.received_at >= $${params.length + 1}`;
      params.push(Number(sinceReceivedAtMs));
    }

    const q = `
      SELECT
        bte.id,
        bte.client_id AS clientId,
        bte.occurred_at AS timestamp,
        bte.received_at AS receivedAt,
        bte.browser_name AS browserName,
        bte.active_tab_id AS activeTabId,
        bte.reason AS reason,
        bte.session_json AS sessionJson,
        bte.switch_log_json AS switchLogJson,
        bte.tabs_json AS tabsJson
      FROM browser_tab_events bte
      INNER JOIN clients c ON c.id = bte.client_id AND c.disabled = 0
      ${where}
      ORDER BY bte.received_at DESC, bte.id DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;
    const r = await this._q(q, [...params, lim, offset]);
    return r.rows.map((row) => ({
      id: row.id,
      clientId: row.clientid ?? row.clientId,
      timestamp: row.timestamp,
      receivedAt: row.receivedat ?? row.receivedAt,
      browserName: row.browsername ?? row.browserName,
      activeTabId: row.activetabid ?? row.activeTabId,
      reason: row.reason,
      sessionJson: row.sessionjson ?? row.sessionJson,
      switchLogJson: row.switchlogjson ?? row.switchLogJson,
      tabsJson: row.tabsjson ?? row.tabsJson,
    }));
  }

  async getClientByOrgAndFullName(orgId, fullName) {
    const fn = normalizeDisplayName(fullName);
    if (!fn) return null;
    const r = await this._q(
      'SELECT id, org_id, full_name, status, socket_id, disabled FROM clients WHERE org_id = $1 AND full_name = $2',
      [orgId, fn]
    );
    return r.rows[0] || null;
  }

  async setClientPendingOrg(clientId, pendingOrgId) {
    await this._q('UPDATE clients SET pending_org_id = $1 WHERE id = $2', [pendingOrgId, clientId]);
  }

  async setClientOrgNow(clientId, orgId) {
    // Immediate org switch after transfer approval, so dashboards reflect the change right away.
    // Also clears any deferred pending_org_id.
    if (!Number.isFinite(clientId) || !Number.isFinite(orgId)) return;
    await this._q(
      `UPDATE clients SET org_id = $1, pending_org_id = NULL WHERE id = $2`,
      [orgId, clientId]
    );
  }

  // ─── Transfer Requests ───
  async createTransferRequest({ clientId, fromOrgId, toOrgId, requestedByAdminId }) {
    if (!Number.isFinite(clientId) || !Number.isFinite(fromOrgId) || !Number.isFinite(toOrgId) || !Number.isFinite(requestedByAdminId)) {
      return { success: false, error: 'INVALID_INPUT', message: 'Invalid transfer request' };
    }
    if (fromOrgId === toOrgId) {
      return { success: false, error: 'INVALID_INPUT', message: 'Source and target organizations must differ' };
    }

    // Enforce at most one pending request per client to avoid concurrent transfer races.
    const pendingRes = await this._q(
      `SELECT id FROM transfer_requests WHERE client_id = $1 AND status = 'pending' ORDER BY id DESC LIMIT 1`,
      [clientId]
    );
    const pendingForClient = pendingRes.rows[0];
    if (pendingForClient) {
      return { success: true, requestId: pendingForClient.id, deduped: true };
    }

    // Also dedupe same client/target request if it races in before the first check.
    const existingRes = await this._q(
      `SELECT id FROM transfer_requests WHERE client_id = $1 AND to_org_id = $2 AND status = 'pending' ORDER BY id DESC LIMIT 1`,
      [clientId, toOrgId]
    );
    const existing = existingRes.rows[0];
    if (existing) {
      return { success: true, requestId: existing.id, deduped: true };
    }

    const res = await this._q(
      `INSERT INTO transfer_requests (client_id, from_org_id, to_org_id, requested_by_admin_id, status, updated_at)
       VALUES ($1, $2, $3, $4, 'pending', $5) RETURNING id`,
      [clientId, fromOrgId, toOrgId, requestedByAdminId, nowMs()]
    );
    return { success: true, requestId: res.rows[0]?.id, deduped: false };
  }

  async listTransferRequests({ adminRole, adminOrgId }) {
    if (adminRole === 'super_admin' || adminRole === 'it_ops') {
      const r = await this._q(`
        SELECT
          tr.id,
          tr.client_id,
          c.full_name AS client_full_name,
          tr.from_org_id,
          ofrom.name AS from_org_name,
          tr.to_org_id,
          oto.name AS to_org_name,
          tr.requested_by_admin_id,
          a.full_name AS requested_by_full_name,
          tr.approved_by_admin_id,
          a2.full_name AS approved_by_full_name,
          tr.status,
          tr.created_at,
          tr.updated_at
        FROM transfer_requests tr
        JOIN clients c ON c.id = tr.client_id
        JOIN organizations ofrom ON ofrom.id = tr.from_org_id
        JOIN organizations oto ON oto.id = tr.to_org_id
        JOIN admins a ON a.id = tr.requested_by_admin_id
        LEFT JOIN admins a2 ON a2.id = tr.approved_by_admin_id
        ORDER BY tr.id DESC
        LIMIT 200
      `);
      return r.rows;
    }

    const r = await this._q(`
      SELECT
        tr.id,
        tr.client_id,
        c.full_name AS client_full_name,
        tr.from_org_id,
        ofrom.name AS from_org_name,
        tr.to_org_id,
        oto.name AS to_org_name,
        tr.requested_by_admin_id,
        a.full_name AS requested_by_full_name,
        tr.approved_by_admin_id,
        a2.full_name AS approved_by_full_name,
        tr.status,
        tr.created_at,
        tr.updated_at
      FROM transfer_requests tr
      JOIN clients c ON c.id = tr.client_id
      JOIN organizations ofrom ON ofrom.id = tr.from_org_id
      JOIN organizations oto ON oto.id = tr.to_org_id
      JOIN admins a ON a.id = tr.requested_by_admin_id
      LEFT JOIN admins a2 ON a2.id = tr.approved_by_admin_id
      WHERE tr.from_org_id = $1 OR tr.to_org_id = $2
      ORDER BY tr.id DESC
      LIMIT 200
    `, [adminOrgId, adminOrgId]);
    return r.rows;
  }

  async getTransferRequestById(requestId) {
    if (!Number.isFinite(requestId)) return null;
    const r = await this._q(`
      SELECT
        tr.*,
        c.full_name AS client_full_name,
        c.org_id AS client_org_id
      FROM transfer_requests tr
      JOIN clients c ON c.id = tr.client_id
      WHERE tr.id = $1
    `, [requestId]);
    return r.rows[0] || null;
  }

  async updateTransferRequestStatus({ requestId, status, approvedByAdminId }) {
    if (!Number.isFinite(requestId) || !['approved', 'rejected'].includes(status)) {
      return { success: false, error: 'INVALID_INPUT', message: 'Invalid status update' };
    }
    await this._q(
      `UPDATE transfer_requests
       SET status = $1, approved_by_admin_id = $2, updated_at = $3
       WHERE id = $4`,
      [status, approvedByAdminId ?? null, nowMs(), requestId]
    );
    return { success: true };
  }

  async disableClient(clientId) {
    await this._q('UPDATE clients SET disabled = 1, status = $1, socket_id = NULL WHERE id = $2', ['offline', clientId]);
  }

  // ─── Sessions ───
  async createSession(orgId, clientId, adminId) {
    const r = await this._q(
      'INSERT INTO sessions (org_id, client_id, admin_id, status) VALUES ($1, $2, $3, $4) RETURNING id',
      [orgId, clientId, adminId ?? null, 'pending']
    );
    return r.rows[0]?.id;
  }

  /** True if this admin has a pending or active viewing session for the client (WebRTC signaling gate). */
  async hasActiveViewingSession(adminId, clientId) {
    const aid = Number(adminId);
    const cid = Number(clientId);
    if (!Number.isFinite(aid) || aid <= 0 || !Number.isFinite(cid) || cid <= 0) return false;
    const r = await this._q(
      `SELECT 1 FROM sessions
       WHERE admin_id = $1 AND client_id = $2 AND status IN ('pending', 'active')
       LIMIT 1`,
      [aid, cid]
    );
    return r.rows.length > 0;
  }

  /** Viewing session row if id matches client and is still open (pending/active). */
  async getViewingSessionForClient(sessionId, clientId) {
    const sid = Number(sessionId);
    const cid = Number(clientId);
    if (!Number.isFinite(sid) || sid <= 0 || !Number.isFinite(cid) || cid <= 0) return null;
    const r = await this._q(
      `SELECT id, admin_id, client_id, status FROM sessions
       WHERE id = $1 AND client_id = $2 AND status IN ('pending', 'active')
       LIMIT 1`,
      [sid, cid]
    );
    return r.rows[0] || null;
  }

  /** Viewing session row by id if still open (pending/active). */
  async getViewingSessionById(sessionId) {
    const sid = Number(sessionId);
    if (!Number.isFinite(sid) || sid <= 0) return null;
    const r = await this._q(
      `SELECT id, admin_id, client_id, status FROM sessions
       WHERE id = $1 AND status IN ('pending', 'active')
       LIMIT 1`,
      [sid]
    );
    return r.rows[0] || null;
  }

  /** Most recent open viewing session for admin<->client pair. */
  async getLatestActiveViewingSession(adminId, clientId) {
    const aid = Number(adminId);
    const cid = Number(clientId);
    if (!Number.isFinite(aid) || aid <= 0 || !Number.isFinite(cid) || cid <= 0) return null;
    const r = await this._q(
      `SELECT id, admin_id, client_id, status FROM sessions
       WHERE admin_id = $1 AND client_id = $2 AND status IN ('pending', 'active')
       ORDER BY id DESC
       LIMIT 1`,
      [aid, cid]
    );
    return r.rows[0] || null;
  }

  async insertIcePathReport({ sessionId, clientId, adminId, localType, remoteType, usingTurn, timeToIceMs, reportedAtMs }) {
    const t = reportedAtMs != null && Number.isFinite(Number(reportedAtMs)) ? Number(reportedAtMs) : nowMs();
    await this._q(
      `INSERT INTO ice_path_reports (session_id, client_id, admin_id, local_type, remote_type, using_turn, time_to_ice_ms, reported_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        Number(sessionId),
        Number(clientId),
        adminId != null && Number.isFinite(Number(adminId)) ? Number(adminId) : null,
        localType != null ? String(localType).slice(0, 32) : null,
        remoteType != null ? String(remoteType).slice(0, 32) : null,
        !!usingTurn,
        timeToIceMs != null && Number.isFinite(Number(timeToIceMs)) ? Math.trunc(Number(timeToIceMs)) : null,
        t,
      ]
    );
  }

  async recordIcePathReport({
    socketId,
    orgId,
    candidateType,
    phase,
    clientId,
    sessionId,
    rtt,
    localType,
    remoteType,
    usingTurn,
    timeToIceMs,
    adminId,
  }) {
    void socketId;
    const sid = Number(sessionId);
    const cid = Number(clientId);
    if (!Number.isFinite(sid) || sid <= 0 || !Number.isFinite(cid) || cid <= 0) {
      return;
    }
    const normalizedCandidateType =
      typeof candidateType === 'string' && candidateType.trim() ? candidateType.trim().slice(0, 32) : null;
    const normalizedPhase = Number.isFinite(Number(phase)) ? Math.trunc(Number(phase)) : null;
    const normalizedRtt = Number.isFinite(Number(rtt)) ? Math.trunc(Number(rtt)) : null;
    const normalizedLocalType =
      localType != null ? String(localType).slice(0, 32) : normalizedCandidateType;
    try {
      await this._q(
        `INSERT INTO ice_path_reports (
          session_id, client_id, admin_id, org_id, local_type, remote_type, using_turn,
          time_to_ice_ms, candidate_type, phase, rtt_ms, reported_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [
          sid,
          cid,
          adminId != null && Number.isFinite(Number(adminId)) ? Number(adminId) : null,
          orgId != null ? String(orgId) : null,
          normalizedLocalType,
          remoteType != null ? String(remoteType).slice(0, 32) : null,
          usingTurn != null ? !!usingTurn : normalizedCandidateType === 'relay',
          timeToIceMs != null && Number.isFinite(Number(timeToIceMs)) ? Math.trunc(Number(timeToIceMs)) : null,
          normalizedCandidateType,
          normalizedPhase,
          normalizedRtt,
          nowMs(),
        ]
      );
    } catch (err) {
      console.error('[DB] recordIcePathReport failed:', err?.message || err);
    }
  }

  async resetAllOnStartup() {
    // Keep orgs/admins/sessions; just mark clients offline and end active sessions.
    await this._q('BEGIN');
    try {
      await this._q('UPDATE clients SET status = $1, socket_id = NULL', ['offline']);
      await this._q(
        'UPDATE sessions SET status = $1, ended_at = $2 WHERE status IN ($3, $4)',
        ['ended', nowMs(), 'pending', 'active']
      );
      await this._q('COMMIT');
    } catch (e) {
      await this._q('ROLLBACK');
      throw e;
    }
  }

  /** Defaults for super-admin “Functionality” toggles (what org_admin may see). */
  defaultAdminUiFeatures() {
    return {
      online_tab: true,
      transfer_tab: true,
      member_presence: true,
      member_call_detection: true,
      activity_center: true,
      stream_layout_tools: true,
    };
  }

  async getAdminUiFeatures() {
    const defaults = this.defaultAdminUiFeatures();
    const r = await this._q('SELECT value FROM app_settings WHERE key = $1', ['admin_ui_features']);
    const row = r.rows[0];
    if (!row || typeof row.value !== 'string') return { ...defaults };
    try {
      const parsed = JSON.parse(row.value);
      if (typeof parsed !== 'object' || parsed == null) return { ...defaults };
      const out = { ...defaults };
      for (const k of Object.keys(defaults)) {
        if (typeof parsed[k] === 'boolean') out[k] = parsed[k];
      }
      return out;
    } catch {
      return { ...defaults };
    }
  }

  /**
   * Merge boolean flags into stored admin UI features. Unknown keys ignored.
   * @returns {object} merged feature map
   */
  async setAdminUiFeaturesPatch(patch) {
    const defaults = this.defaultAdminUiFeatures();
    const cur = await this.getAdminUiFeatures();
    const next = { ...cur };
    if (patch && typeof patch === 'object') {
      for (const k of Object.keys(defaults)) {
        if (Object.prototype.hasOwnProperty.call(patch, k) && typeof patch[k] === 'boolean') {
          next[k] = patch[k];
        }
      }
    }
    const json = JSON.stringify(next);
    await this._q(
      `INSERT INTO app_settings (key, value) VALUES ($1, $2)
       ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value`,
      ['admin_ui_features', json]
    );
    return next;
  }

  // ─── Remote access (office IP bypass grants) ───
  async createRemoteAccessRequest({ adminId, orgId, requesterIp, reason, durationHours }) {
    const r = await this._q(
      `INSERT INTO remote_access_requests
         (admin_id, org_id, requester_ip, reason, duration_hours, status)
       VALUES ($1, $2, $3, $4, $5, 'pending')
       RETURNING *`,
      [adminId, orgId, requesterIp, reason, durationHours]
    );
    return r.rows[0] || null;
  }

  async approveRemoteAccessRequest({ requestId, approvedByAdminId }) {
    const r = await this._q(
      `UPDATE remote_access_requests
       SET status = 'approved',
           approved_by = $2,
           approved_at = NOW(),
           expires_at = NOW() + (duration_hours * INTERVAL '1 hour')
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [requestId, approvedByAdminId]
    );
    return r.rows[0] || null;
  }

  async denyRemoteAccessRequest({ requestId, approvedByAdminId }) {
    const r = await this._q(
      `UPDATE remote_access_requests
       SET status = 'denied', approved_by = $2, approved_at = NOW()
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [requestId, approvedByAdminId]
    );
    return r.rows[0] || null;
  }

  async getActiveRemoteAccess(adminId) {
    const r = await this._q(
      `SELECT * FROM remote_access_requests
       WHERE admin_id = $1
         AND status = 'approved'
         AND expires_at > NOW()
       ORDER BY expires_at DESC
       LIMIT 1`,
      [adminId]
    );
    return r.rows[0] || null;
  }

  async getPendingRemoteAccessRequestsForOrg(orgId) {
    const r = await this._q(
      `SELECT r.*, a.username AS requester_name, a.role AS requester_role
       FROM remote_access_requests r
       JOIN admins a ON a.id = r.admin_id
       WHERE r.org_id = $1 AND r.status = 'pending'
       ORDER BY r.created_at DESC`,
      [orgId]
    );
    return r.rows;
  }

  async getAllPendingRemoteAccessRequests() {
    const r = await this._q(
      `SELECT r.*, a.username AS requester_name, a.role AS requester_role,
              o.name AS org_name
       FROM remote_access_requests r
       JOIN admins a ON a.id = r.admin_id
       JOIN organizations o ON o.id = r.org_id
       WHERE r.status = 'pending'
       ORDER BY r.created_at DESC`
    );
    return r.rows;
  }

  async getMyRemoteAccessRequests(adminId) {
    const r = await this._q(
      `SELECT * FROM remote_access_requests
       WHERE admin_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [adminId]
    );
    return r.rows;
  }

  async expireRemoteAccessRequests() {
    await this._q(
      `UPDATE remote_access_requests
       SET status = 'expired'
       WHERE status = 'approved' AND expires_at <= NOW()`
    );
  }

  // ─── Stream relay (TURN) for org_admin viewers ───
  async createStreamRelayRequest({ adminId, orgId, requesterIp, reason, durationHours }) {
    const r = await this._q(
      `INSERT INTO stream_relay_requests
         (admin_id, org_id, requester_ip, reason, duration_hours, status)
       VALUES ($1, $2, $3, $4, $5, 'pending')
       RETURNING *`,
      [adminId, orgId, requesterIp, reason, durationHours]
    );
    return r.rows[0] || null;
  }

  async approveStreamRelayRequest({ requestId, approvedByAdminId }) {
    const r = await this._q(
      `UPDATE stream_relay_requests
       SET status = 'approved',
           approved_by = $2,
           approved_at = NOW(),
           expires_at = NOW() + (duration_hours * INTERVAL '1 hour')
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [requestId, approvedByAdminId]
    );
    return r.rows[0] || null;
  }

  async denyStreamRelayRequest({ requestId, approvedByAdminId }) {
    const r = await this._q(
      `UPDATE stream_relay_requests
       SET status = 'denied', approved_by = $2, approved_at = NOW()
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [requestId, approvedByAdminId]
    );
    return r.rows[0] || null;
  }

  async getActiveStreamRelay(adminId) {
    const r = await this._q(
      `SELECT * FROM stream_relay_requests
       WHERE admin_id = $1
         AND status = 'approved'
         AND expires_at > NOW()
       ORDER BY expires_at DESC
       LIMIT 1`,
      [adminId]
    );
    return r.rows[0] || null;
  }

  async getAllPendingStreamRelayRequests() {
    const r = await this._q(
      `SELECT r.*, a.username AS requester_name, a.role AS requester_role,
              o.name AS org_name
       FROM stream_relay_requests r
       JOIN admins a ON a.id = r.admin_id
       JOIN organizations o ON o.id = r.org_id
       WHERE r.status = 'pending'
       ORDER BY r.created_at DESC`
    );
    return r.rows;
  }

  async getMyStreamRelayRequests(adminId) {
    const r = await this._q(
      `SELECT * FROM stream_relay_requests
       WHERE admin_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [adminId]
    );
    return r.rows;
  }

  async expireStreamRelayRequests() {
    await this._q(
      `UPDATE stream_relay_requests
       SET status = 'expired'
       WHERE status = 'approved' AND expires_at <= NOW()`
    );
  }

  async close() {
    await this.pool.end();
  }
}

module.exports = SignalingDatabase;
