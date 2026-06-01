# Railway: signaling + audit + Electron apps

Your public URLs:

| Service | URL |
|--------|-----|
| **Signaling** (WebSocket + HTTP API) | `https://bug-free-robot-production.up.railway.app` |
| **Audit dashboard** (Next.js) | `https://stunning-octo-umbrella-production-f5bc.up.railway.app` |

WebSocket for apps: `wss://bug-free-robot-production.up.railway.app`

---

## 1. Signaling service (Railway variables)

Set in the **signaling** project → Variables:

| Variable | Example / notes |
|----------|-----------------|
| `AUDIT_DASHBOARD_URL` | `https://stunning-octo-umbrella-production-f5bc.up.railway.app` (no trailing slash) |
| `AUDIT_SUPERADMIN_SERVICE_SECRET` | Long random string; **must equal** the same variable on the **audit** service |
| `WS_CONNECT_TOKEN` | Same value as in admin + client + audit `.env` (`NEXT_PUBLIC_WS_CONNECT_TOKEN`) |
| `ENFORCE_TLS` | `true` in production |
| Plus existing DB / Supabase / ingest / TURN vars | unchanged |

After deploy, signaling can reach audit at  
`GET/POST …/api/superadmin/audit-org-access` for the Admin Electron “Audit access” tab.

---

## 2. Audit service (Railway variables)

| Variable | Example / notes |
|----------|-----------------|
| `AUDIT_SUPERADMIN_SERVICE_SECRET` | **Same** as signaling |
| `NEXT_PUBLIC_APP_URL` | `https://stunning-octo-umbrella-production-f5bc.up.railway.app` |
| `NEXT_PUBLIC_ANYWHERE_SIGNALING_WSS` | `wss://bug-free-robot-production.up.railway.app` |
| `NEXT_PUBLIC_WS_CONNECT_TOKEN` | Same as signaling `WS_CONNECT_TOKEN` |
| `JWT_SECRET` | Strong random string (≥32 chars), **not** the placeholder |
| Supabase keys | As now |

Redeploy audit after changing env.

---

## 3. Admin Electron (`admin-dashboard/.env`)

Build/run with:

```env
ANYWHERE_SIGNALING_WSS=wss://bug-free-robot-production.up.railway.app
ANYWHERE_SIGNALING_HTTP=https://bug-free-robot-production.up.railway.app
WS_CONNECT_TOKEN=<same as Railway WS_CONNECT_TOKEN>
```

No `AUDIT_DASHBOARD_URL` in admin — audit calls go **through signaling**.

---

## 4. Client Electron (`client-dashboard/.env`)

Same signaling lines as admin:

```env
ANYWHERE_SIGNALING_WSS=wss://bug-free-robot-production.up.railway.app
ANYWHERE_SIGNALING_HTTP=https://bug-free-robot-production.up.railway.app
WS_CONNECT_TOKEN=<same as Railway WS_CONNECT_TOKEN>
```

---

## 5. Quick verification

1. Open audit in browser:  
   `https://stunning-octo-umbrella-production-f5bc.up.railway.app` → should load.
2. From your PC (optional):  
   `curl -sI "https://stunning-octo-umbrella-production-f5bc.up.railway.app/api/superadmin/audit-org-access"`  
   → expect **401** (not connection error).
3. On Railway signaling logs, after opening **Audit access** in Admin, you should **not** see `fetch failed` if `AUDIT_DASHBOARD_URL` is correct.

Local script (from repo, audit must be reachable):

```bash
cd signaling-server && npm run verify:audit-proxy
```

Use a `.env` where `AUDIT_DASHBOARD_URL` is the **public** audit Railway URL.
