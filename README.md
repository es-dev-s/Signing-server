# AnyWhere Signaling Server

WebSocket signaling backend for AnyWhere desktop apps (admin + client).

## Database (Supabase/Postgres)

- Run `supabase_migration.sql` once in Supabase SQL Editor to create the tables (safe to re-run).
- Set env vars (Railway/local): `SUPABASE_DATABASE_URL` (or `DATABASE_URL`), `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_REQUIRE_SSL=true`.
- Optional: `PG_CONNECT_TIMEOUT_MS` (default 10000), `PG_POOL_MAX`, `PG_IDLE_TIMEOUT_MS`.
- Health check locally: `npm run db:check` (loads `.env`, runs `SELECT 1`, prints timing).

## Why cross-network failed before

Your apps were using STUN only. STUN works on same LAN often, but fails across different NAT/firewall networks.
For production, you need TURN relay fallback.

## What is implemented now

- Server includes `iceServers` in the `welcome` message.
- Admin and Client apps consume that dynamic `iceServers` config.
- If no env config is provided, apps fall back to public STUN servers.

## Configure ICE/TURN (Railway)

Set one of these env vars on signaling server:

- `ICE_SERVERS_JSON` (preferred)
- `ANYWHERE_ICE_SERVERS_JSON` (backward alias)

Example:

```json
[
  { "urls": ["stun:stun.l.google.com:19302", "stun:global.stun.twilio.com:3478"] },
  {
    "urls": [
      "turn:your-turn-domain:3478?transport=udp",
      "turn:your-turn-domain:3478?transport=tcp",
      "turns:your-turn-domain:443?transport=tcp"
    ],
    "username": "your-turn-username",
    "credential": "your-turn-password"
  }
]
```

Notes:
- Use `turns:...:443?transport=tcp` for restrictive enterprise networks.
- Keep both STUN and TURN entries.

## No-payment option (self-host TURN)

You do not need a paid API vendor. You can self-host `coturn` on a small VM.

High-level steps:
1. Deploy VM with public IP (Ubuntu).
2. Open firewall ports: `3478` (udp/tcp) and `443` (tcp).  
   Optional relay range: `49152-65535` UDP.
3. Install and configure `coturn` with a static username/password or shared-secret auth.
4. Put that TURN host into `ICE_SERVERS_JSON` on Railway.
5. Restart signaling server.

## Runtime check

After deploy:
- Open admin + client on different networks.
- Confirm both connect to signaling.
- Confirm WebRTC session succeeds and stream opens.
- If it still fails, verify TURN reachability from client networks (especially 443/tcp).

## WebSocket handshake token

Set `WS_CONNECT_TOKEN` on:
- `signaling-server/.env` (or Railway env)
- `admin-dashboard/.env`
- `client-dashboard/.env`

The signaling server now verifies this token during the WebSocket handshake from either:
- query string: `?token=...`
- header: `x-ws-token`

If token is missing or mismatched, the handshake is rejected with `401 Unauthorized`.
