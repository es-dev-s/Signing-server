-- AnyWhere Signaling Server schema (Supabase / Postgres)
-- Paste this whole file into Supabase SQL Editor and run.
--
-- Goal: Mirror the SQLite schema/constraints used by `signaling-server/database.js`
-- so the rest of the codebase can keep the same logic and data expectations.
--
-- Notes:
-- - Many timestamps in the app are stored as INTEGER milliseconds (`nowMs()`), but
--   some `created_at` fields were SQLite seconds (strftime('%s','now')). We keep
--   those as BIGINT seconds to preserve semantics.
-- - `occurred_at` stays TEXT (ISO-8601 string) because the app stores/queries it as text.

begin;

-- ─────────────────────────────────────────────────────────────────────────────
-- Core tables
-- ─────────────────────────────────────────────────────────────────────────────

create table if not exists public.organizations (
  id bigserial primary key,
  name text not null unique,
  created_at bigint not null default (extract(epoch from now())::bigint)
);

-- Optional team branding (HTTPS URL to PNG/SVG/WebP in Supabase Storage or CDN).
alter table public.organizations add column if not exists logo_url text null;

create table if not exists public.admins (
  id bigserial primary key,
  org_id bigint null references public.organizations(id) on delete set null,
  username text not null,
  full_name text not null,
  password_hash text not null,
  role text not null,
  created_at bigint not null default (extract(epoch from now())::bigint),
  constraint admins_role_check check (role in ('super_admin', 'org_admin', 'it_ops'))
);

create unique index if not exists idx_admins_org_username on public.admins(org_id, username);

create table if not exists public.admin_sessions (
  id bigserial primary key,
  admin_id bigint not null references public.admins(id) on delete cascade,
  token text not null unique,
  expires_at bigint not null,
  created_at bigint not null default (extract(epoch from now())::bigint)
);

create index if not exists idx_admin_sessions_admin on public.admin_sessions(admin_id);
create index if not exists idx_admin_sessions_expires on public.admin_sessions(expires_at);

-- Clients are v2 schema from SQLite migration logic.
create table if not exists public.clients (
  id bigserial primary key,
  org_id bigint not null references public.organizations(id) on delete restrict,
  pending_org_id bigint null references public.organizations(id) on delete set null,
  full_name text not null,
  device_id text unique,
  status text not null default 'offline',
  socket_id text null,
  last_heartbeat bigint not null default 0,
  disabled int not null default 0,
  created_at bigint not null default (extract(epoch from now())::bigint),
  last_online_at bigint null,
  last_offline_at bigint null,
  claimed_org_name text null,
  constraint clients_status_check check (status in ('online', 'offline', 'sharing')),
  constraint clients_disabled_check check (disabled in (0, 1))
);

create unique index if not exists idx_clients_org_full_name on public.clients(org_id, full_name);
create index if not exists idx_clients_status on public.clients(status);
create index if not exists idx_clients_socket on public.clients(socket_id);
create index if not exists idx_clients_device on public.clients(device_id);

create table if not exists public.sessions (
  id bigserial primary key,
  org_id bigint not null references public.organizations(id) on delete restrict,
  client_id bigint not null references public.clients(id) on delete cascade,
  admin_id bigint null references public.admins(id) on delete set null,
  status text not null default 'pending',
  created_at bigint not null default (extract(epoch from now())::bigint),
  ended_at bigint null,
  constraint sessions_status_check check (status in ('pending', 'active', 'ended'))
);

create index if not exists idx_sessions_org on public.sessions(org_id);
create index if not exists idx_sessions_client on public.sessions(client_id);

create table if not exists public.transfer_requests (
  id bigserial primary key,
  client_id bigint not null references public.clients(id) on delete cascade,
  from_org_id bigint not null references public.organizations(id) on delete restrict,
  to_org_id bigint not null references public.organizations(id) on delete restrict,
  requested_by_admin_id bigint not null references public.admins(id) on delete restrict,
  approved_by_admin_id bigint null references public.admins(id) on delete set null,
  status text not null default 'pending',
  created_at bigint not null default (extract(epoch from now())::bigint),
  updated_at bigint null,
  constraint transfer_requests_status_check check (status in ('pending', 'approved', 'rejected'))
);

create index if not exists idx_transfer_requests_status on public.transfer_requests(status);
create index if not exists idx_transfer_requests_from_org on public.transfer_requests(from_org_id);
create index if not exists idx_transfer_requests_to_org on public.transfer_requests(to_org_id);
create index if not exists idx_transfer_requests_client on public.transfer_requests(client_id);

create table if not exists public.call_events (
  id bigserial primary key,
  client_id bigint not null references public.clients(id) on delete cascade,
  type text not null,
  platform text not null,
  occurred_at text not null,
  duration_ms bigint null,
  received_at bigint not null,
  constraint call_events_type_check check (type in ('call_start', 'call_end'))
);

create index if not exists idx_call_events_client on public.call_events(client_id);
create index if not exists idx_call_events_occurred on public.call_events(occurred_at);

create table if not exists public.taskbar_events (
  id bigserial primary key,
  client_id bigint not null references public.clients(id) on delete cascade,
  occurred_at text not null,
  received_at bigint not null,
  opened_json text null,
  closed_json text null,
  open_apps_json text null
);

create index if not exists idx_taskbar_events_client on public.taskbar_events(client_id);
create index if not exists idx_taskbar_events_occurred on public.taskbar_events(occurred_at);

create table if not exists public.browser_tab_events (
  id bigserial primary key,
  client_id bigint not null references public.clients(id) on delete cascade,
  occurred_at text not null,
  received_at bigint not null,
  browser_name text null,
  active_tab_id bigint null,
  reason text null,
  session_json text null,
  switch_log_json text null,
  tabs_json text null
);

create index if not exists idx_browser_tab_events_client on public.browser_tab_events(client_id);
create index if not exists idx_browser_tab_events_occurred on public.browser_tab_events(occurred_at);
-- Ingest time (ms) — used for rolling retention of extension/browser snapshots only
create index if not exists idx_browser_tab_events_received_at on public.browser_tab_events(received_at);

alter table public.browser_tab_events add column if not exists reason text null;
alter table public.browser_tab_events add column if not exists session_json text null;
alter table public.browser_tab_events add column if not exists switch_log_json text null;

create table if not exists public.app_settings (
  key text primary key,
  value text not null
);

-- Required for existing runtime: database init assumes there's a default org.
insert into public.organizations (name)
values ('default')
on conflict (name) do nothing;

-- Office / remote access policy (also ensured at runtime in database.js).
create table if not exists public.remote_access_requests (
  id bigserial primary key,
  admin_id bigint not null references public.admins(id) on delete cascade,
  org_id bigint not null references public.organizations(id) on delete cascade,
  requester_ip text not null,
  reason text not null,
  duration_hours integer not null check (duration_hours between 1 and 72),
  status text not null default 'pending' check (status in ('pending','approved','denied','expired')),
  approved_by bigint null references public.admins(id),
  approved_at timestamptz null,
  expires_at timestamptz null,
  created_at timestamptz not null default now()
);
create index if not exists idx_rar_admin_status on public.remote_access_requests (admin_id, status);
create index if not exists idx_rar_org_pending on public.remote_access_requests (org_id, status);

-- Team lead stream viewing: TURN relay approval (separate from office remote_access).
create table if not exists public.stream_relay_requests (
  id bigserial primary key,
  admin_id bigint not null references public.admins(id) on delete cascade,
  org_id bigint not null references public.organizations(id) on delete cascade,
  requester_ip text not null,
  reason text not null,
  duration_hours integer not null check (duration_hours between 1 and 72),
  status text not null default 'pending' check (status in ('pending','approved','denied','expired')),
  approved_by bigint null references public.admins(id),
  approved_at timestamptz null,
  expires_at timestamptz null,
  created_at timestamptz not null default now()
);
create index if not exists idx_srr_admin_status on public.stream_relay_requests (admin_id, status);
create index if not exists idx_srr_pending on public.stream_relay_requests (org_id, status);

-- ICE path telemetry (client → signaling after WebRTC connects)
create table if not exists public.ice_path_reports (
  id bigserial primary key,
  session_id bigint not null references public.sessions(id) on delete cascade,
  client_id bigint not null references public.clients(id) on delete cascade,
  admin_id bigint null references public.admins(id) on delete set null,
  local_type text null,
  remote_type text null,
  using_turn boolean not null default false,
  time_to_ice_ms integer null,
  reported_at bigint not null
);
create index if not exists idx_ice_path_reports_session on public.ice_path_reports (session_id);
create index if not exists idx_ice_path_reports_reported on public.ice_path_reports (reported_at);

commit;
