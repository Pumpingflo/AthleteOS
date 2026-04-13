-- Strivon Strava integration tables
-- Run in Supabase SQL Editor (or migration runner) on your project DB.

begin;

create table if not exists public.strava_tokens (
  user_id uuid primary key references auth.users(id) on delete cascade,
  access_token text not null,
  refresh_token text not null,
  expires_at double precision not null,
  updated_at timestamptz not null default now()
);

create index if not exists idx_strava_tokens_updated_at
  on public.strava_tokens(updated_at desc);

create table if not exists public.strava_webhook_events (
  id bigserial primary key,
  owner_id bigint,
  object_id bigint,
  aspect_type text,
  object_type text,
  event_time bigint,
  updates jsonb not null default '{}'::jsonb,
  raw jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_strava_webhook_events_owner_time
  on public.strava_webhook_events(owner_id, event_time desc);

create index if not exists idx_strava_webhook_events_created_at
  on public.strava_webhook_events(created_at desc);

alter table public.strava_tokens enable row level security;
alter table public.strava_webhook_events enable row level security;

-- Deny direct reads/writes for normal authenticated users.
drop policy if exists "strava_tokens_service_role_all" on public.strava_tokens;
create policy "strava_tokens_service_role_all"
on public.strava_tokens
for all
to service_role
using (true)
with check (true);

drop policy if exists "strava_webhook_events_service_role_all" on public.strava_webhook_events;
create policy "strava_webhook_events_service_role_all"
on public.strava_webhook_events
for all
to service_role
using (true)
with check (true);

commit;
