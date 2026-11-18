
create schema if not exists tracker;

create table if not exists tracker.devices (
  id bigserial primary key,
  name text not null,
  token_hash text not null unique,
  created_at text not null,
  last_seen text,
  lost_mode integer not null default 0
);
create table if not exists tracker.locations (
  id bigserial primary key,
  device_id bigint not null references tracker.devices(id) on delete cascade,
  ts text not null,
  lat double precision, lon double precision, acc double precision,
  battery integer, charging text, network text, note text
);
create index if not exists idx_tracker_loc_dev on tracker.locations(device_id, id desc);
create table if not exists tracker.commands (
  id bigserial primary key,
  device_id bigint not null references tracker.devices(id) on delete cascade,
  type text not null,
  payload text,
  status text not null default 'pending',
  created_at text not null,
  delivered_at text,
  result text
);
create index if not exists idx_tracker_cmd_dev on tracker.commands(device_id, status);
create table if not exists tracker.intruders (
  id bigserial primary key,
  device_id bigint not null references tracker.devices(id) on delete cascade,
  ts text not null,
  mime text not null,
  data bytea not null,
  lat double precision, lon double precision, note text
);
create index if not exists idx_tracker_intr_dev on tracker.intruders(device_id, id desc);
create table if not exists tracker.login_attempts (
  ip text primary key,
  count integer not null,
  first_ts double precision not null
);

revoke all on schema tracker from public, anon, authenticated;
revoke all on all tables in schema tracker from public, anon, authenticated;

do $$ begin
  if not exists (select from pg_roles where rolname = 'tracker_app') then
    create role tracker_app login password 'CHANGE_ME' nosuperuser nocreatedb nocreaterole nobypassrls connection limit 20;
  else
    alter role tracker_app password 'CHANGE_ME';
  end if;
end $$;
alter role tracker_app set search_path = tracker;
grant usage on schema tracker to tracker_app;
grant select, insert, update, delete on all tables in schema tracker to tracker_app;
grant usage, select on all sequences in schema tracker to tracker_app;
