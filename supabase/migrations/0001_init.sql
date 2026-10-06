create table users (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  email text not null,
  password_hash text not null,
  locked boolean not null default false,
  totp_enabled boolean not null default false,
  totp_secret text,
  totp_last_step bigint not null default 0,
  reset_token_hash text,
  reset_token_expires timestamptz,
  created_at timestamptz not null default now()
);
create unique index users_email_key on users (email);
create index users_reset_token_idx on users (reset_token_hash);

create table user_apps (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  app_name text not null,
  issuer text,
  account text,
  secret_key text not null,
  type text not null default 'totp',
  algorithm text not null default 'SHA1',
  digits integer not null default 6,
  period integer not null default 30,
  counter bigint not null default 0,
  folder text,
  icon text,
  favorite boolean not null default false,
  sort_order integer not null default 0,
  created_at timestamptz not null default now()
);
create index user_apps_user_idx on user_apps (user_id);

create table devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  device_hash text not null,
  name text not null default 'Unknown device',
  trusted boolean not null default false,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  last_ip text
);
create unique index devices_user_device_key on devices (user_id, device_hash);

create table login_events (
  id bigserial primary key,
  user_id uuid not null references users (id) on delete cascade,
  outcome text not null,
  device_hash text,
  ip text,
  geo jsonb,
  local_hour integer,
  risk_score integer,
  signals jsonb,
  at timestamptz not null default now()
);
create index login_events_user_outcome_idx on login_events (user_id, outcome, at desc);

create table approvals (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  status text not null default 'pending',
  number integer not null,
  options jsonb not null,
  wrong_attempts integer not null default 0,
  poll_secret_hash text not null,
  request_device_hash text not null,
  request_device_name text,
  trust_device boolean not null default false,
  site text,
  site_source text not null default 'none',
  ip text,
  geo jsonb,
  user_agent text,
  risk_score integer,
  signals jsonb,
  approved_by_device_hash text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index approvals_user_idx on approvals (user_id, status);

create table audit_events (
  id bigserial primary key,
  user_id uuid not null references users (id) on delete cascade,
  type text not null,
  ip text,
  details jsonb,
  at timestamptz not null default now()
);
create index audit_events_user_idx on audit_events (user_id, at desc);

create table passkeys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  credential_id text not null,
  public_key text not null,
  counter bigint not null default 0,
  transports jsonb,
  name text not null default 'Passkey',
  created_at timestamptz not null default now(),
  last_used timestamptz
);
create unique index passkeys_credential_key on passkeys (credential_id);
create index passkeys_user_idx on passkeys (user_id);

create table webauthn_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references users (id) on delete cascade,
  purpose text not null,
  challenge text not null,
  device_hash text,
  expires_at timestamptz not null
);

create table vaults (
  user_id uuid primary key references users (id) on delete cascade,
  ciphertext text not null,
  version integer not null default 1,
  updated_at timestamptz not null default now()
);

create table blocked_ips (
  ip text primary key,
  reason text,
  blocked_until timestamptz not null,
  created_at timestamptz not null default now()
);
