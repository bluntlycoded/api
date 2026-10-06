create table refresh_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  family_id uuid not null,
  device_hash text not null,
  token_hash text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  family_expires_at timestamptz not null,
  used_at timestamptz,
  revoked_at timestamptz
);
create unique index refresh_tokens_hash_key on refresh_tokens (token_hash);
create index refresh_tokens_user_idx on refresh_tokens (user_id);
create index refresh_tokens_family_idx on refresh_tokens (family_id);

create table recovery_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  code_hash text not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);
create unique index recovery_codes_user_hash_key on recovery_codes (user_id, code_hash);
