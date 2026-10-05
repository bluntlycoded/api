-- Supabase exposes every public table over its REST API. This server connects
-- directly as a privileged role, so deny the API roles everything. Row level
-- security with no policies blocks the anon and authenticated keys entirely.
alter table users enable row level security;
alter table user_apps enable row level security;
alter table devices enable row level security;
alter table login_events enable row level security;
alter table approvals enable row level security;
alter table audit_events enable row level security;
alter table passkeys enable row level security;
alter table webauthn_challenges enable row level security;
alter table vaults enable row level security;
alter table blocked_ips enable row level security;

revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
