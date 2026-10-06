-- Same lockdown as 0002, for the tables added in 0003.
alter table refresh_tokens enable row level security;
alter table recovery_codes enable row level security;

revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
