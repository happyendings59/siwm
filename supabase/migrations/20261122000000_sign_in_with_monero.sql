-- Sign-In with Monero (SIWM) · Copyright 2026 Kenneth Mayle · https://5pm.io · https://kwm59.io · Apache-2.0
--
-- Tables for wallet sign-in, backup email + recovery code, and "confirm with your wallet".
-- No plain wallet addresses or emails are stored: only a keyed fingerprint (HMAC-SHA256 with a secret kept in
-- Supabase Vault) for lookups, plus a short label ("82sb…6uAn", "h***y@example.com") so holders recognise their own.
-- Only the edge functions (service role) write these tables; a signed-in browser can read its own wallet labels.
-- Needs the Supabase extensions pgcrypto (schema "extensions") and Vault, which new projects have by default.

-- secret fingerprint key (random, generated inside the database; only the service role can read it)
select vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'siwm_id_pepper',
  'HMAC key for wallet-address and email fingerprints (Sign-In with Monero)');

create function public.id_pepper()
returns text language sql security definer set search_path = '' as $$
  select decrypted_secret from vault.decrypted_secrets where name = 'siwm_id_pepper';
$$;
revoke all on function public.id_pepper() from public, anon, authenticated;
grant execute on function public.id_pepper() to service_role;

-- fingerprint(kind, value) = hex(HMAC-SHA256(pepper, kind || ':' || value)); kind = 'xmr' | 'email' | other chains.
-- Same result as id fingerprint() in supabase/functions/_shared/ident.ts (useful for admin tools).
create function public.id_fingerprint(kind text, value text)
returns text language sql stable security definer set search_path = '' as $$
  select encode(extensions.hmac(kind || ':' || value, public.id_pepper(), 'sha256'), 'hex');
$$;
revoke all on function public.id_fingerprint(text, text) from public, anon, authenticated;
grant execute on function public.id_fingerprint(text, text) to service_role;

-- Wallets linked to an account. One of them is the sign-in wallet (is_login).
-- `chain` is open on purpose: other coins can be added with their own signature check ('xmr' today).
create table public.wallets (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  chain text not null check (chain ~ '^[a-z0-9]{2,12}$'),
  address_hash text not null,
  label text not null,
  is_login boolean not null default false,
  created_at timestamptz not null default now(),
  unique (chain, address_hash)
);
create index wallets_user_id_idx on public.wallets (user_id);
create unique index wallets_one_login_per_chain on public.wallets (user_id, chain) where is_login;

-- One-time messages to sign: sign-in ('login'), switch the sign-in wallet ('link'), and
-- "confirm with your wallet" before a sensitive change ('confirm', see _shared/confirm.ts).
create table public.login_challenges (
  id uuid primary key default gen_random_uuid(),
  chain text not null,
  address_hash text not null,
  message text not null,
  purpose text not null default 'login' check (purpose in ('login', 'link', 'confirm')),
  user_id uuid references auth.users (id) on delete cascade,
  confirm_for text,     -- 'switch_wallet' | 'recovery' | 'delete'
  confirm_detail text,  -- for 'switch_wallet': fingerprint of the exact new address
  expires_at timestamptz not null default now() + interval '10 minutes',
  used_at timestamptz,
  created_at timestamptz not null default now(),
  constraint login_challenges_confirm_check check (
    (purpose = 'confirm') = (confirm_for is not null)
    and (confirm_for is null or confirm_for in ('switch_wallet', 'recovery', 'delete')))
);
create index login_challenges_expires_idx on public.login_challenges (expires_at);
create index login_challenges_user_id_idx on public.login_challenges (user_id);
create index login_challenges_address_idx on public.login_challenges (address_hash, expires_at);

-- Backup email (fingerprint + masked label) and the salted hash of the recovery code. One email can back up
-- several accounts; recovery needs BOTH the email (a code we send) AND the account's recovery code.
create table public.recovery_contacts (
  user_id uuid primary key references auth.users (id) on delete cascade,
  email_hash text not null,
  email_label text not null,
  code_salt text not null,
  code_hash text not null,               -- sha256(salt || recovery code)
  delay_days integer not null default 0 check (delay_days in (0, 3, 7, 30)),
  email_login boolean not null default false, -- holder opted in to everyday sign-in by email code
  created_at timestamptz not null default now()
);
create index recovery_contacts_email_hash_idx on public.recovery_contacts (email_hash);

create table public.recovery_otps (
  id uuid primary key default gen_random_uuid(),
  email_hash text not null,
  user_id uuid references auth.users (id) on delete cascade,
  purpose text not null check (purpose in ('setup', 'recover', 'login')),
  salt text not null,
  code_hash text not null,
  attempts integer not null default 0,
  expires_at timestamptz not null default now() + interval '15 minutes',
  used_at timestamptz,
  created_at timestamptz not null default now()
);
create index recovery_otps_email_hash_idx on public.recovery_otps (email_hash, created_at);
create index recovery_otps_user_idx on public.recovery_otps (user_id);

-- A recovery waiting out the holder's chosen waiting period (a wallet sign-in cancels it).
create table public.recovery_requests (
  user_id uuid primary key references auth.users (id) on delete cascade,
  ready_at timestamptz not null,
  created_at timestamptz not null default now()
);

-- Row-level security: browsers can only read their own wallet labels. Everything else is service-role only.
alter table public.wallets enable row level security;
alter table public.login_challenges enable row level security;
alter table public.recovery_contacts enable row level security;
alter table public.recovery_otps enable row level security;
alter table public.recovery_requests enable row level security;

create policy "read own wallets" on public.wallets
  for select to authenticated using ((select auth.uid()) = user_id);
revoke insert, update, delete on public.wallets from anon, authenticated;
revoke all on public.login_challenges, public.recovery_contacts, public.recovery_otps, public.recovery_requests
  from anon, authenticated;
