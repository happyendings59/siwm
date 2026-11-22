# Security

This is login code: people will trust it with their accounts. If you find a problem, please report it
privately first instead of opening a public issue.

- Use GitHub's **"Report a vulnerability"** button (Security tab → Advisories), or
- contact Kenneth Mayle through https://5pm.io.

Please include what you found, how to reproduce it, and what an attacker could do with it.
You'll get an answer, and credit in the fix notes if you'd like it.

## What this project relies on (good places to look)

- `supabase/functions/_shared/monero.ts`: Monero message-signature verification (SigV1/SigV2, spend key only).
- One-time sign-in messages: bound to the site's host, single-use, 10-minute expiry, bound to one address.
- `supabase/functions/_shared/confirm.ts`: "confirm with your wallet" before sensitive changes.
- Recovery: backup email code **and** a recovery code (only a salted hash stored), optional waiting period.
- Fingerprints: addresses and emails are stored only as HMAC-SHA256 with a key kept in Supabase Vault.

## Known limits

- Wallets don't check which website asked for a signature. The message says "Only sign this on https://<site>",
  and sensitive changes need a second signature that names the change, but a person who signs a sign-in message on
  a look-alike site can still give that site one session. Passkeys (WebAuthn) don't have this weakness; consider
  offering them alongside.
- The code has not had an independent security audit yet.
