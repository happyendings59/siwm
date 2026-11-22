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

- **Man-in-the-middle (relay) attack vector.** Wallets don't check which website asked for a signature, so a
  look-alike site can relay a real sign-in message and the person's signature and get one session. The message says
  "Only sign this on https://<site>", and sensitive changes need a second signature that names the change, so a
  relayed session can't take over the account. It can still act as the person until it signs out.
  Recommended fix, not built yet: confirm sign-ins over a separate private channel such as SimpleX (a bot that asks
  the holder to approve, or that delivers a one-time code). Passkeys (WebAuthn) also avoid this, because the
  browser ties them to the real site.
- The code has not had an independent security audit yet.
