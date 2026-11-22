# Sign-In with Monero (SIWM)

**Wallet login for websites. No email, no password, no tracking.**

<sub>Created by **Kenneth Mayle** · [5pm.io](https://5pm.io) · [kwm59.io](https://kwm59.io) · 2026 · Apache-2.0</sub>

---

People sign in by signing a short message in their Monero wallet (for example Cake Wallet). The site checks the
signature and starts a normal session. It never sees a password, never needs an email, and never stores the
person's wallet address in plain text.

Say it "swim". It's the Monero counterpart of Sign-In with Ethereum (SIWE).

## What you get

- **Monero sign-in.** The person types their address and gets a one-line message that names your site
  ("Only sign this on https://yoursite.com"). They sign it in their wallet and paste the signature back. Each code
  works once and expires in 10 minutes. Spend-key signatures only (view keys are often shared, so they're refused).
- **No plain identifiers stored.** Addresses and emails are kept only as keyed fingerprints (HMAC-SHA256, with the
  key in Supabase Vault), plus a short label like `82sb…6uAn` so people recognise their own account.
- **Optional backup email + recovery code.** If someone loses their wallet, they get back in with a code sent to
  their backup email **and** a 20-letter recovery code they saved. The site keeps only a salted hash of that code.
  Someone who only gets into the inbox can't take the account. The holder can pick a waiting period
  (none, 3, 7 or 30 days), and signing in with the wallet during that time cancels the recovery.
- **"Confirm with your wallet."** Switching the sign-in wallet, changing recovery settings, or deleting the account
  needs a second, fresh signature whose message names the exact change. A look-alike site that tricks someone into
  signing a normal sign-in message gets one session, but can't lock them out.
- **Recovery that works.** After an email recovery, the account can only do one thing: switch to a new wallet.
  Then it's back to normal.
- **Optional email sign-in**, off by default, for people who want it.
- **Delete my account**, confirmed with the wallet.

## How it fits together

```
browser (client/)                     Supabase (supabase/)
  auth.js  ── challenge ─────────▶    functions/xmr-auth   sign-in, switch wallet, confirm, delete
           ◀── one-line message ──
  wallet signs it (Cake: Settings → Other → Sign / Verify)
           ── signature ─────────▶    verifies it (_shared/monero.ts) → Supabase session
  account  ── backup email etc. ─▶    functions/recovery   backup email, recovery code, email sign-in
                                      migrations/          tables + row-level security
```

## Set it up

You need a [Supabase](https://supabase.com) project (the free plan is fine) and an email account that can send
mail over SMTP (port 465), only if you want backup emails.

1. **Database.** Run `supabase/migrations/20261122000000_sign_in_with_monero.sql` (Supabase CLI
   `supabase db push`, or paste it into the SQL editor).
2. **Server settings.** Copy `supabase/functions/_shared/settings.example.ts` to `settings.ts` and fill in your
   site name, exact origins (like `https://example.com`), a domain for placeholder sign-in emails, and your SMTP
   details.
3. **Deploy the functions** with JWT verification off (they check the caller themselves):
   ```sh
   supabase functions deploy xmr-auth --no-verify-jwt
   supabase functions deploy recovery --no-verify-jwt
   ```
   For backup emails, add the secret `SMTP_PASS` (Supabase dashboard → Edge Functions → Secrets).
4. **Browser settings.** Copy `client/settings.example.js` to `client/settings.js` and fill in your Supabase URL
   and **publishable** key (never the service-role key).
5. **Bundle:** `npm install && npm run bundle` gives `dist/siwm.js` and `dist/siwm.css`. Host them yourself. No
   CDN, no third-party scripts.
6. **Pages.** Start from `examples/login.html` and `examples/account.html`. The script picks its job from
   `<body data-page="login">` / `"account"`. On any other page, a link with `data-auth-chip` turns into
   "Sign in" or the signed-in account, with "Sign out" next to it.

The styles use your site's colour variables (`--bg`, `--fg`, `--accent`, …) when you define them, and have light
and dark defaults otherwise.

**Your own rules** (blocked accounts, admins, extra cleanup when an account is deleted) go in the spots marked
`HOOK` in `xmr-auth/index.ts` and `recovery/index.ts`.

## Tests

```sh
npm install
npm test
```

The tests make fresh Monero wallets and signatures with a small reference signer (same math as Monero's own) and
check that real signatures pass and that changed messages, other wallets, tampered signatures and view-key
signatures fail.

## Other coins

Nothing here is tied to Monero except the signature check. The `wallets` table has an open `chain` column, and
the flow (challenge → sign → verify → session, fingerprints instead of plain addresses, confirm before sensitive
changes, email + recovery code) works the same for any wallet that can sign a message. Ethereum, Solana,
Cardano and others can be added with one verify function each. Adaptations are welcome. Please keep the
`NOTICE` file (the license requires it) and say where yours came from.

## Credit

Sign-In with Monero was created by **Kenneth Mayle** ([5pm.io](https://5pm.io) · [kwm59.io](https://kwm59.io)).

The sign-in and account pages show a small, quiet line at the bottom: *"Sign-In with Monero · open source by
5pm.io"*. The license doesn't require you to keep it, and you can turn it off with `credit: false` in
`settings.js`. But if this saved you time, keeping it, or linking back somewhere on your site, is appreciated.

## Known issue: man-in-the-middle (relay) attack

**There is a man-in-the-middle attack vector.** Wallets don't check which website asked for a signature. A
look-alike site can pass a real sign-in message from your site to the user, collect their signature, and send
it on to your site, which gets the attacker a session.

What this repo does about it now:
- The message names your site and says "Only sign this on https://yoursite.com".
- Each code works once, expires in 10 minutes, and only works for one address.
- Switching the sign-in wallet, changing recovery settings, or deleting the account needs a second signature whose
  message names the exact change. A relayed sign-in alone can't lock the holder out.

**Recommended fix (not built yet):** confirm sign-ins over a separate private channel such as
[SimpleX](https://simplex.chat). For example, a SimpleX bot sends the holder "Approve sign-in to yoursite.com?",
or delivers a one-time code, so a relayed signature alone isn't enough. I recommend something like this but
haven't had the time to make it work. Contributions are welcome.

Passkeys (WebAuthn) are another option. The browser ties them to the real site, so they can't be relayed.
See [SECURITY.md](SECURITY.md).

## Other notes

- This code hasn't had an independent security audit.
- If your site takes payments or handles regulated data, have a lawyer review it. This isn't legal advice.

## License

Copyright 2026 Kenneth Mayle · [5pm.io](https://5pm.io) · [kwm59.io](https://kwm59.io)

Licensed under the [Apache License, Version 2.0](LICENSE). You can use it in open or closed projects. Copies and
adaptations must keep the copyright and [NOTICE](NOTICE).
