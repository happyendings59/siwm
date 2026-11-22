// Sign-In with Monero (SIWM) · Copyright 2026 Kenneth Mayle · https://5pm.io · https://kwm59.io
// Licensed under the Apache License, Version 2.0 (see LICENSE and NOTICE).
// Backup email + recovery code. One email may back up several accounts; each account's recovery code says which.
// No plain emails are stored: only a keyed fingerprint (to find the accounts) and a masked label like h***y@5pm.io.
// The holder types the email whenever a code is sent, so we mail what they typed and keep nothing.
//
// Signed-in holder (Bearer token):
//   { action: "status" }                                   -> { email, delayDays, emailLogin, pending } | { email: null }
//   { action: "setup_start", email }                       -> emails a 6-digit code to prove the address
//   { action: "setup_confirm", email, otp, delayDays }     -> { recoveryCode }  (shown ONCE; we keep only a hash)
//   { action: "new_code" }                                 -> { recoveryCode }  (the old one stops working)
//   { action: "settings", delayDays?, emailLogin? }        -> { ok }
//   { action: "remove" }                                   -> { ok }
//   setup_confirm / new_code / settings / remove also need confirm: { id, address, signature } from xmr-auth
//   confirm_start (what: "recovery"), signed by the current sign-in wallet; otherwise 428 { confirm_needed: true }.
// Anyone:
//   { action: "recover_start", email, recoveryCode }       -> { ok } (always the same answer; mails a code if they match)
//   { action: "recover_verify", email, recoveryCode, otp } -> { session } | { pendingUntil }
//   { action: "login_start", email }                       -> { ok } (only accounts that opted in to email sign-in)
//   { action: "login_verify", email, otp, account? }       -> { session } | { choose: [{ account, label }] }
//
// A recovery session carries app_metadata.recovering = true: the site then only lets the holder switch to a new
// Monero wallet (xmr-auth clears the flag). A Monero sign-in cancels any pending (waiting-period) recovery.
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import nodemailer from "npm:nodemailer@6.9.16";
import { ALLOWED_ORIGINS, SITE } from "../_shared/settings.ts";
import { emailLabel, fingerprint, randomPlaceholderEmail } from "../_shared/ident.ts";
import { useConfirm } from "../_shared/confirm.ts";

const url = Deno.env.get("SUPABASE_URL")!;
const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const anon = () =>
  createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, { auth: { persistSession: false, autoRefreshToken: false } });

const DELAYS = [0, 3, 7, 30];
const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$/;
const GENERIC = { ok: true, message: "If that matches an account, a code is on its way to that email." };

function cors(origin: string | null) {
  return {
    "Access-Control-Allow-Origin": origin && ALLOWED_ORIGINS.has(origin) ? origin : SITE.defaultOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, apikey, authorization, x-client-info",
    "Vary": "Origin",
  };
}
const json = (body: unknown, status: number, origin: string | null) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors(origin), "Content-Type": "application/json", "Cache-Control": "no-store" } });

// ---------- small crypto helpers ----------
const hex = (b: ArrayBuffer | Uint8Array) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
async function sha256(s: string) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}
const salt = () => hex(crypto.getRandomValues(new Uint8Array(16)));
function sixDigits() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000;
  return String(n).padStart(6, "0");
}
// LETTERS ONLY (no I or O), so a code written by hand can't be misread (no S/5, B/8, Z/2, G/6 mix-ups):
// 19 random letters (~87 bits) + 1 check letter, so the page catches any single typo before sending anything.
// Shown as XXXXX-XXXXX-XXXXX-XXXXX. (Same check in kit/auth.js.)
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // 24 letters
const WEIGHTS = [1, 5, 7, 11, 13, 17, 19, 23]; // all coprime to 24: every single-letter typo changes the check letter
function checkChar(body19: string) {
  let sum = 0;
  for (let i = 0; i < 19; i++) sum += WEIGHTS[i % 8] * ALPHABET.indexOf(body19[i]);
  return ALPHABET[sum % 24];
}
function newRecoveryCode() {
  const body = Array.from({ length: 19 }, () => {
    // unbiased pick from 24 letters
    let b: number;
    do { b = crypto.getRandomValues(new Uint8Array(1))[0]; } while (b >= 240);
    return ALPHABET[b % 24];
  }).join("");
  const c = body + checkChar(body);
  return `${c.slice(0, 5)}-${c.slice(5, 10)}-${c.slice(10, 15)}-${c.slice(15)}`;
}
const normCode = (c: unknown) => (typeof c === "string" ? c.toUpperCase().replace(/[^A-Z]/g, "") : "");
const normEmail = (e: unknown) => (typeof e === "string" ? e.trim().toLowerCase() : "");
function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// ---------- mail ----------
let transport: ReturnType<typeof nodemailer.createTransport> | null = null;
async function send(to: string, subject: string, text: string) {
  const pass = Deno.env.get("SMTP_PASS");
  if (!pass) throw new Error("Email isn't set up on the server (SMTP_PASS missing).");
  transport ??= nodemailer.createTransport({
    host: SITE.smtp.host, port: SITE.smtp.port, secure: true, auth: { user: SITE.smtp.user, pass },
  });
  await transport.sendMail({ from: SITE.smtp.from, to, subject, text });
}

async function issueOtp(email: string, purpose: string, userId: string | null) {
  const eh = await fingerprint(admin, "email", email);
  // abuse limit: at most 5 codes per email per hour
  const { count } = await admin.from("recovery_otps").select("id", { count: "exact", head: true })
    .eq("email_hash", eh).gt("created_at", new Date(Date.now() - 3600_000).toISOString());
  if ((count ?? 0) >= 5) return false;
  const code = sixDigits(), s = salt();
  await admin.from("recovery_otps").insert({ email_hash: eh, purpose, user_id: userId, salt: s, code_hash: await sha256(s + code) });
  const what = purpose === "setup" ? "confirm this backup email" : purpose === "recover" ? "recover your account" : "sign in";
  await send(email, `Your ${SITE.name} code: ${code}`,
    `Your code to ${what} on ${SITE.name}: ${code}\n\nIt works once and expires in 15 minutes.\n` +
    `If you didn't ask for it, ignore this email. Nobody can ${purpose === "recover" ? "recover an account without its recovery code" : "use it without your code"}.`);
  return true;
}

// Checks the latest unused code for (email, purpose[, user]) and marks it used. Max 5 tries per code.
async function checkOtp(email: string, purpose: string, otp: unknown, userId: string | null, consume = true) {
  if (typeof otp !== "string" || !/^\d{6}$/.test(otp.trim())) return false;
  const eh = await fingerprint(admin, "email", email);
  let q = admin.from("recovery_otps").select("*").eq("email_hash", eh).eq("purpose", purpose).is("used_at", null)
    .gt("expires_at", new Date().toISOString()).order("created_at", { ascending: false }).limit(1);
  if (userId) q = q.eq("user_id", userId);
  const { data } = await q;
  const row = data?.[0];
  if (!row || row.attempts >= 5) return false;
  const ok = timingSafeEqual(await sha256(row.salt + otp.trim()), row.code_hash);
  if (!ok) {
    await admin.from("recovery_otps").update({ attempts: row.attempts + 1 }).eq("id", row.id);
    return false;
  }
  if (consume) await admin.from("recovery_otps").update({ used_at: new Date().toISOString() }).eq("id", row.id).is("used_at", null);
  return true;
}

// The account (if any) whose backup email AND recovery code both match.
async function accountFor(email: string, recoveryCode: unknown) {
  const code = normCode(recoveryCode);
  if (code.length !== 20) return null;
  const eh = await fingerprint(admin, "email", email);
  const { data } = await admin.from("recovery_contacts").select("user_id, code_salt, code_hash, delay_days").eq("email_hash", eh);
  for (const r of data ?? []) {
    if (timingSafeEqual(await sha256(r.code_salt + code), r.code_hash)) return r;
  }
  return null;
}

// A normal Supabase session for the account. `recovering` restricts it (in the site) to switching wallets.
// HOOK: refuse blocked accounts here by throwing new Refused("message").
class Refused extends Error {}
async function sessionFor(userId: string, recovering: boolean) {
  const { data: u } = await admin.auth.admin.getUserById(userId);
  if (!u.user?.email) throw new Error("account has no login email");
  await admin.auth.admin.updateUserById(userId, { app_metadata: { ...u.user.app_metadata, recovering } });
  const { data: link, error } = await admin.auth.admin.generateLink({ type: "magiclink", email: u.user.email });
  if (error || !link.properties?.hashed_token) throw new Error("could not start a session");
  const { data: s, error: e2 } = await anon().auth.verifyOtp({ token_hash: link.properties.hashed_token, type: "email" });
  if (e2 || !s.session) throw new Error("could not start a session");
  return s.session;
}

async function caller(req: Request) {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const { data, error } = await admin.auth.getUser(token);
  return error ? null : data.user;
}

async function walletLabel(userId: string) {
  const { data: w } = await admin.from("wallets").select("label").eq("user_id", userId).eq("is_login", true).maybeSingle();
  return w ? `XMR ${w.label}` : "Account";
}

// ---------- actions ----------
async function handle(body: Record<string, unknown>, req: Request, origin: string | null) {
  const a = body.action;

  if (a === "recover_start" || a === "recover_verify" || a === "login_start" || a === "login_verify") {
    const email = normEmail(body.email);
    if (!EMAIL_RE.test(email)) return json({ error: "Enter the backup email." }, 400, origin);

    if (a === "recover_start") {
      const acct = await accountFor(email, body.recoveryCode);
      if (acct) await issueOtp(email, "recover", acct.user_id);
      return json(GENERIC, 200, origin);
    }
    if (a === "recover_verify") {
      const acct = await accountFor(email, body.recoveryCode);
      if (!acct || !(await checkOtp(email, "recover", body.otp, acct.user_id))) {
        return json({ error: "That didn't match. Check the email, the recovery code and the emailed code, or send a new one." }, 401, origin);
      }
      if (acct.delay_days > 0) {
        const { data: req0 } = await admin.from("recovery_requests").select("ready_at").eq("user_id", acct.user_id).maybeSingle();
        if (!req0) {
          const ready = new Date(Date.now() + acct.delay_days * 86400_000).toISOString();
          await admin.from("recovery_requests").insert({ user_id: acct.user_id, ready_at: ready });
          return json({ pendingUntil: ready, started: true }, 202, origin);
        }
        if (new Date(req0.ready_at) > new Date()) return json({ pendingUntil: req0.ready_at }, 202, origin);
        await admin.from("recovery_requests").delete().eq("user_id", acct.user_id);
      }
      return json({ session: await sessionFor(acct.user_id, true) }, 200, origin);
    }
    if (a === "login_start") {
      const { data } = await admin.from("recovery_contacts").select("user_id").eq("email_hash", await fingerprint(admin, "email", email)).eq("email_login", true);
      if (data?.length) await issueOtp(email, "login", null);
      return json(GENERIC, 200, origin);
    }
    // login_verify
    const { data } = await admin.from("recovery_contacts").select("user_id").eq("email_hash", await fingerprint(admin, "email", email)).eq("email_login", true);
    const ids = (data ?? []).map((r) => r.user_id as string);
    const chosen = typeof body.account === "string" ? body.account : null;
    if (!ids.length || (chosen && !ids.includes(chosen))) return json({ error: "That didn't work. Send a new code." }, 401, origin);
    if (ids.length > 1 && !chosen) {
      if (!(await checkOtp(email, "login", body.otp, null, false))) return json({ error: "That code didn't work or has expired." }, 401, origin);
      return json({ choose: await Promise.all(ids.map(async (id) => ({ account: id, label: await walletLabel(id) }))) }, 200, origin);
    }
    if (!(await checkOtp(email, "login", body.otp, null))) return json({ error: "That code didn't work or has expired." }, 401, origin);
    return json({ session: await sessionFor(chosen ?? ids[0], false) }, 200, origin);
  }

  // everything below needs a signed-in holder
  const user = await caller(req);
  if (!user) return json({ error: "Sign in again." }, 401, origin);
  if (user.app_metadata?.recovering) return json({ error: "Finish recovery first: switch to a new Monero wallet." }, 403, origin);
  const { data: mine } = await admin.from("recovery_contacts").select("*").eq("user_id", user.id).maybeSingle();

  // Changing the safety net needs a fresh "confirm with your wallet" from the current sign-in wallet
  // (see _shared/confirm.ts): a relayed sign-in alone can't swap the backup email or recovery code.
  if (a === "setup_confirm" || a === "new_code" || a === "settings" || a === "remove") {
    const problem = await useConfirm(admin, user.id, "recovery", body.confirm);
    if (problem === "CONFIRM_NEEDED") return json({ error: "Confirm with your current wallet first.", confirm_needed: true, what: "recovery" }, 428, origin);
    if (problem) return json({ error: problem }, 400, origin);
  }

  if (a === "status") {
    if (!mine) return json({ email: null }, 200, origin);
    const { data: p } = await admin.from("recovery_requests").select("ready_at").eq("user_id", user.id).maybeSingle();
    return json({ email: mine.email_label, delayDays: mine.delay_days, emailLogin: mine.email_login, pending: p?.ready_at ?? null }, 200, origin);
  }
  if (a === "setup_start") {
    const email = normEmail(body.email);
    if (!EMAIL_RE.test(email)) return json({ error: "Enter an email address." }, 400, origin);
    if (!(await issueOtp(email, "setup", user.id))) return json({ error: "Too many codes for that email. Wait an hour." }, 429, origin);
    return json({ ok: true }, 200, origin);
  }
  if (a === "setup_confirm") {
    const email = normEmail(body.email);
    const delay = Number(body.delayDays ?? 0);
    if (!DELAYS.includes(delay)) return json({ error: "Pick a waiting period." }, 400, origin);
    if (!(await checkOtp(email, "setup", body.otp, user.id))) return json({ error: "That code didn't work or has expired." }, 401, origin);
    const efp = await fingerprint(admin, "email", email);
    const code = newRecoveryCode(), s = salt();
    const row = { user_id: user.id, email_hash: efp, email_label: emailLabel(email), code_salt: s, code_hash: await sha256(s + normCode(code)), delay_days: delay, email_login: mine?.email_login ?? false };
    const { error } = await admin.from("recovery_contacts").upsert(row);
    if (error) return json({ error: "Couldn't save it. Try again." }, 500, origin);
    // Only a fingerprint + masked label is kept. The sign-in system keeps a random, never-mailed placeholder.
    if (!/^acct-[0-9a-f]{32}@/.test(user.email ?? "")) {
      await admin.auth.admin.updateUserById(user.id, { email: randomPlaceholderEmail(SITE.loginEmailDomain), email_confirm: true });
    }
    return json({ recoveryCode: code }, 200, origin);
  }
  if (!mine) return json({ error: "Add a backup email first." }, 400, origin);
  if (a === "new_code") {
    const code = newRecoveryCode(), s = salt();
    await admin.from("recovery_contacts").update({ code_salt: s, code_hash: await sha256(s + normCode(code)) }).eq("user_id", user.id);
    return json({ recoveryCode: code }, 200, origin);
  }
  if (a === "settings") {
    const patch: Record<string, unknown> = {};
    if (body.delayDays !== undefined) {
      if (!DELAYS.includes(Number(body.delayDays))) return json({ error: "Pick a waiting period." }, 400, origin);
      patch.delay_days = Number(body.delayDays);
    }
    if (body.emailLogin !== undefined) patch.email_login = !!body.emailLogin;
    await admin.from("recovery_contacts").update(patch).eq("user_id", user.id);
    return json({ ok: true }, 200, origin);
  }
  if (a === "remove") {
    await admin.from("recovery_contacts").delete().eq("user_id", user.id);
    await admin.from("recovery_requests").delete().eq("user_id", user.id);
    return json({ ok: true }, 200, origin);
  }
  return json({ error: "Unknown action" }, 400, origin);
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin");
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });
  if (req.method !== "POST") return json({ error: "POST only" }, 405, origin);
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "Bad request" }, 400, origin); }
  try {
    return await handle(body, req, origin);
  } catch (e) {
    if (e instanceof Refused) return json({ error: e.message }, 403, origin);
    console.error(e);
    const msg = e instanceof Error && /SMTP_PASS/.test(e.message) ? e.message : "Server error";
    return json({ error: msg }, 500, origin);
  }
});
