// Sign-In with Monero (SIWM) · Copyright 2026 Kenneth Mayle · https://5pm.io · https://kwm59.io
// Licensed under the Apache License, Version 2.0 (see LICENSE and NOTICE).
// Monero sign-in. The site never stores a plain Monero address: only a keyed fingerprint + a short label
// (see _shared/ident.ts). The person types their address each time; we check the signature against what they typed.
//
//   POST { action: "challenge", address }                       -> { id, message, expires_at }
//   POST { action: "verify", id, address, signature }           -> { session, new_account }
//   POST { action: "challenge", address, replace: true } + Bearer -> { id, message, expires_at, same }
//   POST { action: "verify", id, address, signature, confirm } on a replace code -> { ok }  account now signs in with it
//        (confirm = a signed "confirm with your wallet" from the CURRENT wallet; not needed while recovering)
//   POST { action: "confirm_start", address, what, detail? } + Bearer -> { id, message }  see _shared/confirm.ts
//   POST { action: "delete_account", address, confirm } + Bearer -> { ok }
//        (recovery: lost wallet -> backup email + recovery code -> switch to a new wallet; `same` = it's the wallet
//        the account already uses, e.g. restored from its seed phrase)
//
// The browser shows `message`; the person signs it in their Monero wallet (Cake: Settings -> Other -> Sign / Verify)
// and pastes the "SigV2..." signature back. Spend-key signatures only. Codes are single-use and expire in 10 minutes.
// A wallet sign-in cancels any pending email recovery and lifts recovery mode.
// Add your own rules (blocked accounts, admins, ...) in the hooks marked HOOK below.
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import { decodeAddress, isViewKeySignature, verifyMoneroMessage } from "../_shared/monero.ts";
import { ALLOWED_ORIGINS, SITE } from "../_shared/settings.ts";
import { addressLabel, fingerprint, randomPlaceholderEmail } from "../_shared/ident.ts";
import { CONFIRM_TEXT, confirmMessage, loginWalletHash, useConfirm } from "../_shared/confirm.ts";

const url = Deno.env.get("SUPABASE_URL")!;
const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const anon = () =>
  createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, { auth: { persistSession: false, autoRefreshToken: false } });

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

function code(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const chars = [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}`;
}

async function caller(req: Request) {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const { data, error } = await admin.auth.getUser(token);
  return error ? null : data.user;
}

function cleanAddress(address: unknown) {
  if (typeof address !== "string" || address.length > 120) return null;
  const a = address.trim();
  try { decodeAddress(a); } catch { return null; }
  return a;
}
const BAD_ADDRESS = "That doesn't look like a Monero address (standard or subaddress, starting with 4 or 8).";

async function challenge(address: unknown, origin: string | null, replaceFor: string | null = null) {
  const addr = cleanAddress(address);
  if (!addr) return json({ error: BAD_ADDRESS }, 400, origin);
  const fp = await fingerprint(admin, "xmr", addr);

  // housekeeping + simple abuse limit: at most 5 open challenges per address
  await admin.from("login_challenges").delete().lt("expires_at", new Date(Date.now() - 3600_000).toISOString());
  const { count } = await admin.from("login_challenges").select("id", { count: "exact", head: true })
    .eq("address_hash", fp).is("used_at", null).gt("expires_at", new Date().toISOString());
  if ((count ?? 0) >= 5) return json({ error: "Too many open sign-in codes. Wait a few minutes." }, 429, origin);

  let same = false;
  if (replaceFor) {
    const { data: taken } = await admin.from("wallets").select("user_id").eq("chain", "xmr").eq("address_hash", fp).maybeSingle();
    if (taken && taken.user_id !== replaceFor) return json({ error: "That address already signs in to another account." }, 409, origin);
    same = !!taken;
  }
  const host = origin && ALLOWED_ORIGINS.has(origin) ? new URL(origin).host : new URL(SITE.defaultOrigin).host;
  // One line on purpose: line breaks can change when pasted into a wallet, and the signature must match exactly.
  // Wallets don't check which site asked, so the message itself warns against signing it anywhere else.
  const safety = `Only sign this on https://${host}. It does not move any funds. Valid for 10 minutes.`;
  const message = replaceFor
    ? `Use this Monero address to sign in to ${host}. ${safety} Code: ${code()}`
    : `Sign in to ${host} with Monero. ${safety} Code: ${code()}`;
  const { data, error } = await admin.from("login_challenges")
    .insert({ chain: "xmr", address_hash: fp, message, purpose: replaceFor ? "link" : "login", user_id: replaceFor })
    .select("id, message, expires_at").single();
  if (error) return json({ error: "Could not create a sign-in code." }, 500, origin);
  return json({ ...data, same }, 200, origin);
}

// HOOK: return an error message to refuse an account or a wallet (e.g. blocked by an admin), or null to allow.
// deno-lint-ignore require-await
async function refuseAccount(_userId: string): Promise<string | null> { return null; }
// deno-lint-ignore require-await
async function refuseWallet(_addressFingerprint: string): Promise<string | null> { return null; }

async function liftRecovery(userId: string) {
  await admin.from("recovery_requests").delete().eq("user_id", userId);
  const { data: u } = await admin.auth.admin.getUserById(userId);
  if (u.user?.app_metadata?.recovering) {
    await admin.auth.admin.updateUserById(userId, { app_metadata: { ...u.user.app_metadata, recovering: false } });
  }
  return u.user;
}

// Start a "confirm with your wallet" for a sensitive change (see _shared/confirm.ts). The holder types their
// current sign-in address (we only keep a fingerprint); for a wallet switch, the new address is named in the message.
async function confirmStart(userId: string, recoveringNow: boolean, address: unknown, what: unknown, detail: unknown, origin: string | null) {
  if (recoveringNow) return json({ error: "Finish recovery first: switch to a new Monero wallet." }, 403, origin);
  if (typeof what !== "string" || !CONFIRM_TEXT[what]) return json({ error: "Unknown change." }, 400, origin);
  const addr = cleanAddress(address);
  if (!addr) return json({ error: "Type your current sign-in Monero address." }, 400, origin);
  const fp = await fingerprint(admin, "xmr", addr);
  if (fp !== (await loginWalletHash(admin, userId))) return json({ error: "That isn't this account's sign-in address." }, 400, origin);
  const { count } = await admin.from("login_challenges").select("id", { count: "exact", head: true })
    .eq("address_hash", fp).is("used_at", null).gt("expires_at", new Date().toISOString());
  if ((count ?? 0) >= 5) return json({ error: "Too many open codes. Wait a few minutes." }, 429, origin);
  let label = "", nextFp: string | null = null;
  if (what === "switch_wallet") {
    const next = cleanAddress(detail);
    if (!next) return json({ error: BAD_ADDRESS }, 400, origin);
    label = addressLabel(next);
    nextFp = await fingerprint(admin, "xmr", next); // binds the confirm to this exact new address, not just its label
  }
  const host = origin && ALLOWED_ORIGINS.has(origin) ? new URL(origin).host : new URL(SITE.defaultOrigin).host;
  const { data, error } = await admin.from("login_challenges")
    .insert({ chain: "xmr", address_hash: fp, purpose: "confirm", confirm_for: what, confirm_detail: nextFp, user_id: userId,
      message: confirmMessage(host, what, label, code()) })
    .select("id, message, expires_at").single();
  if (error) return json({ error: "Could not create a confirmation code." }, 500, origin);
  return json(data, 200, origin);
}

// A confirm problem: CONFIRM_NEEDED tells the page to ask for one (HTTP 428), anything else is a plain error.
const confirmError = (msg: string, what: string, origin: string | null) =>
  msg === "CONFIRM_NEEDED"
    ? json({ error: "Confirm with your current wallet first.", confirm_needed: true, what }, 428, origin)
    : json({ error: msg }, 400, origin);

async function verify(id: unknown, address: unknown, signature: unknown, confirm: unknown, origin: string | null) {
  if (typeof id !== "string" || typeof signature !== "string" || signature.length > 200) {
    return json({ error: "Missing code or signature." }, 400, origin);
  }
  const addr = cleanAddress(address);
  if (!addr) return json({ error: "Missing the Monero address. Start again." }, 400, origin);
  const { data: ch } = await admin.from("login_challenges").select("*").eq("id", id).maybeSingle();
  if (!ch || ch.chain !== "xmr" || ch.purpose === "petition" || ch.purpose === "confirm") return json({ error: "Sign-in code not found. Start again." }, 400, origin);
  if (ch.used_at) return json({ error: "That sign-in code was already used. Start again." }, 400, origin);
  if (new Date(ch.expires_at) < new Date()) return json({ error: "That sign-in code expired. Start again." }, 400, origin);
  const fp = await fingerprint(admin, "xmr", addr);
  if (fp !== ch.address_hash) return json({ error: "That isn't the address this code was made for. Start again." }, 400, origin);

  const sig = signature.trim();
  if (!verifyMoneroMessage(ch.message, addr, sig)) {
    const hint = isViewKeySignature(ch.message, addr, sig)
      ? "That was signed with the view key. Sign with the spend key instead."
      : "Signature didn't match. Make sure you signed the exact message with the wallet for this address.";
    return json({ error: hint }, 401, origin);
  }

  // switching the sign-in wallet needs a confirm from the CURRENT wallet, except while recovering (old wallet lost)
  if (ch.purpose === "link") {
    const { data: u } = await admin.auth.admin.getUserById(ch.user_id);
    if (!u.user?.app_metadata?.recovering) {
      const problem = await useConfirm(admin, ch.user_id, "switch_wallet", confirm, fp);
      if (problem) return confirmError(problem, "switch_wallet", origin);
    }
  }

  // mark used (atomically: only one request can win)
  const { data: used } = await admin.from("login_challenges").update({ used_at: new Date().toISOString() })
    .eq("id", id).is("used_at", null).select("id");
  if (!used?.length) return json({ error: "That sign-in code was already used. Start again." }, 400, origin);

  if (ch.purpose === "link") return await replaceLogin(ch.user_id, fp, addr, origin);

  // find or create the account for this address
  let userId: string;
  const { data: wallet } = await admin.from("wallets").select("user_id").eq("chain", "xmr").eq("address_hash", fp).maybeSingle();
  if (wallet) {
    userId = wallet.user_id;
    const no = await refuseAccount(userId);
    if (no) return json({ error: no }, 403, origin);
  } else {
    const no = await refuseWallet(fp);
    if (no) return json({ error: no }, 403, origin);
    const { data: created, error } = await admin.auth.admin.createUser({
      email: randomPlaceholderEmail(SITE.loginEmailDomain), // meaningless; never mailed
      email_confirm: true,
      app_metadata: { login: "xmr" },
    });
    if (error || !created.user) return json({ error: "Could not create the account." }, 500, origin);
    userId = created.user.id;
    const { error: wErr } = await admin.from("wallets")
      .insert({ user_id: userId, chain: "xmr", address_hash: fp, label: addressLabel(addr), is_login: true });
    if (wErr) return json({ error: "Could not save the wallet." }, 500, origin);
  }

  const user = await liftRecovery(userId);
  if (!user?.email) return json({ error: "Account problem. Contact the site admin." }, 500, origin);

  // mint a normal Supabase session for that user
  const { data: link, error: linkErr } = await admin.auth.admin.generateLink({ type: "magiclink", email: user.email });
  if (linkErr || !link.properties?.hashed_token) return json({ error: "Could not start a session." }, 500, origin);
  const { data: s, error: sErr } = await anon().auth.verifyOtp({ token_hash: link.properties.hashed_token, type: "email" });
  if (sErr || !s.session) return json({ error: "Could not start a session." }, 500, origin);

  return json({ session: s.session, new_account: !wallet }, 200, origin);
}

// The account's Monero sign-in moves to this address; the old one no longer signs in.
async function replaceLogin(userId: string, fp: string, addr: string, origin: string | null) {
  const no = (await refuseAccount(userId)) ?? (await refuseWallet(fp));
  if (no) return json({ error: no }, 403, origin);
  const { data: taken } = await admin.from("wallets").select("user_id").eq("chain", "xmr").eq("address_hash", fp).maybeSingle();
  if (taken && taken.user_id !== userId) return json({ error: "That address already signs in to another account." }, 409, origin);
  const { error: dErr } = await admin.from("wallets").delete().eq("user_id", userId).eq("chain", "xmr");
  if (dErr) return json({ error: "Could not update the wallet." }, 500, origin);
  const { error: iErr } = await admin.from("wallets")
    .insert({ user_id: userId, chain: "xmr", address_hash: fp, label: addressLabel(addr), is_login: true });
  if (iErr) return json({ error: "Could not save the new wallet." }, 500, origin);
  await liftRecovery(userId); // recovery finished
  return json({ ok: true }, 200, origin);
}

// Delete my account: the holder retypes their sign-in Monero address and confirms with that wallet. Removes the
// account, its wallets, backup email and recovery code. Refused while recovering (a recovery session isn't proof of
// the wallet).
async function deleteAccount(userId: string, recoveringNow: boolean, address: unknown, confirm: unknown, origin: string | null) {
  if (recoveringNow) return json({ error: "Finish recovery first (switch to a new wallet), then you can delete the account." }, 403, origin);
  const addr = cleanAddress(address);
  if (!addr) return json({ error: "Type your sign-in Monero address to confirm." }, 400, origin);
  const fp = await fingerprint(admin, "xmr", addr);
  const { data: w } = await admin.from("wallets").select("user_id").eq("chain", "xmr").eq("address_hash", fp).eq("is_login", true).maybeSingle();
  if (!w || w.user_id !== userId) return json({ error: "That isn't this account's sign-in address." }, 400, origin);
  const no = await refuseAccount(userId); // HOOK: also a good place to refuse deleting admins or held accounts
  if (no) return json({ error: no }, 403, origin);
  const problem = await useConfirm(admin, userId, "delete", confirm);
  if (problem) return confirmError(problem, "delete", origin);
  // HOOK: delete your app's own rows for this account here (or let them cascade from auth.users).
  const { error } = await admin.auth.admin.deleteUser(userId); // wallets, recovery_* cascade
  if (error) { console.error(error); return json({ error: "Couldn't delete the account. Try again." }, 500, origin); }
  return json({ ok: true }, 200, origin);
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin");
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });
  if (req.method !== "POST") return json({ error: "POST only" }, 405, origin);
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "Bad request" }, 400, origin); }
  try {
    if (body.action === "challenge") {
      if (!body.replace) return await challenge(body.address, origin);
      const user = await caller(req);
      if (!user) return json({ error: "Sign in again." }, 401, origin);
      return await challenge(body.address, origin, user.id);
    }
    if (body.action === "verify") return await verify(body.id, body.address, body.signature, body.confirm, origin);
    if (body.action === "confirm_start") {
      const user = await caller(req);
      if (!user) return json({ error: "Sign in again." }, 401, origin);
      return await confirmStart(user.id, !!user.app_metadata?.recovering, body.address, body.what, body.detail, origin);
    }
    if (body.action === "delete_account") {
      const user = await caller(req);
      if (!user) return json({ error: "Sign in again." }, 401, origin);
      return await deleteAccount(user.id, !!user.app_metadata?.recovering, body.address, body.confirm, origin);
    }
    return json({ error: "Unknown action" }, 400, origin);
  } catch (e) {
    console.error(e);
    return json({ error: "Server error" }, 500, origin);
  }
});
