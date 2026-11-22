// Sign-In with Monero (SIWM) · Copyright 2026 Kenneth Mayle · https://5pm.io · https://kwm59.io
// Licensed under the Apache License, Version 2.0 (see LICENSE and NOTICE).
// "Confirm with your wallet": a fresh Monero signature from the account's CURRENT sign-in wallet, required before
// anything that could lock the holder out (switch sign-in wallet, backup email / recovery code / settings, delete).
//
// Why: wallets don't check which site asks for a signature, so a look-alike site can relay a real sign-in code and
// get a session. A sign-in alone shouldn't be enough to take the account over. The confirm message names the exact
// action ("switch your sign-in wallet to 8AbC…xYz9"), so a holder who only meant to log in sees a red flag.
//
// Recovery sessions (app_metadata.recovering) skip this for the wallet switch only: the old wallet is lost,
// which is the whole point of recovery. Everything else waits until recovery is finished.
//
// Flow: client sends { action: "confirm_start", address, what, detail? } to xmr-auth (signed in) and gets
// { id, message }; the holder signs it in their wallet; the client passes
// confirm: { id, address, signature } along with the sensitive request. Each confirm works once, for 10 minutes,
// for that one account and that one kind of action.
// deno-lint-ignore-file no-explicit-any
import { verifyMoneroMessage } from "./monero.ts";
import { fingerprint } from "./ident.ts";

export const CONFIRM_TEXT: Record<string, (detail: string) => string> = {
  switch_wallet: (d) => `switch your sign-in wallet${d ? ` to ${d}` : ""}`,
  recovery: () => "change your backup email, recovery code or recovery settings",
  delete: () => "DELETE your account",
};

export function confirmMessage(host: string, what: string, detail: string, code: string) {
  return `Confirm on ${host}: ${CONFIRM_TEXT[what](detail)}. ` +
    `Only sign this on https://${host} and only if you asked for this. It does not move any funds. ` +
    `Valid for 10 minutes. Code: ${code}`;
}

/** The account's current Monero sign-in wallet fingerprint, or null if it has none. */
export async function loginWalletHash(admin: any, userId: string): Promise<string | null> {
  const { data } = await admin.from("wallets").select("address_hash")
    .eq("user_id", userId).eq("chain", "xmr").eq("is_login", true).maybeSingle();
  return data?.address_hash ?? null;
}

/**
 * Checks and uses up a confirm. Returns null when it's valid, or an error message for the holder.
 * An account without a sign-in wallet has nothing to confirm with, so it passes.
 */
export async function useConfirm(admin: any, userId: string, what: string, confirm: unknown, detail?: string): Promise<string | null> {
  const current = await loginWalletHash(admin, userId);
  if (!current) return null;
  const c = (confirm ?? {}) as Record<string, unknown>;
  if (typeof c.id !== "string" || typeof c.address !== "string" || typeof c.signature !== "string" || c.signature.length > 200) {
    return "CONFIRM_NEEDED";
  }
  const { data: ch } = await admin.from("login_challenges").select("*").eq("id", c.id).maybeSingle();
  if (!ch || ch.purpose !== "confirm" || ch.user_id !== userId || ch.confirm_for !== what) {
    return "That confirmation doesn't match this request. Start again.";
  }
  if (detail !== undefined && ch.confirm_detail !== detail) return "That confirmation was for a different wallet. Start again.";
  if (ch.used_at) return "That confirmation was already used. Start again.";
  if (new Date(ch.expires_at) < new Date()) return "That confirmation expired. Start again.";
  const addr = c.address.trim();
  const fp = await fingerprint(admin, "xmr", addr);
  if (fp !== ch.address_hash || fp !== current) return "Confirm with the wallet you sign in with now.";
  if (!verifyMoneroMessage(ch.message, addr, c.signature.trim())) {
    return "Signature didn't match. Sign the exact confirmation message with your sign-in wallet's spend key.";
  }
  const { data: used } = await admin.from("login_challenges").update({ used_at: new Date().toISOString() })
    .eq("id", c.id).is("used_at", null).select("id");
  if (!used?.length) return "That confirmation was already used. Start again.";
  return null;
}
