// Sign-In with Monero (SIWM) · Copyright 2026 Kenneth Mayle · https://5pm.io · https://kwm59.io
// Licensed under the Apache License, Version 2.0 (see LICENSE and NOTICE).
// Keyed fingerprints for identifiers we must NOT store in plain text (wallet addresses, emails).
// fingerprint(kind, value) = hex(HMAC-SHA256(pepper, `${kind}:${value}`)), the same as SQL public.id_fingerprint().
// The pepper lives in Vault (public.id_pepper(), service role only). People type their address/email whenever it's
// needed, so the server checks it against the fingerprint and keeps nothing.
// deno-lint-ignore no-explicit-any
type Db = any;

let pepperKey: CryptoKey | null = null;

async function key(db: Db) {
  if (pepperKey) return pepperKey;
  const { data, error } = await db.rpc("id_pepper");
  if (error || !data) throw new Error("fingerprint key unavailable");
  pepperKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(String(data)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return pepperKey;
}

export async function fingerprint(db: Db, kind: string, value: string) {
  const sig = await crypto.subtle.sign("HMAC", await key(db), new TextEncoder().encode(`${kind}:${value}`));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** "82sb…6uAn": enough for the holder to recognise their wallet, useless for finding it. */
export const addressLabel = (a: string) => `${a.slice(0, 4)}…${a.slice(-4)}`;

/** "h***y@5pm.io" */
export function emailLabel(email: string) {
  const [local, domain] = email.split("@");
  return `${local.slice(0, 1)}***${local.length > 1 ? local.slice(-1) : ""}@${domain}`;
}

/** A random, meaningless sign-in email for wallet accounts (never mailed, reveals nothing). */
export function randomPlaceholderEmail(domain: string) {
  const r = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `acct-${r}@${domain}`;
}
