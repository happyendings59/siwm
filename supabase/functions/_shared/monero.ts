// Sign-In with Monero (SIWM) · Copyright 2026 Kenneth Mayle · https://5pm.io · https://kwm59.io
// Licensed under the Apache License, Version 2.0 (see LICENSE and NOTICE).
// Monero message-signature verification (wallet "Sign / Verify", SigV1 + SigV2).
// Pure JS: @noble/curves (ed25519 point math) + @noble/hashes (original Keccak-256).
// Mirrors monero wallet2::verify + crypto::check_signature.
import { ed25519 } from "npm:@noble/curves@2.4.0/ed25519.js";
import { keccak_256 } from "npm:@noble/hashes@2.4.0/sha3.js";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const FULL_BLOCK = 8;
const FULL_ENCODED_BLOCK = 11;
const L = 2n ** 252n + 27742317777372353535851937790883648493n; // ed25519 group order

// Address network prefixes Monero uses (mainnet / stagenet / testnet)
const STANDARD_PREFIXES = new Set([18n, 24n, 53n]);
const SUBADDRESS_PREFIXES = new Set([42n, 36n, 63n]);

function decodeBlock(block: string, size: number): Uint8Array {
  let num = 0n;
  for (const ch of block) {
    const d = ALPHABET.indexOf(ch);
    if (d < 0) throw new Error("bad base58 character");
    num = num * 58n + BigInt(d);
  }
  if (num >= 1n << BigInt(8 * size)) throw new Error("base58 block overflow");
  const out = new Uint8Array(size);
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(num & 0xffn);
    num >>= 8n;
  }
  return out;
}

export function moneroBase58Decode(s: string): Uint8Array {
  const fullBlocks = Math.floor(s.length / FULL_ENCODED_BLOCK);
  const lastLen = s.length % FULL_ENCODED_BLOCK;
  const lastSize = ENCODED_BLOCK_SIZES.indexOf(lastLen);
  if (lastSize < 0) throw new Error("bad base58 length");
  const out = new Uint8Array(fullBlocks * FULL_BLOCK + lastSize);
  for (let i = 0; i < fullBlocks; i++) {
    out.set(decodeBlock(s.slice(i * 11, i * 11 + 11), FULL_BLOCK), i * FULL_BLOCK);
  }
  if (lastSize > 0) out.set(decodeBlock(s.slice(fullBlocks * 11), lastSize), fullBlocks * FULL_BLOCK);
  return out;
}

function readVarint(b: Uint8Array): { value: bigint; len: number } {
  let value = 0n, shift = 0n, i = 0;
  for (; i < b.length; i++) {
    value |= BigInt(b[i] & 0x7f) << shift;
    if ((b[i] & 0x80) === 0) return { value, len: i + 1 };
    shift += 7n;
  }
  throw new Error("bad varint");
}

function writeVarint(n: number): Uint8Array {
  const out: number[] = [];
  while (n >= 0x80) { out.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
  out.push(n);
  return new Uint8Array(out);
}

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const leToBig = (b: Uint8Array) => b.reduceRight((acc, v) => (acc << 8n) | BigInt(v), 0n);

export type MoneroAddress = { spend: Uint8Array; view: Uint8Array; kind: "standard" | "subaddress" };

/** Decode a Monero standard address or subaddress (integrated addresses are rejected). */
export function decodeAddress(address: string): MoneroAddress {
  const raw = moneroBase58Decode(address.trim());
  const { value: prefix, len } = readVarint(raw);
  if (raw.length !== len + 64 + 4) throw new Error("not a standard address or subaddress");
  const body = raw.slice(0, len + 64);
  const checksum = raw.slice(len + 64);
  if (!eq(keccak_256(body).slice(0, 4), checksum)) throw new Error("address checksum mismatch");
  const kind = STANDARD_PREFIXES.has(prefix) ? "standard" : SUBADDRESS_PREFIXES.has(prefix) ? "subaddress" : null;
  if (!kind) throw new Error("unsupported address type");
  return { spend: body.slice(len, len + 32), view: body.slice(len + 32, len + 64), kind };
}

// crypto::check_signature(prefix_hash, pub, sig)
function checkSignature(hash: Uint8Array, pub: Uint8Array, sig: Uint8Array): boolean {
  const c = leToBig(sig.slice(0, 32));
  const r = leToBig(sig.slice(32, 64));
  if (c >= L || r >= L || c === 0n) return false;
  let P;
  try { P = ed25519.Point.fromBytes(pub, true); } catch { return false; }
  const comm = P.multiplyUnsafe(c).add(ed25519.Point.BASE.multiplyUnsafe(r));
  if (comm.is0()) return false;
  const h = keccak_256(concat(hash, pub, comm.toBytes()));
  return leToBig(h) % L === c;
}

const MESSAGE_KEY = concat(new TextEncoder().encode("MoneroMessageSignature"), new Uint8Array([0]));

function messageHashV2(msg: Uint8Array, spend: Uint8Array, view: Uint8Array, mode: number) {
  return keccak_256(concat(MESSAGE_KEY, spend, view, new Uint8Array([mode]), writeVarint(msg.length), msg));
}

/** Verify a "SigV1…"/"SigV2…" signature from a Monero wallet over `message` for `address`. */
export function verifyMoneroMessage(message: string, address: string, signature: string): boolean {
  let addr: MoneroAddress;
  try { addr = decodeAddress(address); } catch { return false; }
  const sigStr = signature.trim();
  const version = sigStr.slice(0, 5);
  if (version !== "SigV1" && version !== "SigV2") return false;
  let sig: Uint8Array;
  try { sig = moneroBase58Decode(sigStr.slice(5)); } catch { return false; }
  if (sig.length !== 64) return false;
  const msg = new TextEncoder().encode(message);

  if (version === "SigV1") return checkSignature(keccak_256(msg), addr.spend, sig);
  // SigV2 spend-key signatures only (mode 0). View-key signatures (mode 1) are refused for
  // login: view keys are routinely shared with watch-only wallets and auditors.
  return checkSignature(messageHashV2(msg, addr.spend, addr.view, 0), addr.spend, sig);
}

/** True if the signature is a valid SigV2 made with the VIEW key (used to give a clearer error). */
export function isViewKeySignature(message: string, address: string, signature: string): boolean {
  try {
    const addr = decodeAddress(address);
    const s = signature.trim();
    if (!s.startsWith("SigV2")) return false;
    const sig = moneroBase58Decode(s.slice(5));
    const msg = new TextEncoder().encode(message);
    return sig.length === 64 && checkSignature(messageHashV2(msg, addr.spend, addr.view, 1), addr.view, sig);
  } catch { return false; }
}
