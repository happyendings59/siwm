// Tests for supabase/functions/_shared/monero.ts. A tiny reference signer (same math as Monero's
// crypto::generate_signature + wallet2::sign_message, SigV2) makes fresh wallets and signatures.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { load } from "./load.mjs";

const M = await load("supabase/functions/_shared/monero.ts");
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const G = ed25519.Point.BASE;
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const concat = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const leToBig = (b) => b.reduceRight((a, v) => (a << 8n) | BigInt(v), 0n);
const bigToLe = (n) => { const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o; };
const randScalar = () => leToBig(crypto.getRandomValues(new Uint8Array(64))) % L || 1n;
const varint = (n) => { const o = []; while (n >= 0x80) { o.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); } o.push(n); return new Uint8Array(o); };

function b58block(bytes, encSize) {
  let num = leToBig([...bytes].reverse()); // big-endian
  let s = "";
  for (let i = 0; i < encSize; i++) { s = ALPHABET[Number(num % 58n)] + s; num /= 58n; }
  return s;
}
function b58(bytes) {
  const sizes = [0, 2, 3, 5, 6, 7, 9, 10, 11];
  let s = "";
  for (let i = 0; i < bytes.length; i += 8) { const blk = bytes.slice(i, i + 8); s += b58block(blk, sizes[blk.length]); }
  return s;
}

function wallet(prefix = 18) {
  const spend = randScalar(), view = randScalar();
  const S = G.multiply(spend).toBytes(), V = G.multiply(view).toBytes();
  const body = concat(varint(prefix), S, V);
  return { spend, view, S, V, address: b58(concat(body, keccak_256(body).slice(0, 4))) };
}
const KEY = concat(new TextEncoder().encode("MoneroMessageSignature"), new Uint8Array([0]));
function sign(w, message, mode = 0) {
  const msg = new TextEncoder().encode(message);
  const hash = keccak_256(concat(KEY, w.S, w.V, new Uint8Array([mode]), varint(msg.length), msg));
  const [sec, pub] = mode === 0 ? [w.spend, w.S] : [w.view, w.V];
  const k = randScalar();
  const c = leToBig(keccak_256(concat(hash, pub, G.multiply(k).toBytes()))) % L;
  const r = (((k - c * sec) % L) + L) % L;
  return "SigV2" + b58(concat(bigToLe(c), bigToLe(r)));
}

const MSG = "Sign in to example.com with Monero. Only sign this on https://example.com. It does not move any funds. Valid for 10 minutes. Code: ABCD-EFGH-JKLM";

test("decodes a standard address and a subaddress", () => {
  const w = wallet(18), sub = wallet(42);
  assert.equal(M.decodeAddress(w.address).kind, "standard");
  assert.deepEqual(M.decodeAddress(w.address).spend, w.S);
  assert.equal(M.decodeAddress(sub.address).kind, "subaddress");
  assert.equal(w.address.length, 95);
});

test("rejects a mistyped address (checksum)", () => {
  const a = wallet().address;
  const typo = a.slice(0, 40) + (a[40] === "A" ? "B" : "A") + a.slice(41);
  assert.throws(() => M.decodeAddress(typo));
  assert.throws(() => M.decodeAddress("not an address"));
});

test("accepts a SigV2 spend-key signature for the exact message", () => {
  const w = wallet();
  assert.equal(M.verifyMoneroMessage(MSG, w.address, sign(w, MSG)), true);
});

test("rejects a changed message, another wallet, or a tampered signature", () => {
  const w = wallet(), other = wallet();
  const sig = sign(w, MSG);
  assert.equal(M.verifyMoneroMessage(MSG + " ", w.address, sig), false);
  assert.equal(M.verifyMoneroMessage(MSG.replace("example.com", "examp1e.com"), w.address, sig), false);
  assert.equal(M.verifyMoneroMessage(MSG, other.address, sig), false);
  const flipped = sig.slice(0, 20) + (sig[20] === "x" ? "y" : "x") + sig.slice(21);
  assert.equal(M.verifyMoneroMessage(MSG, w.address, flipped), false);
  assert.equal(M.verifyMoneroMessage(MSG, w.address, "SigV2"), false);
  assert.equal(M.verifyMoneroMessage(MSG, w.address, "hello"), false);
});

test("refuses view-key signatures for sign-in, but recognises them for a clearer error", () => {
  const w = wallet();
  const viewSig = sign(w, MSG, 1);
  assert.equal(M.verifyMoneroMessage(MSG, w.address, viewSig), false);
  assert.equal(M.isViewKeySignature(MSG, w.address, viewSig), true);
  assert.equal(M.isViewKeySignature(MSG, w.address, sign(w, MSG)), false);
});

test("works for a subaddress", () => {
  // A real subaddress has its own spend/view pair; signing with that pair is what the wallet does.
  const sub = wallet(42);
  assert.equal(M.verifyMoneroMessage(MSG, sub.address, sign(sub, MSG)), true);
});
