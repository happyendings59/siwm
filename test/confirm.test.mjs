// The confirm messages must name the action and the site, so a holder who only meant to sign in sees a red flag.
import { test } from "node:test";
import assert from "node:assert/strict";
import { load } from "./load.mjs";

const C = await load("supabase/functions/_shared/confirm.ts");

test("confirm messages name the action, the site and the new wallet", () => {
  const m = C.confirmMessage("example.com", "switch_wallet", "8AbC…xYz9", "ABCD-EFGH-JKLM");
  assert.match(m, /^Confirm on example\.com: switch your sign-in wallet to 8AbC…xYz9\./);
  assert.match(m, /Only sign this on https:\/\/example\.com/);
  assert.match(m, /does not move any funds/);
  assert.match(C.confirmMessage("example.com", "delete", "", "X"), /DELETE your account/);
  assert.ok(!/\n/.test(m), "one line, so pasting into a wallet can't change it");
});
