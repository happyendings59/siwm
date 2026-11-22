// Sign-In with Monero (SIWM) · Copyright 2026 Kenneth Mayle · https://5pm.io · https://kwm59.io
// Licensed under the Apache License, Version 2.0 (see LICENSE and NOTICE).
// Wallet-first sign-in kit (brand-free; all site specifics live in settings.js).
// Bundle it yourself (`npm run bundle` -> dist/siwm.js) so nothing loads from a third-party CDN.
// The session is kept in this browser's localStorage only: no cookies, no analytics.
//
// Pages (picked by <body data-page="...">):
//   login    Monero sign-in (primary). Lost wallet: recover with backup email + recovery code.
//            Accounts that opted in may also sign in with an email code.
//   account  linked wallets, switch to a new Monero wallet, backup email + recovery code, sign out
//   anything else: fills any [data-auth-chip] element with "Sign in" or the signed-in account
//
// Recovery mode: a session from email recovery carries app_metadata.recovering (set by the server). Until the holder
// switches to a new Monero wallet, every page sends them to the account page's recovery step.
import { createClient } from "@supabase/supabase-js";
import { SETTINGS as S } from "./settings.js";
import { addCredit } from "./credit.js";

export const supabase = createClient(S.supabaseUrl, S.supabaseKey, {
  auth: { persistSession: true, autoRefreshToken: true, storageKey: `${S.storagePrefix}-auth` },
});
const FN = `${S.supabaseUrl}/functions/v1`;

const $ = (sel) => document.querySelector(sel);
const short = (a) => (a.length > 20 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a);
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const recovering = (session) => !!session?.user?.app_metadata?.recovering;

async function call(fn, body, accessToken) {
  const headers = { "content-type": "application/json" };
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;
  const r = await fetch(`${FN}/${fn}`, { method: "POST", headers, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok && r.status !== 202) {
    const err = new Error(data.error || "Something went wrong. Try again.");
    err.status = r.status;
    err.data = data;
    throw err;
  }
  return data;
}
const callXmr = (body, token) => call("xmr-auth", body, token);
async function callRecovery(body, needAuth) {
  let token;
  if (needAuth) token = (await supabase.auth.getSession()).data.session?.access_token;
  return call("recovery", body, token);
}

// ---------- "confirm with your wallet" ----------
// Sensitive changes (switch sign-in wallet, backup email / recovery code / settings, delete) need a fresh signature
// from the CURRENT sign-in wallet, so a session obtained by a look-alike site relaying a sign-in can't lock the
// holder out. The server answers 428 { confirm_needed, what } until it gets one; then we ask and retry once.
// (Recovery sessions don't need it for the wallet switch: the old wallet is lost.)
const CONFIRM_TITLES = {
  switch_wallet: "Confirm the wallet switch",
  recovery: "Confirm the change to your recovery settings",
  delete: "Confirm deleting your account",
};
function askWalletConfirm(what, detail) {
  return new Promise((resolve) => {
    const dlg = document.createElement("dialog");
    dlg.className = "wallet-confirm";
    dlg.style.cssText = "max-width:560px;width:calc(100% - 32px);border-radius:12px;padding:20px";
    const remembered = (() => { try { return localStorage.getItem(`${S.storagePrefix}-xmr-address`) || ""; } catch { return ""; } })();
    dlg.innerHTML = `
      <h3 style="margin-top:0"></h3>
      <p class="hint">For your safety, changes like this need a signature from the wallet you sign in with now. It doesn't move any funds.</p>
      <label>Your current sign-in Monero address
        <input class="wc-address" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="4… or 8…"></label>
      <button type="button" class="small wc-start">Get confirmation message</button>
      <div class="wc-sign" hidden>
        <p class="hint">Sign this in your CURRENT wallet (Cake: Settings → Other → Sign / Verify). Read it first: it should describe exactly what you asked for.</p>
        <div class="message-row"><code class="wc-message"></code><button type="button" class="small wc-copy">Copy</button></div>
        <textarea class="wc-signature" rows="3" spellcheck="false" autocapitalize="off" placeholder="SigV2…"></textarea>
        <button type="button" class="small wc-go">Confirm</button>
      </div>
      <p class="error wc-error" hidden></p>
      <p><button type="button" class="small wc-cancel">Cancel</button></p>
      <p class="siwm-credit"></p>`;
    dlg.querySelector("h3").textContent = CONFIRM_TITLES[what] || "Confirm with your wallet";
    const q = (c) => dlg.querySelector(c);
    q(".wc-address").value = remembered;
    addCredit(q(".siwm-credit"));
    let id = null;
    const done = (v) => { dlg.close(); dlg.remove(); resolve(v); };
    q(".wc-cancel").addEventListener("click", () => done(null));
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); done(null); });
    q(".wc-start").addEventListener("click", (e) => busy(e.currentTarget, async () => {
      say(q(".wc-error"), "");
      try {
        const token = (await supabase.auth.getSession()).data.session?.access_token;
        const r = await callXmr({ action: "confirm_start", what, detail, address: q(".wc-address").value.trim() }, token);
        id = r.id;
        q(".wc-message").textContent = r.message;
        q(".wc-sign").hidden = false;
        q(".wc-signature").focus();
      } catch (ex) { say(q(".wc-error"), ex.message); }
    }));
    q(".wc-copy").addEventListener("click", (e) => copy(q(".wc-message").textContent, e.currentTarget, q(".wc-message")));
    q(".wc-go").addEventListener("click", () => {
      const signature = q(".wc-signature").value.trim();
      if (!id || !signature) return say(q(".wc-error"), "Get the message, sign it, and paste the signature.");
      done({ id, address: q(".wc-address").value.trim(), signature });
    });
    document.body.append(dlg);
    dlg.showModal();
    if (!remembered) q(".wc-address").focus();
  });
}
/** Runs request(confirm); if the server asks for a wallet confirmation, gets one and retries once. */
async function withWalletConfirm(request, detail) {
  try {
    return await request(undefined);
  } catch (ex) {
    if (ex.status !== 428 || !ex.data?.confirm_needed) throw ex;
    const confirm = await askWalletConfirm(ex.data.what, detail);
    if (!confirm) throw new Error("Cancelled. Nothing was changed.");
    return await request(confirm);
  }
}

function say(el, msg) {
  if (!el) return;
  el.textContent = msg || "";
  el.hidden = !msg;
}

async function copy(text, button, fallbackEl) {
  try {
    await navigator.clipboard.writeText(text);
    const was = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = was), 1500);
  } catch {
    const range = document.createRange();
    range.selectNodeContents(fallbackEl);
    getSelection().removeAllRanges();
    getSelection().addRange(range);
  }
}

async function busy(btn, fn) {
  btn.disabled = true;
  try { await fn(); } finally { btn.disabled = false; }
}

async function useSession(session) {
  const { error } = await supabase.auth.setSession({ access_token: session.access_token, refresh_token: session.refresh_token });
  if (error) throw error;
}

const when = (iso) => new Date(iso).toLocaleString();

// Recovery codes are 20 LETTERS (no I or O) ending in a check letter (same rule as the server), so a typo is
// caught right here, before anything is sent, without telling anyone whether the code belongs to an account.
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const CODE_WEIGHTS = [1, 5, 7, 11, 13, 17, 19, 23];
function recoveryCodeProblem(input) {
  const raw = input.toUpperCase().replace(/[\s-]/g, "");
  const digit = raw.match(/[0-9]/);
  if (digit) return `Recovery codes are letters only; “${digit[0]}” is probably a letter that looks like it (0 → no O is used, so check it; 5 → S, 8 → B, 2 → Z, 6 → G).`;
  const c = raw.replace(/[^A-Z]/g, "");
  if (c.length !== 20) return `Your recovery code has 20 letters (like ABCDE-FGHJK-LMNPQ-RSTUV); this has ${c.length}.`;
  const bad = [...c].find((ch) => !CODE_ALPHABET.includes(ch));
  if (bad) return `“${bad}” never appears in recovery codes (no I or O are used). Check that letter.`;
  let sum = 0;
  for (let i = 0; i < 19; i++) sum += CODE_WEIGHTS[i % 8] * CODE_ALPHABET.indexOf(c[i]);
  if (CODE_ALPHABET[sum % 24] !== c[19]) return "That recovery code has a typo: a letter is off somewhere. Check it against your saved copy.";
  return null;
}

// ---------- login ----------
async function initLogin() {
  const { data } = await supabase.auth.getSession();
  const next = new URLSearchParams(location.search).get("next");
  const goNext = () => location.replace(next && next.startsWith("/") && !next.startsWith("//") ? next : S.paths.account);
  if (data.session) return recovering(data.session) ? location.replace(`${S.paths.account}?recover=1`) : goNext();

  for (const a of document.querySelectorAll("[data-cake-android]")) a.href = S.cakeWalletAndroid;
  for (const a of document.querySelectorAll("[data-cake-desktop]")) a.href = S.cakeWalletDesktop;

  const step1 = $("#step-address"), step2 = $("#step-sign");
  const err1 = $("#error-address"), err2 = $("#error-sign");
  let challengeId = null;
  const addrKey = `${S.storagePrefix}-xmr-address`;
  try { $("#address").value = localStorage.getItem(addrKey) || ""; } catch {}

  step1.addEventListener("submit", (e) => {
    e.preventDefault();
    say(err1, "");
    busy(step1.querySelector("button[type=submit]"), async () => {
      const address = $("#address").value.trim();
      try {
        const ch = await callXmr({ action: "challenge", address });
        challengeId = ch.id;
        $("#message").textContent = ch.message;
        try { localStorage.setItem(addrKey, address); } catch {}
        step1.hidden = true;
        step2.hidden = false;
        $("#signature").focus();
      } catch (ex) { say(err1, ex.message); }
    });
  });

  $("#copy-message").addEventListener("click", (e) => copy($("#message").textContent, e.currentTarget, $("#message")));
  $("#start-over").addEventListener("click", () => {
    step2.hidden = true;
    step1.hidden = false;
    $("#signature").value = "";
    say(err2, "");
  });

  step2.addEventListener("submit", (e) => {
    e.preventDefault();
    say(err2, "");
    busy(step2.querySelector("button[type=submit]"), async () => {
      try {
        const { session, new_account } = await callXmr({ action: "verify", id: challengeId, address: $("#address").value.trim(), signature: $("#signature").value });
        await useSession(session);
        // a brand-new account goes to the account page first (a good place to suggest a backup email)
        if (new_account) return location.replace(S.paths.account);
        goNext();
      } catch (ex) { say(err2, ex.message); }
    });
  });

  // ----- lost wallet: backup email + recovery code -----
  const rBox = $("#recover-box");
  if (rBox) {
    const rErr = $("#r-error"), rStatus = $("#r-status");
    $("#show-recover").addEventListener("click", () => {
      rBox.hidden = !rBox.hidden;
      if (!rBox.hidden) $("#r-email").focus();
    });
    const inputs = () => ({ email: $("#r-email").value.trim(), recoveryCode: $("#r-code").value.trim() });
    $("#r-send").addEventListener("click", (e) => {
      say(rErr, ""); say(rStatus, "");
      busy(e.currentTarget, async () => {
        const v = inputs();
        if (!EMAIL_RE.test(v.email)) return say(rErr, "Enter your backup email.");
        const typo = recoveryCodeProblem(v.recoveryCode);
        if (typo) return say(rErr, typo);
        try {
          await callRecovery({ action: "recover_start", ...v });
          say(rStatus, "If the email and recovery code match an account, a 6-digit code is on its way to that email. Nothing after a few minutes (check spam)? Then the email or the recovery code doesn't match: use the exact code you saved (copy-paste is safest). Only the most recent code you made works.");
          $("#r-otp-row").hidden = false;
          $("#r-otp").focus();
        } catch (ex) { say(rErr, ex.message); }
      });
    });
    $("#r-verify").addEventListener("click", (e) => {
      say(rErr, "");
      busy(e.currentTarget, async () => {
        try {
          const r = await callRecovery({ action: "recover_verify", ...inputs(), otp: $("#r-otp").value.trim() });
          if (r.pendingUntil) {
            say(rStatus, `${r.started ? "Recovery started." : "Recovery is waiting."} This account has a waiting period: come back after ${when(r.pendingUntil)} and do these steps again to finish. If you still have your wallet, signing in with it cancels the recovery.`);
            $("#r-otp-row").hidden = true;
            return;
          }
          await useSession(r.session);
          location.replace(`${S.paths.account}?recover=1`);
        } catch (ex) { say(rErr, ex.message); }
      });
    });
  }

  // ----- email sign-in (only accounts that turned it on) -----
  const eBox = $("#email-login");
  if (eBox) {
    const eErr = $("#email-error"), eStatus = $("#email-status");
    let chosen = null;
    $("#show-email").addEventListener("click", () => {
      eBox.hidden = !eBox.hidden;
      if (!eBox.hidden) $("#email").focus();
    });
    $("#email-send").addEventListener("click", (e) => {
      say(eErr, ""); say(eStatus, "");
      busy(e.currentTarget, async () => {
        const email = $("#email").value.trim();
        if (!EMAIL_RE.test(email)) return say(eErr, "Enter your email.");
        try {
          const r = await callRecovery({ action: "login_start", email });
          say(eStatus, r.message);
          $("#email-code-row").hidden = false;
          $("#email-code").focus();
        } catch (ex) { say(eErr, ex.message); }
      });
    });
    const verify = (btn) => busy(btn, async () => {
      say(eErr, "");
      try {
        const r = await callRecovery({ action: "login_verify", email: $("#email").value.trim(), otp: $("#email-code").value.trim(), account: chosen });
        if (r.choose) {
          const list = $("#email-choose");
          list.innerHTML = "";
          for (const c of r.choose) {
            const b = document.createElement("button");
            b.type = "button";
            b.className = "small";
            b.textContent = c.label;
            b.addEventListener("click", () => { chosen = c.account; verify(b); });
            list.append(b);
          }
          list.hidden = false;
          return say(eStatus, "That email backs up several accounts. Which one?");
        }
        await useSession(r.session);
        goNext();
      } catch (ex) { say(eErr, ex.message); }
    });
    $("#email-verify").addEventListener("click", (e) => verify(e.currentTarget));
  }
}

// ---------- account ----------
async function initAccount() {
  const { data } = await supabase.auth.getSession();
  if (!data.session) return location.replace(`${S.paths.login}?next=${encodeURIComponent(location.pathname)}`);
  const names = { xmr: "Monero", eth: "Ethereum", sol: "Solana", ada: "Cardano" };
  const userId = data.session.user.id;

  async function renderWallets() {
    const { data: wallets } = await supabase.from("wallets").select("chain, label, is_login, created_at").order("created_at");
    const list = $("#wallets");
    list.innerHTML = "";
    for (const w of wallets || []) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.className = "chain";
      label.textContent = (names[w.chain] || w.chain) + (w.is_login ? " · sign-in" : "");
      const addr = document.createElement("code");
      addr.textContent = w.label; // we only keep a short label, never the full address
      li.append(label, addr);
      list.append(li);
    }
  }

  // ----- backup email + recovery code -----
  const eErr = $("#email-error"), eStatus = $("#email-status");
  let status = { email: null };
  async function renderEmail() {
    status = await callRecovery({ action: "status" }, true).catch(() => ({ email: null }));
    const has = !!status.email;
    $("#email-current").textContent = has
      ? `Backup email: ${status.email} · waiting period: ${status.delayDays ? `${status.delayDays} days` : "none"}`
      : "No backup email. If you lose your Monero wallet, this account can't be recovered.";
    if (status.pending) say(eStatus, `A recovery was requested and finishes after ${when(status.pending)} unless you sign in with your wallet (which cancels it). If that wasn't you, someone has your email AND your recovery code: sign out and back in with Monero now, then make a new recovery code.`);
    $("#rec-manage").hidden = !has;
    $("#rec-setup").hidden = has;
    $("#e-delay-now").value = String(status.delayDays ?? 0);
    $("#email-login").checked = !!status.emailLogin;
  }
  function showCode(code) {
    $("#rec-code").textContent = code;
    $("#rec-code-box").hidden = false;
    $("#rec-saved").checked = false;
    $("#rec-done").disabled = true;
    $("#rec-code-box").scrollIntoView({ block: "center" });
  }
  $("#rec-copy").addEventListener("click", (e) => copy($("#rec-code").textContent, e.currentTarget, $("#rec-code")));
  $("#rec-download").addEventListener("click", () => {
    const text = `${S.siteName} recovery code\n\n${$("#rec-code").textContent}\n\nBackup email: ${status.email || $("#email-new").value.trim()}\n` +
      `Keep this somewhere safe and offline. With your backup email, it lets you recover your account if you lose your Monero wallet.\n`;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = `${S.storagePrefix}-recovery-code.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $("#rec-saved").addEventListener("change", (e) => ($("#rec-done").disabled = !e.target.checked));
  $("#rec-done").addEventListener("click", async () => {
    $("#rec-code").textContent = "";
    $("#rec-code-box").hidden = true;
    await renderEmail();
  });

  $("#email-save").addEventListener("click", (e) => {
    say(eErr, ""); say(eStatus, "");
    busy(e.currentTarget, async () => {
      const email = $("#email-new").value.trim();
      if (!EMAIL_RE.test(email)) return say(eErr, "Enter an email address.");
      try {
        await callRecovery({ action: "setup_start", email }, true);
        say(eStatus, `We sent a code to ${email}. Enter it to confirm.`);
        $("#email-code-row").hidden = false;
        $("#email-code").focus();
      } catch (ex) { say(eErr, ex.message); }
    });
  });
  $("#email-confirm").addEventListener("click", (e) => {
    say(eErr, "");
    busy(e.currentTarget, async () => {
      try {
        const r = await withWalletConfirm((confirm) => callRecovery({
          action: "setup_confirm", email: $("#email-new").value.trim(), otp: $("#email-code").value.trim(), delayDays: Number($("#e-delay").value), confirm,
        }, true));
        $("#email-code-row").hidden = true;
        $("#email-code").value = "";
        say(eStatus, "Backup email saved. It's only for recovery; you still sign in with Monero. Now save your recovery code:");
        await supabase.auth.refreshSession().catch(() => {});
        showCode(r.recoveryCode);
      } catch (ex) { say(eErr, ex.message); }
    });
  });
  $("#rec-new").addEventListener("click", (e) => {
    if (!confirm("Make your recovery code now? If you had one before, it stops working right away.")) return;
    say(eErr, ""); say(eStatus, "");
    busy(e.currentTarget, async () => {
      try {
        const r = await withWalletConfirm((confirm) => callRecovery({ action: "new_code", confirm }, true));
        say(eStatus, "Here's your recovery code. Keep it with your email info; any older code no longer works.");
        showCode(r.recoveryCode);
      } catch (ex) { say(eErr, ex.message); }
    });
  });
  $("#rec-change").addEventListener("click", () => {
    $("#rec-setup").hidden = false;
    $("#email-new").focus();
  });
  $("#e-delay-save").addEventListener("click", (e) => busy(e.currentTarget, async () => {
    say(eErr, ""); say(eStatus, "");
    try {
      await withWalletConfirm((confirm) => callRecovery({ action: "settings", delayDays: Number($("#e-delay-now").value), confirm }, true));
      say(eStatus, "Waiting period saved.");
      await renderEmail();
    } catch (ex) { say(eErr, ex.message); }
  }));
  $("#email-login").addEventListener("change", async (e) => {
    const on = e.target.checked;
    try {
      await withWalletConfirm((confirm) => callRecovery({ action: "settings", emailLogin: on, confirm }, true));
      say(eStatus, on ? "You can now also sign in with an email code (no recovery code needed for that)." : "Email codes are back to recovery only.");
    } catch (ex) { e.target.checked = !on; say(eErr, ex.message); }
  });
  $("#email-remove").addEventListener("click", (e) => {
    if (!confirm("Remove your backup email? Without it, losing your Monero wallet means losing this account.")) return;
    say(eErr, ""); say(eStatus, "");
    busy(e.currentTarget, async () => {
      try {
        await withWalletConfirm((confirm) => callRecovery({ action: "remove", confirm }, true));
        say(eStatus, "Backup email removed.");
        await renderEmail();
      } catch (ex) { say(eErr, ex.message); }
    });
  });

  // ----- switch the Monero sign-in to a new address (also how recovery finishes) -----
  const rErr = $("#replace-error"), rStatus = $("#replace-status");
  let replaceId = null;
  $("#replace-start").addEventListener("click", (e) => {
    say(rErr, ""); say(rStatus, "");
    busy(e.currentTarget, async () => {
      try {
        const { data: s } = await supabase.auth.getSession();
        const newAddr = $("#replace-address").value.trim();
        const ch = await callXmr({ action: "challenge", address: newAddr, replace: true }, s.session.access_token);
        replaceId = ch.id;
        // Same wallet as before: fine after restoring from the seed phrase, not if the seed may be compromised.
        if (ch.same) {
          say(rStatus, "This is the same wallet as before. That's fine if you restored it from your seed phrase. If someone else might have your seed phrase, use a brand-new wallet instead (and move your coins to it).");
        }
        $("#replace-message").textContent = ch.message;
        $("#replace-sign").hidden = false;
        $("#replace-signature").focus();
      } catch (ex) { say(rErr, ex.message); }
    });
  });
  $("#replace-copy").addEventListener("click", (e) => copy($("#replace-message").textContent, e.currentTarget, $("#replace-message")));
  $("#replace-confirm").addEventListener("click", (e) => {
    say(rErr, "");
    busy(e.currentTarget, async () => {
      try {
        const newAddr = $("#replace-address").value.trim();
        await withWalletConfirm((confirm) => callXmr({ action: "verify", id: replaceId, address: newAddr, signature: $("#replace-signature").value, confirm }), newAddr);
        try { localStorage.setItem(`${S.storagePrefix}-xmr-address`, $("#replace-address").value.trim()); } catch {}
        $("#replace-sign").hidden = true;
        $("#replace-address").value = $("#replace-signature").value = "";
        const wasRecovering = inRecoveryMode;
        await supabase.auth.refreshSession().catch(() => {}); // picks up recovering = false
        if (wasRecovering) {
          inRecoveryMode = false;
          showAll();
          say(rStatus, "Recovered. From now on, sign in with your new Monero wallet. Consider making a new recovery code below.");
          await renderEmail();
        } else say(rStatus, "Done. This account now signs in with the new wallet.");
        await renderWallets();
      } catch (ex) { say(rErr, ex.message); }
    });
  });

  // ----- recovery mode: only the wallet switch until it's done -----
  let inRecoveryMode = recovering(data.session);
  function showAll() {
    $("#recover-note").hidden = true;
    for (const id of ["#wallets-card", "#email-card"]) $(id).hidden = false;
  }
  if (inRecoveryMode) {
    $("#recover-note").hidden = false;
    for (const id of ["#wallets-card", "#email-card"]) $(id).hidden = true;
    await renderWallets();
  } else {
    await Promise.all([renderWallets(), renderEmail()]);
  }
  $("#account").hidden = false;
  $("#gate").hidden = true;

  $("#sign-out").addEventListener("click", async () => {
    await supabase.auth.signOut();
    location.replace(S.paths.home);
  });
  // ----- delete my account -----
  if ($("#delete-card")) {
    $("#delete-card").hidden = recovering(data.session);
    $("#delete-open").addEventListener("click", () => { $("#delete-confirm").hidden = false; $("#delete-open").hidden = true; $("#delete-address").focus(); });
    $("#delete-cancel").addEventListener("click", () => { $("#delete-confirm").hidden = true; $("#delete-open").hidden = false; say($("#delete-error"), ""); });
    $("#delete-go").addEventListener("click", () => busy($("#delete-go"), async () => {
      say($("#delete-error"), "");
      if (!confirm("Delete your account for good? This can't be undone.")) return;
      try {
        const token = (await supabase.auth.getSession()).data.session?.access_token;
        await withWalletConfirm((confirm) => callXmr({ action: "delete_account", address: $("#delete-address").value.trim(), confirm }, token));
        await supabase.auth.signOut();
        location.replace(`${S.paths.home}?deleted=1`);
      } catch (e) { say($("#delete-error"), e.message); }
    }));
  }
}

// ---------- other pages: small "Sign in" / account chip ----------
async function initChip() {
  const { data } = await supabase.auth.getSession();
  // Came in through email recovery: nothing else until a new Monero wallet is set.
  if (recovering(data.session)) return location.replace(`${S.paths.account}?recover=1`);
  const chips = document.querySelectorAll("[data-auth-chip]");
  if (!chips.length) return;
  let label = "Sign in", href = `${S.paths.login}?next=${encodeURIComponent(location.pathname)}`;
  if (data.session) {
    const { data: w } = await supabase.from("wallets").select("chain, label").eq("is_login", true).maybeSingle();
    label = w ? `${w.chain === "xmr" ? "XMR" : w.chain.toUpperCase()} ${w.label}` : "Account";
    href = S.paths.account;
    window.dispatchEvent(new CustomEvent("siwm:signed-in", { detail: { userId: data.session.user.id } }));
  }
  for (const c of chips) {
    c.textContent = label;
    c.href = href;
    c.hidden = false;
    // signed in: a "Sign out" link right after the account link, wherever the page shows it
    if (data.session && !c.nextElementSibling?.matches?.("[data-auth-signout]")) {
      const out = document.createElement("a");
      out.href = "#";
      out.textContent = "Sign out";
      out.dataset.authSignout = "";
      out.className = c.className;
      out.addEventListener("click", async (e) => {
        e.preventDefault();
        await supabase.auth.signOut();
        location.reload();
      });
      c.after(c.parentElement?.tagName === "P" ? " · " : "", out);
    }
  }
}

const page = document.body.dataset.page;
if (page === "login" || page === "account") addCredit();
if (page === "login") initLogin();
else if (page === "account") initAccount();
else initChip();
