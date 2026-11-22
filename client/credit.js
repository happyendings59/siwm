// Sign-In with Monero (SIWM) · Copyright 2026 Kenneth Mayle · https://5pm.io · https://kwm59.io
// Licensed under the Apache License, Version 2.0 (see LICENSE and NOTICE).
//
// A small, quiet credit line on the sign-in and account pages and in the wallet-confirm box:
//   "Sign-In with Monero · open source by 5pm.io"
// It's styled to stay out of the way (small, muted, at the bottom). The license doesn't require you to keep it,
// but if this saved you time, please do. Turn it off with `credit: false` in settings.js.
import { SETTINGS as S } from "./settings.js";

export const CREDIT_URL = "https://github.com/happyendings59/siwm";

export function addCredit(target) {
  if (S.credit === false) return;
  let el = target;
  if (!el) {
    if (document.querySelector("p.siwm-credit[data-page-credit]")) return;
    el = document.createElement("p");
    el.className = "siwm-credit";
    el.dataset.pageCredit = "";
    (document.querySelector("main") || document.body).append(el);
  }
  el.className = "siwm-credit";
  el.replaceChildren(
    link(CREDIT_URL, "Sign-In with Monero"),
    " · open source by ",
    link("https://5pm.io", "5pm.io"),
  );
}

function link(href, text) {
  const a = document.createElement("a");
  a.href = href;
  a.textContent = text;
  a.target = "_blank";
  a.rel = "noopener";
  return a;
}
