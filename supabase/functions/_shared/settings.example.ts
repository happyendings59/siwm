// Copy to settings.ts and fill in. The ONLY place the server side names your site.
// EXTRA_ORIGINS (comma-separated env var) adds origins without a code change, e.g. a local preview.
export const SITE = {
  name: "Example",
  // Exact origins allowed to call the functions. The sign-in message names the caller's host and says
  // "Only sign this on https://<host>", so list only sites you control.
  origins: ["https://example.com", "https://www.example.com"],
  defaultOrigin: "https://example.com",
  // Placeholder sign-in emails for wallet accounts (random, never mailed). Use a domain you own.
  loginEmailDomain: "users.example.com",
  // Outgoing mail for backup-email codes. Password: edge-function secret SMTP_PASS. Port 465 (Supabase blocks 25/587).
  smtp: { host: "smtp.example.com", port: 465, user: "login@example.com", from: "Example <login@example.com>" },
};

export const ALLOWED_ORIGINS = new Set([
  ...SITE.origins,
  ...(Deno.env.get("EXTRA_ORIGINS") ?? "").split(",").map((s) => s.trim()).filter(Boolean),
]);
