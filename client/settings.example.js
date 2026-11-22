// Copy to settings.js and fill in. This is the ONLY place the browser side names your site.
// (Server side: supabase/functions/_shared/settings.ts.)
export const SETTINGS = {
  siteName: "Example",
  supabaseUrl: "https://YOUR-PROJECT-REF.supabase.co",
  supabaseKey: "sb_publishable_...", // the PUBLISHABLE key (safe in a browser). Never the service-role key.
  storagePrefix: "example", // localStorage key prefix (session + remembered address)
  paths: { home: "/", login: "/login/", account: "/account/" },
  // Monero wallet suggested on the sign-in page
  cakeWalletDesktop: "https://cakewallet.com/",
  cakeWalletAndroid: "https://play.google.com/store/apps/details?id=com.cakewallet.cake_wallet",
  // Small "Sign-In with Monero · open source by 5pm.io" line on the sign-in pages. Kept is appreciated.
  credit: true,
};
