/**
 * One-time link handler.
 *
 * Reads key=...&uid=... from the URL fragment, stores them as cookies,
 * and redirects to the clean URL (fragment stripped).
 *
 * Link format: https://example.com/login#key=<base64url>&uid=<hex>
 */

(function () {
  if (!window.location.hash) return;

  var raw = window.location.hash.substring(1); // strip leading #
  if (!raw) return;

  var params = new URLSearchParams(raw);
  var key = params.get("key");
  var uid = params.get("uid");

  if (!key || !uid) return;

  // Validate key: unpadded base64url 32 bytes → always 43 characters.
  if (key.length !== 43 || !/^[A-Za-z0-9_-]+$/.test(key)) return;

  var expires = new Date();
  expires.setFullYear(expires.getFullYear() + 1);

  document.cookie =
    "__Host-key=" + encodeURIComponent(key) +
    "; expires=" + expires.toUTCString() +
    "; path=/" +
    "; Secure" +
    "; SameSite=Lax";

  document.cookie =
    "__Host-uid=" + encodeURIComponent(uid) +
    "; expires=" + expires.toUTCString() +
    "; path=/" +
    "; Secure" +
    "; SameSite=Lax";

  // Strip the fragment and redirect. The root page is now the index.
  window.location.replace("/" + window.location.search);
})();
