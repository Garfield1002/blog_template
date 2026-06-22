/**
 * Onboarding link handler.
 *
 * Reads key=...&uid=... from the URL fragment, stores them in localStorage,
 * and redirects to the clean URL (fragment stripped).
 *
 * Link format: https://example.com/login.html#key=<base64url>&uid=<hex>
 */

(function () {
  if (!window.location.hash) return;

  var raw = window.location.hash.substring(1);
  if (!raw) return;

  var params = new URLSearchParams(raw);
  var key = params.get("key");
  var uid = params.get("uid");

  if (!key || !uid) return;

  // Validate key: unpadded base64url 32 bytes → always 43 characters.
  if (key.length !== 43 || !/^[A-Za-z0-9_-]+$/.test(key)) return;
  if (!/^[a-f0-9]{16}$/.test(uid)) return;

  localStorage.setItem("static-blog-key", key);
  localStorage.setItem("static-blog-uid", uid);
  localStorage.removeItem("__Host-key");
  localStorage.removeItem("__Host-uid");

  // Strip the fragment and redirect to index.
  var base = document.body.getAttribute("data-base") || ".";
  window.location.replace(base + "/");
})();
