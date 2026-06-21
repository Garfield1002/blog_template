/**
 * Static blog decryption engine.
 *
 * Handles:
 *  - One-time link fragment (#key=...&uid=...) → cookie set + redirect
 *  - Post decryption via ?id=<slug>
 *
 * Crypto: AES-256-GCM, raw binary .enc files (12-byte nonce + ciphertext+tag).
 */

/* ── One-time link handler (same as auth.js, in case link points to /post/) ── */

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

  window.location.replace(window.location.pathname + window.location.search);
})();

/* ── Helpers ── */

function getCookie(name) {
  var match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Convert a base64url string to a Uint8Array.
 * Uses the standard base64url alphabet (RFC 4648 §5).
 */
function base64urlToBytes(str) {
  // Restore standard base64.
  var b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding.
  while (b64.length % 4) b64 += "=";
  var raw = atob(b64);
  var bytes = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

/* ── Crypto ── */

/**
 * Decrypt raw .enc bytes with AES-256-GCM.
 *
 * @param {Uint8Array} keyBytes  — 32-byte AES-256 key
 * @param {ArrayBuffer} encData  — raw .enc file bytes
 * @returns {Promise<ArrayBuffer>} plaintext
 */
async function decrypt(keyBytes, encData) {
  if (encData.byteLength < 28) {
    // Minimum: 12 (nonce) + 1 (payload) + 16 (tag)
    throw new Error("enc file too short: " + encData.byteLength + " bytes");
  }

  var full = new Uint8Array(encData);
  var nonce = full.slice(0, 12);
  var ciphertext = full.slice(12);

  var key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, tagLength: 128 },
    key,
    ciphertext
  );
}

/* ── Decryption flow ── */

async function loadPost() {
  var slug = new URLSearchParams(window.location.search).get("id");
  if (!slug) return; // v1: nothing to show

  var keyB64 = getCookie("__Host-key");
  var uid = getCookie("__Host-uid");

  if (!keyB64 || !uid) {
    throw new Error("Missing credentials — visit your one-time link first.");
  }

  // Validate slug: only allow safe characters (alphanumeric, hyphens, underscores).
  if (!/^[a-zA-Z0-9_-]+$/.test(slug)) {
    throw new Error("Invalid post slug.");
  }

  var keyBytes = base64urlToBytes(keyB64);
  if (keyBytes.length !== 32) {
    throw new Error("Invalid key length: expected 32 bytes, got " + keyBytes.length);
  }

  // 1. Fetch and decrypt user manifest.
  var manifestResp = await fetch("/users/" + encodeURIComponent(uid) + "/info.enc");
  if (!manifestResp.ok) {
    throw new Error("Failed to fetch user manifest: HTTP " + manifestResp.status);
  }
  var manifestEnc = await manifestResp.arrayBuffer();
  var manifestRaw = await decrypt(keyBytes, manifestEnc);
  var manifestStr = new TextDecoder().decode(manifestRaw);
  var manifest;
  try {
    manifest = JSON.parse(manifestStr);
  } catch (e) {
    throw new Error("Failed to parse manifest JSON: " + e.message);
  }

  // 2. Look up DEK for this slug.
  var dekB64 = manifest.posts && manifest.posts[slug];
  if (!dekB64) {
    throw new Error("Post not found or access denied: " + slug);
  }
  var dekBytes = base64urlToBytes(dekB64);
  if (dekBytes.length !== 32) {
    throw new Error("Invalid DEK length for post: " + slug);
  }

  // 3. Fetch and decrypt post.
  var postResp = await fetch("/posts/" + encodeURIComponent(slug) + ".enc");
  if (!postResp.ok) {
    throw new Error("Failed to fetch post: HTTP " + postResp.status);
  }
  var postEnc = await postResp.arrayBuffer();
  var postRaw = await decrypt(dekBytes, postEnc);
  var html = new TextDecoder().decode(postRaw);

  // 4. Inject.
  var el = document.getElementById("content");
  if (el) {
    el.innerHTML = html;
  }
}

loadPost().catch(function (err) {
  console.error("decrypt error:", err);
  window.location.replace("/unauthorized/");
});
