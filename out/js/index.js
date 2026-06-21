/**
 * Index page decryption engine.
 *
 * Reads key + uid from localStorage, fetches the user's encrypted index page
 * from /users/<uid>/index.enc, decrypts it with AES-256-GCM, and injects
 * the HTML into #content.
 */

/* ── Helpers (mirrored from decrypt.js for independence) ── */

function base64urlToBytes(str) {
  var b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  var raw = atob(b64);
  var bytes = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

async function decrypt(keyBytes, encData) {
  if (encData.byteLength < 28) {
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

/* ── Index flow ── */

async function loadIndex() {
  // Don't run during auth redirect — let auth.js handle the fragment first.
  if (window.location.hash) return;

  var keyB64 = localStorage.getItem("__Host-key");
  var uid = localStorage.getItem("__Host-uid");

  if (!keyB64 || !uid || !/^[a-f0-9]{16}$/.test(uid)) {
    var base = document.body.getAttribute("data-base") || ".";
    window.location.replace(base + "/unauthorized/");
    return;
  }

  var keyBytes = base64urlToBytes(keyB64);
  if (keyBytes.length !== 32) {
    throw new Error("Invalid key length: expected 32 bytes, got " + keyBytes.length);
  }

  var base = document.body.getAttribute("data-base") || ".";

  // Fetch and decrypt the user's encrypted index page.
  var resp = await fetch(base + "/users/" + encodeURIComponent(uid) + "/index.enc");
  if (!resp.ok) {
    throw new Error("Failed to fetch index: HTTP " + resp.status);
  }
  var encData = await resp.arrayBuffer();
  var raw = await decrypt(keyBytes, encData);
  var html = new TextDecoder().decode(raw);

  // Inject into the shell.
  var el = document.getElementById("content");
  if (el) {
    el.innerHTML = html;
  }
}

loadIndex().catch(function (err) {
  console.error("index error:", err);
  var base = document.body.getAttribute("data-base") || ".";
  window.location.replace(base + "/unauthorized/");
});
