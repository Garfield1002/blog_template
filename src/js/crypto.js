/**
 * Shared cryptographic helpers for the static encrypted blog.
 *
 * Crypto: AES-256-GCM.  All .enc files are [12-byte nonce][ciphertext+16-byte tag].
 */

/**
 * Convert a base64url string to a Uint8Array.
 * Uses the standard base64url alphabet (RFC 4648 §5).
 */
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

/**
 * Decrypt raw .enc bytes with AES-256-GCM.
 *
 * @param {Uint8Array} keyBytes  — 32-byte AES-256 key
 * @param {ArrayBuffer} encData  — raw .enc file bytes
 * @returns {Promise<ArrayBuffer>} plaintext
 */
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
