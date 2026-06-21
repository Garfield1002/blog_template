/**
 * Static blog post decryption engine.
 *
 * Loaded by /post/.  crypto.js must be loaded first (provides base64urlToBytes
 * and decrypt).  Fetches the user manifest to get the DEK for the requested
 * post slug, fetches and decrypts the post blob, and injects the HTML.
 */

/* ── Decryption flow ── */

async function loadPost() {
  var slug = new URLSearchParams(window.location.search).get("id");
  if (!slug) return;

  var keyB64 = localStorage.getItem("__Host-key");
  var uid = localStorage.getItem("__Host-uid");

  if (!keyB64 || !uid || !/^[a-f0-9]{16}$/.test(uid)) {
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

  var base = document.body.getAttribute("data-base") || ".";

  // 1. Fetch and decrypt user manifest.
  var manifestResp = await fetch(base + "/users/" + encodeURIComponent(uid) + "/info.enc");
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
  var postResp = await fetch(base + "/posts/" + encodeURIComponent(slug) + ".enc");
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
  var base = document.body.getAttribute("data-base") || ".";
  window.location.replace(base + "/unauthorized/");
});
