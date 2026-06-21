# How does this website work ?

A fully static semi-private blog — how's that possible ?

The reader is trusted. The server/storage is not trusted with plaintext. Random internet users are not trusted.

Security through obscurity is the worst kind of security, therefore I should be able to share the technical details of the site without compromising its security.

## What this protects against

This is designed to stop random visitors, crawlers, search engines, and people browsing the static files from reading private posts.

## Why not just use a login?

A normal login requires a backend that decides who can read what.
I wanted the site to stay fully static, free to host, and easy to archive.

The tradeoff is that access control can't be done by a server, which makes it harder (or more interesting).

## Encryption

The solution is to encrypt the blog.
The server only hosts encrypted blobs.

Each post is encrypted with AES-256-GCM using a random Data Encryption Key (DEK).

### The key needs to come from somewhere

White-box-cryptography (hiding the key in the distributed code), is broken.
It's a form of obfuscation, and as such attackers will always win.

But if the key isn't in the code where is it ?

Each user is sent an onboarding URL containing their uid and secret key in the URL fragment.

This is not password-based authentication. The URL fragment contains a random 256-bit bearer secret. Anyone who has that secret can decrypt that user's manifest.

The user's key encrypts their per-user manifest and their per-user index page.

### User identity

Users are identified by a random 16-character hex string (64 bits of entropy). Sequential integers were used in early prototypes; random strings prevent trivial enumeration of users and their manifests.

### Manifest

Each user has a manifest stored at `/users/<uid>/info.enc`.

The manifest is encrypted with the user's AES-256 key using AES-256-GCM (random 96-bit nonce).

When decrypted, the manifest contains a mapping of post slugs to raw DEKs:

```json
{
  "posts": {
    "a1b2c3d4e5f6": "<base64url-encoded-32-byte-DEK>",
    "7890abcdef12": "<base64url-encoded-32-byte-DEK>"
  }
}
```

### Per-user index page

Each user also has an encrypted index page at `/users/<uid>/index.enc`.

This is an HTML fragment rendered at build time (Jinja2), encrypted with the user's key. It contains a greeting and a list of links to the user's accessible posts. Like the manifest, it is decrypted client-side via the Web Crypto API.

### Posts

Each post lives at `/posts/<slug>.enc`. Slugs are random 16-character hex strings (same format as user IDs) — they are not derived from the post filename or title. This prevents guessing post URLs.

Each post is encrypted with its own random DEK using AES-256-GCM (random 96-bit nonce).
When decrypted, the blob yields the post's raw HTML.

### Binary format

Both user manifests, index pages, and post blobs use the same on-disk format:

```
[12 bytes: random nonce] [variable: ciphertext + 16 bytes: GCM auth tag]
```

### Flow

1. You receive an onboarding URL: `https://example.com/login#key=<base64url-key>&uid=<16-char-hex>`
2. The `/login/` page loads `auth.js`, which parses the fragment, stores the key and uid in localStorage, then redirects to `/`.
3. The root page (`/`) loads `index.js`, which reads key and uid from localStorage, fetches `/users/<uid>/index.enc`, decrypts it with your key, and injects the HTML — showing a greeting and a list of posts you can access.
4. When you click a post link (`/post/?id=<slug>`), the browser fetches `/users/<uid>/info.enc` (the manifest), decrypts it, looks up the DEK for the slug, fetches `/posts/<slug>.enc`, and decrypts it.
5. If decryption fails (wrong key, missing manifest, corrupted data), the GCM auth tag won't verify — the user is redirected to `/unauthorized/`.

### Why per-build DEKs?

DEKs are regenerated on every build and never stored on disk. This avoids a DEK store that could be exfiltrated. The cost is re-encrypting all posts on every publish, which for a personal blog is negligible.

## Threat model

### In scope

- Random visitors and crawlers cannot read posts.
- Post slugs are random (unguessable), and user IDs are random — enumeration is infeasible.
- The access graph (who can read what) is hidden inside encrypted manifests.
- An attacker who obtains a user's key can read that user's posts and nothing more.
- The root page, index pages, and post pages are all encrypted blobs or shells — without a key, nothing is revealed.

### Out of scope

- A user who shares their key or decrypted content.
- A user who saves or copies decrypted content.
- Cross-device support for v1 (new device = need the onboarding URL again).
- Physical or endpoint compromise of the publisher's laptop.

### Metadata

The content and access graph are encrypted, but the site still leaks some metadata:

- **Number of users** — visible from the directory listing under `out/users/` (one subdirectory per user).
- **Number of posts** — visible from `out/posts/` (one `.enc` file per post).
- **Per-user access count** — manifest sizes (`info.enc`) and index page sizes (`index.enc`) correlate to how many posts a user can access. A user with 50 posts will have a noticeably larger manifest than one with 1 post.
- **Post sizes** — encrypted blob sizes reveal approximate plaintext length (AES-GCM adds 28 bytes of overhead: 12-byte nonce + 16-byte tag). A 5 KB post is clearly longer than a 500-byte one.
- **File modification times** — `git` records when each `.enc` file was last rebuilt.

All `.enc` files and the `out/` directory are committed to the repository (see [Deployment](#deployment)). I do not try to hide metadata in v1.

### Deployment

The `out/` directory is committed to git and deployed via GitHub Pages. CI does not run `publish.py` because the workflow cannot access `posts/` or `security/users.csv` (those are gitignored secrets). Instead, the build runs on the publisher's laptop and the resulting ciphertext is committed.

This is safe because everything in `out/` is encrypted with AES-256-GCM. An attacker who obtains the ciphertext cannot decrypt it without a user's 256-bit key. Brute-forcing AES-256 is infeasible.

## Access control

Post access is specified via frontmatter in the Markdown source:

```markdown
---
access: ["14a63cfbf7677a4c", "c12819fcd1af678d"]
title: My Post
date: 2025-06-21
---

# Hello world
```

The `access` list contains user IDs (16-char hex strings). Only listed users receive the post's DEK in their manifest and see it in their index.

## Pages

| Path | Purpose |
|------|---------|
| `/` | Root — authenticated users see their encrypted post index |
| `/login#key=...&uid=...` | Onboarding link landing page |
| `/login/` | Stripped-fragment redirect target (handled by auth.js) |
| `/logout/` | Clears key and uid from localStorage, redirects to `/` |
| `/post/?id=<slug>` | Individual encrypted post |
| `/unauthorized/` | Shown when not authenticated or decryption fails |
| `/arch.html` | This document (public) |

## Adding a user

Script: `./scripts/add-user.py <name>`

- Generates a random 256-bit key (32 bytes, base64url-encoded).
- Generates a random 16-character hex user ID (64 bits of entropy).
- Appends to `security/users.csv` (name, uid, key_b64, login_url).
- Prints the onboarding URL (`/login#key=...&uid=...`).

## Revoking a user

Script: `./scripts/revoke-user.py <uid>`

- Removes the user from `security/users.csv`.
- Triggers a full rebuild: regenerates all DEKs, re-encrypts all posts, rebuilds every remaining user's manifest and index page.
- Deploys to a clean output directory — the revoked user's manifest and index are not generated, so they disappear from the static host.

Revocation only affects the newly deployed site. It does not invalidate copies of old encrypted blobs that the user already downloaded. Their old `.enc` manifest and index are no longer deployed after the next rebuild. They can't read new posts.

## Rebuilding after a post change

Script: `./scripts/publish.py`

- Parses all Markdown posts, reads access frontmatter and titles.
- For each post: generates a random 16-char hex slug, generates a new random DEK, encrypts the HTML.
- For each authorized user: embeds the raw DEK in their manifest.
- Renders a per-user index page (Jinja2) with the user's name and post links, encrypts it.
- Encrypts each user's manifest with that user's key.
- Converts `architecture.md` to `/arch.html` (public).
- Writes all `.enc` files, static assets, and pages to a clean output directory.
- Output directory replaces the previous deployment (no stale files).

## What if you share your key?

Shame on you!

In this situation, the scheme cannot help.
Anyone who has a user's key can decrypt that user's manifest and index and read all posts that user can access.

I don't stop you from doing it though, so this part relies on the honor system.

## What if someone loses their key?

Their old `.enc` manifest and index are no longer deployed after the next rebuild. They can't read new posts. Revocation only affects the newly deployed site. It does not invalidate copies of old encrypted blobs that the user already downloaded.

For already-published content, if they cached their manifest, index, and the post blobs, they can still read them. This is inherent to a static scheme — there is no server to check freshness.

## Crypto stack

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-GCM |
| Key size | 256 bits (32 bytes) |
| Nonce / IV | 96 bits (12 bytes), random per encryption |
| Auth tag | 128 bits (16 bytes), appended to ciphertext |
| Key encoding | Unpadded base64url (RFC 4648 §5) |
| Client API | Web Crypto API (`crypto.subtle`) |
| Python lib | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |

No KDF. No key wrapping. Raw 256-bit keys used directly — the key is already a random 256-bit string; adding PBKDF2 would only burn CPU for no security gain.

## CSP

All pages ship a strict Content Security Policy via `<meta>` tag:

```
default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'none'
```

No inline scripts, no external resources, no CDNs. All JS is external (`<script src="...">`). Styles are external stylesheets. Fetch requests are same-origin only.
