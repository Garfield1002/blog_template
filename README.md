# static encrypted blog

A fully static blog where posts are client-side decrypted. No backend, no login page, no database. Users receive a one-time link containing an AES-256 key. The browser stores it in a cookie, decrypts a per-user manifest, then decrypts posts. Crawlers and random visitors see nothing but encrypted blobs.

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Add users
python scripts/add-user.py Alice
python scripts/add-user.py Bob

# Create a post (posts/hello-world.md)
# ---
# access: [<alice-uid>, <bob-uid>]
# title: Hello, World
# ---
# # Hello, World
# ...

# Build
python scripts/publish.py

# Serve
python -m http.server -d out/ 8080
```

Each `add-user.py` run prints a one-time link. Send it to the user. They open it once — the browser stores the credentials in cookies — then the root page shows their post index.

## How it works

- **Posts** are Markdown files in `posts/` with YAML frontmatter (`access:` list of user IDs, `title`).
- **Users** are rows in `security/users.csv` (gitignored): name, uid, key, login URL.
- **Build** (`publish.py`) encrypts each post with a random DEK, builds per-user manifests (mapping slugs to DEKs), encrypts manifests with user keys, and renders per-user index pages (Jinja2) which are also encrypted.
- **Client** (`index.html` + `index.js`) reads cookies, fetches the user's encrypted index, decrypts it, and shows a post list. Clicking a post fetches the encrypted post body, decrypts it with the DEK from the manifest, and injects the HTML.
- **Crypto** is AES-256-GCM everywhere. Wrong key → GCM tag fails → redirect to unauthorized page.

## URLs

| Path | Purpose |
|------|---------|
| `/` | Root — authenticated users see their post index |
| `/login#key=...&uid=...` | One-time link landing page |
| `/logout/` | Clears cookies |
| `/post/?id=<slug>` | Individual post |
| `/unauthorized/` | Shown when not authenticated |
| `/arch.html` | Public architecture document |

## Architecture

See [architecture.md](architecture.md) for the full design, threat model, and crypto rationale. Rendered at `/arch.html` in the built site.

## Revoking access

```bash
python scripts/revoke-user.py <uid>
python scripts/publish.py     # rebuild — revoked user's files are gone
```

## Dependencies

- Python: `cryptography`, `mistune`, `Jinja2`, `PyYAML`
- Browser: Web Crypto API (AES-GCM), ES6
