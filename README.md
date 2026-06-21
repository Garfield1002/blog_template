# static encrypted blog

A fully static blog where posts are client-side decrypted. No backend, no login page, no database.
Each user is sent an onboarding URL containing their uid and a 256-bit bearer secret in the URL fragment.
The browser stores credentials in localStorage, decrypts a per-user manifest, then decrypts posts.
Crawlers and random visitors see nothing but encrypted blobs.

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

Each `add-user.py` run prints an onboarding URL. Send it to the user. They open it once — the browser stores the credentials in localStorage — then the root page shows their post index.

## How it works

- **Posts** are Markdown files in `posts/` with YAML frontmatter (`access:` list of user IDs, `title`).
- **Users** are rows in `security/users.csv` (gitignored): name, uid, key, login URL.
- **Build** (`publish.py`) encrypts each post with a random DEK, builds per-user manifests (mapping slugs to DEKs), encrypts manifests with user keys, and renders per-user index pages (Jinja2) which are also encrypted.
- **Client** (`index.html` + `index.js`) reads key and uid from localStorage, fetches the user's encrypted index, decrypts it, and shows a post list. Clicking a post fetches the encrypted post body, decrypts it with the DEK from the manifest, and injects the HTML.
- **Crypto** is AES-256-GCM everywhere. Wrong key → GCM tag fails → redirect to unauthorized page.

## URLs

| Path | Purpose |
|------|---------|
| `/` | Root — authenticated users see their post index |
| `/login#key=...&uid=...` | Onboarding link landing page |
| `/logout/` | Clears key and uid from localStorage |
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


## Example Logins

> **Demo keys only.** The credentials below are published intentionally so visitors can explore the blog.
> In a real deployment, these onboarding URLs would be sent privately to each user.

[Alice](https://garfield1002.github.io/blog_template/login#key=tjBwKZwLI-TMhTlB_NxNox7PFs9KIS1YPoiULZuZ2KM&uid=14a63cfbf7677a4c) can access: [Hello, World](https://garfield1002.github.io/blog_template/post/?id=9cb01b8a88982f29), [Private Note](https://garfield1002.github.io/blog_template/post/?id=f2b3fa56d581fe41)
[Bob](https://garfield1002.github.io/blog_template/login#key=RN71uk2qUwqfX7Yi82MD7xU4ngrVPTDK022nNgJD_VY&uid=c12819fcd1af678d) can access: [Hello, World](https://garfield1002.github.io/blog_template/post/?id=9cb01b8a88982f29)

[logout](https://garfield1002.github.io/blog_template/logout/)
