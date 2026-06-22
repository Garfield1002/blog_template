# static encrypted blog

A fully static blog where posts are client-side decrypted. No backend, no login page, no database.
Each user is sent an onboarding URL containing their uid and a 256-bit bearer secret in the URL fragment.
The browser stores credentials in localStorage, decrypts a per-user manifest, then decrypts posts.
Crawlers and random visitors see nothing but encrypted blobs.

## Quick start

```bash
# Install dependencies
uv sync

# Add users
uv run add-user Alice
uv run add-user Bob

# Create a post (posts/hello-world.md)
# ---
# access: [<alice-uid>, <bob-uid>]
# title: Hello, World
# ---
# # Hello, World
# ...

# Build
uv run publish

# Serve
python -m http.server -d out/ 8080
```

Each `uv run add-user` run prints an onboarding URL. Send it to the user. They open it once — the browser stores the credentials in localStorage — then the root page shows their post index.

## How it works

- **Posts** are Markdown files in `posts/` with YAML frontmatter (`access:` list of user IDs, `title`).
- **Users** are rows in `security/users.csv` (gitignored): name, uid, key, login URL.
- **Build** (`publish.py`) encrypts each post with a random DEK, builds per-user manifests (mapping slugs to DEKs), encrypts manifests with user keys, and renders per-user index pages (Jinja2) which are also encrypted.
- **Client** (`index.html` + `index.js`) reads key and uid from localStorage (`static-blog-key` / `static-blog-uid`), fetches the user's encrypted index, decrypts it, and shows a post list. Clicking a post fetches the encrypted post body, decrypts it with the DEK from the manifest, and injects the HTML.
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

## Security notes

The static host is not trusted with plaintext at rest, but it **is** trusted to serve the correct HTML and JavaScript. A compromised repo, deployment, DNS record, or static host could serve malicious JavaScript that steals the browser-stored bearer key. Keep this origin dedicated to this app only: do not add analytics, comments, third-party scripts, unrelated pages, or other apps to the same origin.

Keep local secrets private too: `security/` and `posts/` should be mode `700`, and files inside them should be mode `600`. The user-management scripts create `security/users.csv` with `0600` permissions.

## Revoking access

```bash
uv run revoke-user <uid>
uv run publish                       # rebuild — revoked user's files are gone
```

## Commands

- `uv run add-user <name>` — create a user and print their onboarding URL.
- `uv run revoke-user <uid>` — remove a user from `security/users.csv`.
- `uv run publish` — rebuild the encrypted static site.
- `uv run make_example [--base-url URL]` — regenerate the README demo-login section from the current build.

## Dependencies

Use `uv sync` to install the pinned Python dependency set from `uv.lock`.

- Python: `cryptography`, `mistune`, `Jinja2`, `PyYAML`
- Browser: Web Crypto API (AES-GCM), ES6


## Example Logins

> **Demo keys only.** The credentials below are published intentionally so visitors can explore the blog.
> In a real deployment, these onboarding URLs would be sent privately to each user.

[Alice](https://garfield1002.github.io/blog_template/login#key=tjBwKZwLI-TMhTlB_NxNox7PFs9KIS1YPoiULZuZ2KM&uid=14a63cfbf7677a4c) can access: [Hello, World](https://garfield1002.github.io/blog_template/post/?id=ef0df314effa5c0f), [Private Note](https://garfield1002.github.io/blog_template/post/?id=6c6633e2da93db38)
[Bob](https://garfield1002.github.io/blog_template/login#key=RN71uk2qUwqfX7Yi82MD7xU4ngrVPTDK022nNgJD_VY&uid=c12819fcd1af678d) can access: [Hello, World](https://garfield1002.github.io/blog_template/post/?id=ef0df314effa5c0f)

[logout](https://garfield1002.github.io/blog_template/logout/)
