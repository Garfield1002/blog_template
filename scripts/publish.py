#!/usr/bin/env python3
"""
Build the static encrypted blog bundle.

Flow:
1. Clean and recreate the output directory.
2. Copy static assets (HTML, JS) from src/ to out/, skipping templates.
3. Read all markdown posts from posts/, parse frontmatter, convert to HTML.
4. Generate a random 256-bit DEK for each post, encrypt the HTML.
5. Read security/users.csv for user keys.
6. For each user, build a manifest of {slug: raw_DEK} for posts they can access.
7. Encrypt each user's manifest with their key.
8. Render a per-user index page (Jinja2), encrypt with user key.
9. Write all .enc files to out/.
"""

import base64
import csv
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
from pathlib import Path

import jinja2
import mistune
import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
POSTS_DIR = BASE_DIR / "posts"
USERS_CSV = BASE_DIR / "security" / "users.csv"
OUT_DIR = BASE_DIR / "out"


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt, return nonce || ciphertext+tag."""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def sri_hash(filepath: Path) -> str:
    """Compute sha256-<base64> SRI integrity hash for a file."""
    sha256 = hashlib.sha256(filepath.read_bytes()).digest()
    b64 = base64.b64encode(sha256).decode("ascii")
    return f"sha256-{b64}"


def inject_sri(html_path: Path) -> None:
    """Add integrity attributes to <script src="..."> tags in an HTML file.

    Resolves each src relative to the HTML file's directory, computes the
    SHA-256 hash of the referenced JS file, and injects an integrity attribute.
    Tags that already have an integrity attribute are left unchanged.
    """
    html = html_path.read_text(encoding="utf-8")
    html_dir = html_path.parent

    def replace_script_tag(match):
        tag = match.group(0)
        if "integrity=" in tag:
            return tag
        src = match.group(1)
        js_path = (html_dir / src).resolve()
        if js_path.exists():
            integrity = sri_hash(js_path)
            return tag[:-1] + f' integrity="{integrity}">'
        return tag

    new_html = re.sub(
        r'<script\s[^>]*src="([^"]+)"[^>]*>',
        replace_script_tag,
        html,
    )
    html_path.write_text(new_html, encoding="utf-8")


def parse_post(filepath: Path) -> dict:
    """
    Parse a markdown post with YAML frontmatter.

    Returns dict with keys: slug, title, access, html
    """
    raw = filepath.read_text(encoding="utf-8")
    if not raw.startswith("---"):
        raise ValueError(f"{filepath}: missing frontmatter (must start with ---)")

    parts = raw.split("---", 2)
    if len(parts) < 3:
        raise ValueError(f"{filepath}: invalid frontmatter")

    meta = yaml.safe_load(parts[1]) or {}
    body = parts[2].strip()

    slug = secrets.token_hex(8)  # 16 random hex chars

    access = meta.get("access", [])
    if not isinstance(access, list):
        access = [access]
    # Coerce to strings (handles legacy int UIDs and new hex string UIDs).
    access = [str(uid) for uid in access]

    title = meta.get("title", slug)

    html = mistune.html(body)

    return {
        "slug": slug,
        "title": title,
        "access": access,
        "html": html,
    }


def read_users() -> list[dict]:
    """Read security/users.csv, return list of {name, id, key_bytes}."""
    if not USERS_CSV.exists():
        print(f"Warning: {USERS_CSV} not found — no users configured.", file=sys.stderr)
        return []

    users = []
    with open(USERS_CSV, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            try:
                name = row[0]
                uid = row[1]  # hex string
                key_b64 = row[2]
                # row[3] is login URL — not needed during build
                key_bytes = base64url_decode(key_b64)
                if len(key_bytes) != 32:
                    print(f"Error: user {uid} key is {len(key_bytes)} bytes, expected 32.", file=sys.stderr)
                    sys.exit(1)
                users.append({"name": name, "id": uid, "key": key_bytes})
            except (IndexError, ValueError) as e:
                print(f"Warning: malformed row in users.csv: {row} ({e})", file=sys.stderr)
                continue

    return users


def main() -> None:
    # Validate inputs.
    if not SRC_DIR.is_dir():
        print(f"Error: src/ directory not found at {SRC_DIR}", file=sys.stderr)
        sys.exit(1)
    if not POSTS_DIR.is_dir():
        print(f"Error: posts/ directory not found at {POSTS_DIR}", file=sys.stderr)
        sys.exit(1)

    posts = sorted(POSTS_DIR.glob("*.md"))
    if not posts:
        print("Warning: no .md posts found in posts/", file=sys.stderr)

    users = read_users()
    if not users:
        print("Warning: no users configured — manifests will not be generated.", file=sys.stderr)

    # 1. Clean output directory.
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True)

    # 2. Copy static assets (skip templates in src/user/).
    shutil.copytree(
        SRC_DIR,
        OUT_DIR,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("user"),
    )
    print(f"Copied static assets from {SRC_DIR} to {OUT_DIR}")

    # 2b. Create /login.html for GitHub Pages (handles fragment-preserving auth).
    (OUT_DIR / "login.html").write_text(
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '  <meta charset="UTF-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        '  <meta http-equiv="Content-Security-Policy" content="'
        "default-src 'none'; script-src 'self'; style-src 'self';"
        " connect-src 'self'; base-uri 'none'; object-src 'none';"
        " form-action 'none'; frame-ancestors 'none';\">\n"
        '  <title>blog — login</title>\n'
        '</head>\n<body data-base=".">\n'
        '  <script src="./js/auth.js"></script>\n'
        '</body>\n</html>\n',
        encoding="utf-8",
    )
    print("  Created login.html (GitHub Pages compat)")

    # 2c. Render architecture page (public).
    arch_md = BASE_DIR / "architecture.md"
    if arch_md.exists():
        arch_html = mistune.html(arch_md.read_text(encoding="utf-8"))
        arch_page = (
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            '  <meta charset="UTF-8">\n'
            '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            '  <meta http-equiv="Content-Security-Policy" content="'
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "base-uri 'none'; object-src 'none';"
            " form-action 'none'; frame-ancestors 'none';\">\n"
            '  <title>architecture</title>\n'
            '  <style>\n'
            '    body { max-width:720px; margin:0 auto; padding:2rem 1rem; '
            'font-family:system-ui,sans-serif; line-height:1.6; color:#1a1a1a; }\n'
            '    pre { background:#f5f5f5; padding:1rem; overflow-x:auto; }\n'
            '    code { font-size:0.9em; }\n'
            '    a { color:#2563eb; }\n'
            '  </style>\n</head>\n<body>\n'
            + arch_html +
            '\n</body>\n</html>'
        )
        (OUT_DIR / "arch.html").write_text(arch_page, encoding="utf-8")
        print("  Rendered architecture → arch.html")
    else:
        print("  Skipping arch.html (architecture.md not found)")

    # 3. Process posts.
    posts_out = OUT_DIR / "posts"
    posts_out.mkdir(exist_ok=True)

    post_deks = {}  # slug -> {dek, access, title}

    for post_file in posts:
        post = parse_post(post_file)
        slug = post["slug"]
        title = post["title"]
        html = post["html"]
        access = post["access"]

        # Generate DEK.
        dek = secrets.token_bytes(32)

        # Encrypt post.
        enc_data = encrypt_bytes(dek, html.encode("utf-8"))
        enc_path = posts_out / f"{slug}.enc"
        enc_path.write_bytes(enc_data)

        post_deks[slug] = {"dek": dek, "access": access, "title": title}
        print(f"  Post: {slug}  (access: {access})")

    # 4. Build user manifests and per-user encrypted index pages.
    users_out = OUT_DIR / "users"
    users_out.mkdir(exist_ok=True)

    # Set up Jinja2 for index page rendering.
    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(SRC_DIR)),
        autoescape=True,
    )
    index_template = jinja_env.get_template("user/index.html.j2")

    for user in users:
        uid = user["id"]
        name = user["name"]
        manifest = {"posts": {}}

        # Collect posts this user can access.
        user_posts = []

        for slug, info in post_deks.items():
            if uid in info["access"]:
                dek_b64 = base64url_encode(info["dek"])
                manifest["posts"][slug] = dek_b64
                user_posts.append({"slug": slug, "title": info["title"]})

        # Create user output directory.
        user_dir = users_out / uid
        user_dir.mkdir(exist_ok=True)

        # Write encrypted manifest (info.enc).
        manifest_json = json.dumps(manifest, separators=(",", ":"))
        enc_manifest = encrypt_bytes(user["key"], manifest_json.encode("utf-8"))
        (user_dir / "info.enc").write_bytes(enc_manifest)

        # Render and encrypt per-user index page.
        index_html = index_template.render(name=name, posts=user_posts)
        enc_index = encrypt_bytes(user["key"], index_html.encode("utf-8"))
        (user_dir / "index.enc").write_bytes(enc_index)

        post_count = len(manifest["posts"])
        print(f"  User {uid} ({name}): {post_count} post(s)")

    # 5. Inject SRI integrity hashes into all HTML files.
    print()
    for html_file in sorted(OUT_DIR.rglob("*.html")):
        inject_sri(html_file)
        print(f"  SRI: {html_file.relative_to(OUT_DIR)}")

    print()
    print(f"Done. Output: {OUT_DIR}")
    print(f"  Posts: {len(post_deks)}")
    print(f"  Users: {len(users)}")
    print()
    print("Deploy the contents of out/ to your static host.")


if __name__ == "__main__":
    main()
