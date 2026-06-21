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

# Markdown renderer with HTML escaping enabled (security: prevents raw HTML
# from Markdown posts being injected into the page via innerHTML).
MARKDOWN = mistune.create_markdown(escape=True)

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
POSTS_DIR = BASE_DIR / "posts"
USERS_CSV = BASE_DIR / "security" / "users.csv"
OUT_DIR = BASE_DIR / "out"

# Content-Security-Policy used by every page.  Single source of truth — update
# here and all pages (both static .html and Jinja2-rendered) stay in sync.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src data:; "
    "base-uri 'none'; object-src 'none'; "
    "form-action 'none'; frame-ancestors 'none';"
)


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
    """Add integrity attributes to <script> and <link rel=stylesheet> tags.

    Resolves each src/href relative to the HTML file's directory, computes the
    SHA-256 hash of the referenced file, and injects an integrity attribute.
    Tags that already have an integrity attribute are left unchanged.
    """
    html = html_path.read_text(encoding="utf-8")
    html_dir = html_path.parent

    def replace_src_tag(match):
        tag = match.group(0)
        if "integrity=" in tag:
            return tag
        src = match.group(1)
        path = (html_dir / src).resolve()
        if path.exists():
            integrity = sri_hash(path)
            return tag[:-1] + f' integrity="{integrity}">'
        return tag

    # Inject SRI on <script src="..."> tags.
    html = re.sub(
        r'<script\s[^>]*src="([^"]+)"[^>]*>',
        replace_src_tag,
        html,
    )
    # Inject SRI on <link rel="stylesheet" href="..."> tags.
    html = re.sub(
        r'<link\s[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>',
        replace_src_tag,
        html,
    )
    html_path.write_text(html, encoding="utf-8")


# Map file extensions to MIME types for image embedding.
_IMG_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
}

_IMG_TAG_RE = re.compile(r"<img\s[^>]*/?>", re.IGNORECASE)
_SRC_ATTR_RE = re.compile(r'src="([^"]+)"', re.IGNORECASE)


def embed_images(html: str, post_dir: Path) -> str:
    """Find <img> tags with local src, embed the images as base64 data URIs.

    Only resolves paths relative to *post_dir*.  External URLs and already-
    embedded data: URIs are left untouched.  Path-traversal attempts are
    detected and the tag is left unchanged with a warning.
    """

    def _replace(match: re.Match) -> str:
        tag = match.group(0)
        src_m = _SRC_ATTR_RE.search(tag)
        if not src_m:
            return tag
        src = src_m.group(1)

        # Leave external URLs and already-embedded data URIs alone.
        if src.startswith(("http://", "https://", "data:")):
            return tag

        # Resolve relative to the post's directory.
        img_path = (post_dir / src).resolve()
        post_dir_resolved = post_dir.resolve()

        # Security: prevent path traversal out of the posts directory.
        try:
            img_path.relative_to(post_dir_resolved)
        except ValueError:
            print(
                f"  Warning: image src '{src}' escapes posts directory, skipping.",
                file=sys.stderr,
            )
            return tag

        if not img_path.is_file():
            print(f"  Warning: image not found: {img_path}", file=sys.stderr)
            return tag

        # Detect MIME type from extension.
        ext = img_path.suffix.lower()
        mime = _IMG_MIME.get(ext)
        if mime is None:
            print(
                f"  Warning: unsupported image type '{ext}' for {img_path}, skipping.",
                file=sys.stderr,
            )
            return tag

        img_bytes = img_path.read_bytes()
        b64 = base64.b64encode(img_bytes).decode("ascii")
        data_uri = f"data:{mime};base64,{b64}"

        return tag.replace(f'src="{src}"', f'src="{data_uri}"')

    return _IMG_TAG_RE.sub(_replace, html)


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

    html = MARKDOWN(body)
    html = embed_images(html, filepath.parent)

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
        ignore=shutil.ignore_patterns("user", "*.j2"),
    )
    print(f"Copied static assets from {SRC_DIR} to {OUT_DIR}")

    # 2b. Set up Jinja2 (used for login, arch, and per-user index pages).
    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(SRC_DIR)),
        autoescape=True,
    )

    # 2c. Create /login.html for GitHub Pages (handles fragment-preserving auth).
    login_html = jinja_env.get_template("login.html.j2").render(csp=CSP)
    (OUT_DIR / "login.html").write_text(login_html, encoding="utf-8")
    print("  Created login.html (GitHub Pages compat)")

    # 2d. Render architecture page (public).
    arch_md = BASE_DIR / "architecture.md"
    if arch_md.exists():
        arch_content = MARKDOWN(arch_md.read_text(encoding="utf-8"))
        arch_html = jinja_env.get_template("arch.html.j2").render(csp=CSP, content=arch_content)
        (OUT_DIR / "arch.html").write_text(arch_html, encoding="utf-8")
        print("  Rendered architecture → arch.html")
    else:
        print("  Skipping arch.html (architecture.md not found)")

    # 2e. Render page templates (Jinja2 with CSP injected).
    _PAGES = [
        "index.html.j2",
        "post/index.html.j2",
        "logout/index.html.j2",
        "unauthorized/index.html.j2",
    ]
    for template_name in _PAGES:
        out_path = OUT_DIR / template_name.replace(".j2", "")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        html = jinja_env.get_template(template_name).render(csp=CSP)
        out_path.write_text(html, encoding="utf-8")
    print("  Rendered page templates (index, post, logout, unauthorized)")

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
