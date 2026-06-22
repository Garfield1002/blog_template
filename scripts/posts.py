"""
Post processing — Markdown parsing, image embedding, and AES encryption.

Used by ``publish.py`` during the build.
"""

import base64
import re
import secrets
import sys
from pathlib import Path

import mistune
import yaml

from lib import POSTS_DIR, base64url_encode, encrypt_bytes, read_users, resolve_access

# ---------------------------------------------------------------------------
# Markdown renderer (HTML escaping enabled for security)
# ---------------------------------------------------------------------------
MARKDOWN = mistune.create_markdown(escape=True)

# ---------------------------------------------------------------------------
# Image embedding
# ---------------------------------------------------------------------------

_IMG_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
}

_IMG_TAG_RE = re.compile(r"<img\s[^>]*/?>", re.IGNORECASE)
_SRC_ATTR_RE = re.compile(r'src="([^"]+)"', re.IGNORECASE)


def embed_images(html: str, post_dir: Path) -> tuple[str, list[tuple[str, float]]]:
    """Find ``<img>`` tags with local ``src`` and embed them as base64 data
    URIs.

    Returns ``(html, images)`` where *images* is a list of
    ``(filename, size_kb)`` tuples for every inlined image.

    Only resolves paths relative to *post_dir*.  External URLs and already-
    embedded ``data:`` URIs are left untouched.  Path-traversal attempts are
    detected and the tag is left unchanged with a warning.
    """
    images: list[tuple[str, float]] = []

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
                f"  Warning: image src '{src}' escapes posts directory, "
                "skipping.",
                file=sys.stderr,
            )
            return tag

        if not img_path.is_file():
            print(f"  Warning: image not found: {img_path}", file=sys.stderr)
            return tag

        ext = img_path.suffix.lower()
        mime = _IMG_MIME.get(ext)
        if mime is None:
            print(
                f"  Warning: unsupported image type '{ext}' for "
                f"{img_path}, skipping.",
                file=sys.stderr,
            )
            return tag

        img_bytes = img_path.read_bytes()
        size_kb = len(img_bytes) / 1024
        images.append((img_path.name, size_kb))
        b64 = base64.b64encode(img_bytes).decode("ascii")
        data_uri = f"data:{mime};base64,{b64}"
        return tag.replace(f'src="{src}"', f'src="{data_uri}"')

    return _IMG_TAG_RE.sub(_replace, html), images


# ---------------------------------------------------------------------------
# Post parsing
# ---------------------------------------------------------------------------


def parse_post(filepath: Path) -> dict | None:
    """Parse a Markdown file with YAML frontmatter.

    Returns a dict with keys: ``slug``, ``title``, ``access``, ``html``.

    Returns ``None`` when the frontmatter has ``draft: true`` — the post is
    skipped entirely during the build.
    """
    raw = filepath.read_text(encoding="utf-8")
    if not raw.startswith("---"):
        raise ValueError(f"{filepath}: missing frontmatter (must start with ---)")

    parts = raw.split("---", 2)
    if len(parts) < 3:
        raise ValueError(f"{filepath}: invalid frontmatter")

    meta = yaml.safe_load(parts[1]) or {}

    # Draft posts are skipped.
    if meta.get("draft"):
        return None

    body = parts[2].strip()

    slug = secrets.token_hex(8)  # 16 random hex chars

    access = meta.get("access", [])
    if not isinstance(access, list):
        access = [access]
    # Coerce to strings (handles legacy int UIDs, new hex UIDs, and names).
    access = [str(uid) for uid in access]

    title = meta.get("title", slug)

    html = MARKDOWN(body)
    html, images = embed_images(html, filepath.parent)

    return {
        "slug": slug,
        "title": title,
        "access": access,
        "html": html,
        "images": images,
    }


# ---------------------------------------------------------------------------
# Batch processing (called from publish.py)
# ---------------------------------------------------------------------------


def process_all_posts(
    posts_dir: Path | None = None,
    posts_out: Path | None = None,
) -> tuple[dict, int]:
    """Process every ``.md`` file in *posts_dir* and write ``.enc`` files to
    *posts_out*.

    Returns a ``(post_deks, skipped)`` tuple where *post_deks* is a
    ``{slug: {dek, access, title}}`` dict and *skipped* is the number of
    draft posts that were ignored.
    """
    if posts_dir is None:
        posts_dir = POSTS_DIR
    if posts_out is None:
        # We need OUT_DIR from lib, but let's accept it explicitly.
        raise ValueError("posts_out is required")

    post_files = sorted(posts_dir.glob("*.md"))
    if not post_files:
        print("Warning: no .md posts found in posts/", file=sys.stderr)

    # Build uid → name lookup for display.
    uid_to_name: dict[str, str] = {
        u.id: u.name for u in read_users()
    }

    post_deks: dict = {}
    skipped = 0

    for post_file in post_files:
        post = parse_post(post_file)
        if post is None:
            print(f"  Draft: {post_file.name}  (skipped)")
            skipped += 1
            continue

        slug = post["slug"]
        while slug in post_deks:
            # Extremely unlikely, but duplicate slugs would overwrite the same
            # out/posts/<slug>.enc file. Regenerate until unique in this build.
            print(
                f"  Warning: slug collision for {slug}; regenerating.",
                file=sys.stderr,
            )
            slug = secrets.token_hex(8)
            post["slug"] = slug

        title = post["title"]
        html = post["html"]
        images = post["images"]
        access = resolve_access(post["access"])

        if not access:
            print(
                f"  Warning: {post_file.name} has an empty access list "
                f"after resolution — no users will see this post",
                file=sys.stderr,
            )

        # Generate a random 256-bit Data Encryption Key for this post.
        dek = secrets.token_bytes(32)

        # Encrypt post HTML with the DEK.
        enc_data = encrypt_bytes(dek, html.encode("utf-8"))
        enc_path = posts_out / f"{slug}.enc"
        enc_path.write_bytes(enc_data)

        post_deks[slug] = {"dek": dek, "access": access, "title": title}

        # Hierarchical log.
        access_names = [uid_to_name.get(uid, uid) for uid in access]
        print(f"  Post: {post_file.name} ({slug})")
        print(f"    Access: {', '.join(access_names)}")
        for img_name, size_kb in images:
            print(f"    Image: {img_name} ({size_kb:.1f} KB)")

    return post_deks, skipped
