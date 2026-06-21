#!/usr/bin/env python3
"""
Build the static encrypted blog bundle.

Flow:
1. Clean and recreate the output directory.
2. Copy static assets and render Jinja2 templates.
3. Parse, image-embed, and encrypt every Markdown post.
4. Build per-user encrypted manifests and index pages.
5. Inject SRI integrity hashes into all HTML files.
"""

import json
import shutil
import sys
from pathlib import Path

import jinja2

import lib
import posts as posts_mod
import static as static_mod


def _build_user_artifacts(post_deks: dict) -> None:
    """Build per-user encrypted manifests and index pages.

    For each user in users.csv, collect the posts they can access, encrypt a
    manifest (info.enc) and a personalised index page (index.enc).
    """
    users = lib.read_users()
    if not users:
        print("Warning: no users configured — manifests will not be generated.",
              file=sys.stderr)
        return

    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(lib.SRC_DIR)),
        autoescape=True,
    )
    index_template = jinja_env.get_template("user/index.html.j2")

    users_out = lib.OUT_DIR / "users"
    users_out.mkdir(exist_ok=True)

    for user in users:
        manifest: dict = {"posts": {}}
        user_posts: list[dict] = []

        for slug, info in post_deks.items():
            if user.id in info["access"]:
                dek_b64 = lib.base64url_encode(info["dek"])
                manifest["posts"][slug] = dek_b64
                user_posts.append({"slug": slug, "title": info["title"]})

        # Create per-user output directory.
        user_dir = users_out / user.id
        user_dir.mkdir(exist_ok=True)

        # Encrypt manifest → info.enc.
        manifest_json = json.dumps(manifest, separators=(",", ":"))
        enc_manifest = lib.encrypt_bytes(
            user.key, manifest_json.encode("utf-8"))
        (user_dir / "info.enc").write_bytes(enc_manifest)

        # Render and encrypt per-user index → index.enc.
        index_html = index_template.render(
            name=user.name, posts=user_posts)
        enc_index = lib.encrypt_bytes(
            user.key, index_html.encode("utf-8"))
        (user_dir / "index.enc").write_bytes(enc_index)

        post_count = len(manifest["posts"])
        print(f"  User {user.name} ({user.id}): {post_count} post(s)")


def main() -> None:
    # --- Validate inputs ---
    if not lib.SRC_DIR.is_dir():
        print(f"Error: src/ directory not found at {lib.SRC_DIR}",
              file=sys.stderr)
        sys.exit(1)
    if not lib.POSTS_DIR.is_dir():
        print(f"Error: posts/ directory not found at {lib.POSTS_DIR}",
              file=sys.stderr)
        sys.exit(1)

    # --- 1. Clean output directory ---
    if lib.OUT_DIR.exists():
        shutil.rmtree(lib.OUT_DIR)
    lib.OUT_DIR.mkdir(parents=True)

    # --- 2. Static assets & templates ---
    static_mod.copy_static_assets()
    static_mod.render_templates()

    # --- 3. Process posts ---
    posts_out = lib.OUT_DIR / "posts"
    posts_out.mkdir(exist_ok=True)
    post_deks, skipped = posts_mod.process_all_posts(lib.POSTS_DIR, posts_out)

    # --- 4. Per-user manifests & index pages ---
    _build_user_artifacts(post_deks)

    # --- 5. SRI integrity ---
    print()
    static_mod.inject_sri_all()

    # --- Summary ---
    print()
    print(f"Done. Output: {lib.OUT_DIR}")
    print(f"  Posts: {len(post_deks)}")
    if skipped:
        print(f"  Skipped: {skipped}")
    print(f"  Users: {len(lib.read_users())}")
    print()
    print("Deploy the contents of out/ to your static host.")


if __name__ == "__main__":
    main()
