#!/usr/bin/env python3
"""
Update the "Example Logins" section of README.md with actual user keys and
post links.

Reads user keys from security/users.csv, decrypts each user's per-user
index page (out/users/<uid>/index.enc) to discover post slugs and titles,
then regenerates the example section.

Requires a completed build (python scripts/publish.py).

Usage:
  python scripts/make-example.py [--base-url https://example.com]
"""

import argparse
import re
import sys
from pathlib import Path

import lib

EXAMPLE_HEADER = "## Example Logins"


def parse_index_links(html: str) -> list[tuple[str, str]]:
    """Parse the per-user index page HTML and extract (slug, title) pairs.

    The template renders: <a href="./post/?id=SLUG">TITLE</a>
    """
    pattern = re.compile(
        r'<a\s[^>]*href="\.\/post\/\?id=([^"]+)"[^>]*>([^<]+)</a>'
    )
    return [(m.group(1), m.group(2).strip()) for m in pattern.finditer(html)]


def main(base_url: str) -> None:
    # --- Safety check ---
    print()
    print("⚠️  WARNING: This script will publish real user keys to README.md.")
    print("    Only run this for demo or example deployments.")
    print("    Never run against a production users.csv file.")
    print()
    answer = input("    Type \"I know what I'm doing\" to continue: ")
    if answer != "I know what I'm doing":
        print("Aborted.")
        sys.exit(0)
    print()

    # --- Read users ---
    users = lib.read_users()
    if not users:
        print("Error: no users found in users.csv.", file=sys.stderr)
        sys.exit(1)

    # --- Decrypt each user's index to discover (slug, title) pairs ---
    if not lib.OUT_DIR.is_dir():
        print(f"Error: {lib.OUT_DIR} not found — run publish.py first.",
              file=sys.stderr)
        sys.exit(1)

    user_posts: dict[str, list[tuple[str, str]]] = {}
    all_slugs: dict[str, str] = {}

    for user in users:
        index_path = lib.OUT_DIR / "users" / user.id / "index.enc"
        if not index_path.exists():
            print(f"Warning: {index_path} not found for {user.name} — "
                  "run publish.py first.", file=sys.stderr)
            user_posts[user.name] = []
            continue

        try:
            enc_data = index_path.read_bytes()
            plaintext = lib.decrypt_bytes(user.key, enc_data)
            html = plaintext.decode("utf-8")
            posts = parse_index_links(html)
            user_posts[user.name] = posts
            for slug, title in posts:
                if slug not in all_slugs:
                    all_slugs[slug] = title
        except Exception as e:
            print(f"Warning: failed to decrypt index for "
                  f"{user.name} ({user.id}): {e}",
                  file=sys.stderr)
            user_posts[user.name] = []

    # --- Build example section ---
    lines = [
        "> **Demo keys only.** The credentials below are published intentionally so visitors can explore the blog.",
        "> In a real deployment, these onboarding URLs would be sent privately to each user.",
        "",
    ]

    for user in users:
        login_url = f"{base_url}/login#key={user.key_b64}&uid={user.id}"
        posts = user_posts.get(user.name, [])

        if posts:
            post_links = ", ".join(
                f"[{title}]({base_url}/post/?id={slug})"
                for slug, title in posts
            )
            lines.append(f"[{user.name}]({login_url}) can access: {post_links}")
        else:
            lines.append(f"[{user.name}]({login_url}) has no posts assigned.")

    lines.append("")
    lines.append(f"[logout]({base_url}/logout/)")

    # --- Update README.md ---
    readme_path = lib.BASE_DIR / "README.md"
    readme_text = readme_path.read_text(encoding="utf-8")

    header_idx = readme_text.find(EXAMPLE_HEADER)
    if header_idx == -1:
        print(f"Error: '{EXAMPLE_HEADER}' section not found in README.md.",
              file=sys.stderr)
        sys.exit(1)

    end_of_header = readme_text.index("\n", header_idx) + 1
    prefix = readme_text[:end_of_header]
    new_section = prefix + "\n" + "\n".join(lines) + "\n"

    readme_path.write_text(new_section, encoding="utf-8")
    print(f"Updated {readme_path} with {len(users)} user(s).")
    for name, posts in user_posts.items():
        print(f"  {name}: {len(posts)} post(s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Update README example logins from build output"
    )
    parser.add_argument(
        "--base-url",
        default="https://garfield1002.github.io/blog_template",
        help="Base URL of the deployed site "
             "(default: https://garfield1002.github.io/blog_template)",
    )
    args = parser.parse_args()
    main(args.base_url)
