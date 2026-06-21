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
import base64
import csv
import re
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Error: cryptography package required. Run: pip install cryptography",
          file=sys.stderr)
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent.parent
CSV_PATH = BASE_DIR / "security" / "users.csv"
OUT_DIR = BASE_DIR / "out"
README_PATH = BASE_DIR / "README.md"

EXAMPLE_HEADER = "## Example Logins"


def base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def decrypt_bytes(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM decrypt.  Format: 12-byte nonce || ciphertext+tag."""
    if len(data) < 28:
        raise ValueError(f"enc file too short: {len(data)} bytes")
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def parse_index_links(html: str) -> list[tuple[str, str]]:
    """
    Parse the per-user index page HTML and extract (slug, title) pairs.
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
    if not CSV_PATH.exists():
        print(
            f"Error: {CSV_PATH} not found — run add-user.py first.", file=sys.stderr)
        sys.exit(1)

    users = []  # (name, uid, key_b64, key_bytes)
    with open(CSV_PATH, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            try:
                name = row[0]
                uid = row[1]
                key_b64 = row[2]
                key_bytes = base64url_decode(key_b64)
                if len(key_bytes) != 32:
                    print(f"Warning: user {uid} key is {len(key_bytes)} bytes, skipping.",
                          file=sys.stderr)
                    continue
                users.append((name, uid, key_b64, key_bytes))
            except (IndexError, ValueError) as e:
                print(
                    f"Warning: malformed row in users.csv: {row} ({e})", file=sys.stderr)
                continue

    if not users:
        print("Error: no users found in users.csv.", file=sys.stderr)
        sys.exit(1)

    # --- Decrypt each user's index to discover (slug, title) pairs ---
    if not OUT_DIR.is_dir():
        print(
            f"Error: {OUT_DIR} not found — run publish.py first.", file=sys.stderr)
        sys.exit(1)

    user_posts = {}  # name -> [(slug, title)]
    all_slugs = {}   # slug -> title (deduplicated across users)

    for name, uid, _key_b64, key_bytes in users:
        index_path = OUT_DIR / "users" / uid / "index.enc"
        if not index_path.exists():
            print(f"Warning: {index_path} not found for {name} — "
                  "run publish.py first.", file=sys.stderr)
            user_posts[name] = []
            continue

        try:
            enc_data = index_path.read_bytes()
            plaintext = decrypt_bytes(key_bytes, enc_data)
            html = plaintext.decode("utf-8")
            posts = parse_index_links(html)
            user_posts[name] = posts
            for slug, title in posts:
                if slug not in all_slugs:
                    all_slugs[slug] = title
        except Exception as e:
            print(f"Warning: failed to decrypt index for {name} ({uid}): {e}",
                  file=sys.stderr)
            user_posts[name] = []

    # --- Build example section ---
    lines = [
        "> **Demo keys only.** The credentials below are published intentionally so visitors can explore the blog.",
        "> In a real deployment, these onboarding URLs would be sent privately to each user.",
        ""
    ]

    for name, uid, key_b64, _key_bytes in users:
        login_url = f"{base_url}/login#key={key_b64}&uid={uid}"
        posts = user_posts.get(name, [])

        if posts:
            post_links = ", ".join(
                f"[{title}]({base_url}/post/?id={slug})"
                for slug, title in posts
            )
            lines.append(f"[{name}]({login_url}) can access: {post_links}")
        else:
            lines.append(f"[{name}]({login_url}) has no posts assigned.")

    lines.append("")
    lines.append(f"[logout]({base_url}/logout/)")

    # --- Update README.md ---
    readme_text = README_PATH.read_text(encoding="utf-8")

    header_idx = readme_text.find(EXAMPLE_HEADER)
    if header_idx == -1:
        print(
            f"Error: '{EXAMPLE_HEADER}' section not found in README.md.", file=sys.stderr)
        sys.exit(1)

    end_of_header = readme_text.index("\n", header_idx) + 1
    prefix = readme_text[:end_of_header]
    new_section = prefix + "\n" + "\n".join(lines) + "\n"

    README_PATH.write_text(new_section, encoding="utf-8")
    print(f"Updated {README_PATH} with {len(users)} user(s).")
    for name, posts in user_posts.items():
        print(f"  {name}: {len(posts)} post(s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Update README example logins from build output"
    )
    parser.add_argument(
        "--base-url",
        default="https://garfield1002.github.io/blog_template",
        help="Base URL of the deployed site (default: https://garfield1002.github.io/blog_template)",
    )
    args = parser.parse_args()
    main(args.base_url)
