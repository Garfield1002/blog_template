#!/usr/bin/env python3
"""
Add a new user to the blog.

Generates a random 256-bit AES key, a random 16-character hex user ID,
appends to security/users.csv, and prints the one-time link.
"""

import csv
import os
import secrets
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CSV_PATH = BASE_DIR / "security" / "users.csv"


def base64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url (RFC 4648 §5)."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def main(name: str) -> None:
    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Generate a random 16-character hex user ID (64 bits of entropy).
    uid = secrets.token_hex(8)

    # Generate a 256-bit AES key.
    key_bytes = secrets.token_bytes(32)
    key_b64 = base64url_encode(key_bytes)

    # Build the one-time login link.
    login_url = f"https://example.com/login#key={key_b64}&uid={uid}"

    # Append to CSV (4 columns: name, uid, key_b64, login_url).
    write_header = not CSV_PATH.exists() or CSV_PATH.stat().st_size == 0
    with open(CSV_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["# name", "uid", "key_b64", "login_url"])
        writer.writerow([name, uid, key_b64, login_url])

    print(f"User '{name}' added with uid={uid}")
    print(f"One-time link:\n{login_url}")
    print()
    print("Send this link to the user. They must open it exactly once.")
    print("After opening, the credentials are stored in cookies.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: add-user.py <name>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
