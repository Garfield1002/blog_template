#!/usr/bin/env python3
"""
Add a new user to the blog.

Generates a random 256-bit AES key, a random 16-character hex user ID,
appends to security/users.csv, and prints the one-time link.
"""

import sys
from pathlib import Path

import lib


def main(name: str) -> None:
    user = lib.add_user(name)

    print(f"User '{user.name}' added with uid={user.id}")
    print(f"One-time link:\n{user.login_url}")
    print()
    print("Send this link to the user. They must open it exactly once.")
    print("After opening, the credentials are stored in cookies.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: add-user.py <name>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
