#!/usr/bin/env python3
"""
Revoke a user's access to the blog.

Removes the user from security/users.csv.  The next publish will regenerate
all DEKs and rebuild all manifests without this user — their manifest and
index files will not appear in the output directory.
"""

import sys
from pathlib import Path

import lib


def main(uid: str) -> None:
    removed = lib.remove_user(uid)
    if removed is None:
        print(f"Error: no user with uid={uid} found in {lib.USERS_CSV}",
              file=sys.stderr)
        sys.exit(1)

    print(f"Revoked user '{removed.name}' (uid={uid})")
    print("Run publish.py to rebuild the site without this user's manifest.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: revoke-user.py <uid>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
