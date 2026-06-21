#!/usr/bin/env python3
"""
Revoke a user's access to the blog.

Removes the user from security/users.csv.  The next publish will regenerate
all DEKs and rebuild all manifests without this user — their manifest and
index files will not appear in the output directory.
"""

import csv
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CSV_PATH = BASE_DIR / "security" / "users.csv"


def main(uid: str) -> None:
    if not CSV_PATH.exists():
        print(f"Error: {CSV_PATH} not found — no users to revoke.", file=sys.stderr)
        sys.exit(1)

    rows = []
    found = False
    with open(CSV_PATH, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                rows.append(row)
                continue
            try:
                if row[1] == uid:
                    found = True
                    print(f"Revoking user '{row[0]}' (uid={uid})")
                    continue  # drop this row
            except IndexError:
                pass
            rows.append(row)

    if not found:
        print(f"Error: no user with uid={uid} found in {CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    with open(CSV_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    print("User removed from CSV.")
    print("Run publish.py to rebuild the site without this user's manifest.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: revoke-user.py <uid>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
