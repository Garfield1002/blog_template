"""Console entry point for revoking a blog user."""

import sys
from pathlib import Path

# Support both package entry points (`uv run revoke-user`) and direct module use.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import lib


def main(uid: str) -> None:
    removed = lib.remove_user(uid)
    if removed is None:
        print(f"Error: no user with uid={uid} found in {lib.USERS_CSV}",
              file=sys.stderr)
        sys.exit(1)

    print(f"Revoked user '{removed.name}' (uid={uid})")
    print("Run `uv run publish` to rebuild the site without this user's manifest.")


def cli() -> None:
    if len(sys.argv) < 2:
        print("Usage: revoke-user <uid>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])


if __name__ == "__main__":
    cli()
