"""Console entry point for adding a blog user."""

import sys
from pathlib import Path

# Support both package entry points (`uv run add-user`) and direct script use.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import lib


def main(name: str) -> None:
    user = lib.add_user(name)

    print(f"User '{user.name}' added with uid={user.id}")
    print(f"One-time link:\n{user.login_url}")
    print()
    print("Send this link to the user. They must open it exactly once.")
    print("After opening, the credentials are stored in localStorage.")


def cli() -> None:
    if len(sys.argv) < 2:
        print("Usage: add-user <name>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])


if __name__ == "__main__":
    cli()
