"""
Shared helpers for blog scripts — crypto, user CSV management, paths, and
constants.

All scripts in this directory can import from here by adding::

    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import lib
"""

import base64
import csv
import os
import re
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Paths (relative to the repo root, which is one level above scripts/)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
POSTS_DIR = BASE_DIR / "posts"
USERS_CSV = BASE_DIR / "security" / "users.csv"
OUT_DIR = BASE_DIR / "out"

UID_RE = re.compile(r"^[a-f0-9]{16}$")
KEY_B64_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

# ---------------------------------------------------------------------------
# Content-Security-Policy — single source of truth
# ---------------------------------------------------------------------------
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src data:; "
    "base-uri 'none'; object-src 'none'; "
    "form-action 'none'; frame-ancestors 'none';"
)

# ===================================================================
#  Crypto helpers
# ===================================================================


def base64url_encode(data: bytes) -> str:
    """Encode *data* as unpadded base64url (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Decode an unpadded base64url string back to bytes."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt — returns *nonce* || *ciphertext+tag*."""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_bytes(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM decrypt — expects 12-byte nonce || ciphertext+tag."""
    if len(data) < 28:
        raise ValueError(f"enc file too short: {len(data)} bytes")
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ===================================================================
#  User
# ===================================================================


class User:
    """A blog reader — hex *uid*, 256-bit AES *key*, and a one-time *login_url*.

    ``key_b64`` is a derived property (base64url of *key*) so it can never
    drift from the canonical key bytes.
    """

    def __init__(
        self,
        name: str,
        uid: str,
        key: bytes,
        login_url: str = "",
    ) -> None:
        self.name = name
        self.id = uid
        self.key = key
        self.login_url = login_url

    @property
    def key_b64(self) -> str:
        return base64url_encode(self.key)

    def __repr__(self) -> str:
        return f"User({self.name!r}, id={self.id})"


# ===================================================================
#  Access-list resolution
# ===================================================================


def resolve_access(access: list[str], users: list[User] | None = None) -> list[str]:
    """Resolve an access list into a deduplicated list of hex UIDs.

    * ``"all"`` expands to every known user.
    * Names are matched **case-insensitively** against ``User.name``.
    * Strings that are already 16-char hex UIDs pass through unchanged.
    * Unmatched entries produce a warning and are dropped.
    """
    if users is None:
        users = read_users()

    if "all" in access:
        return sorted(u.id for u in users)

    # Build a case-insensitive name → id lookup.
    name_to_id: dict[str, str] = {}
    for u in users:
        lower = u.name.lower()
        if lower in name_to_id:
            print(
                f"Warning: duplicate user name '{u.name}' — "
                f"using first match ({name_to_id[lower]})",
                file=sys.stderr,
            )
        else:
            name_to_id[lower] = u.id

    # Build the set of known UIDs for validation.
    known_ids = {u.id for u in users}

    resolved: dict[str, None] = {}  # ordered set (dict preserves insertion)
    for entry in access:
        lower = entry.lower()
        if lower in name_to_id:
            resolved[name_to_id[lower]] = None
        elif entry in known_ids:
            resolved[entry] = None
        else:
            print(
                f"Warning: '{entry}' in access list doesn't match any "
                f"user name or UID — skipping",
                file=sys.stderr,
            )

    return list(resolved.keys())


# ===================================================================
#  Validation helpers
# ===================================================================


def is_valid_uid(uid: str) -> bool:
    """Return ``True`` when *uid* is a 16-character lowercase hex ID."""
    return bool(UID_RE.fullmatch(uid))


def validate_uid(uid: str, context: str = "uid") -> None:
    """Raise ``ValueError`` unless *uid* is safe for user IDs and paths."""
    if not is_valid_uid(uid):
        raise ValueError(f"{context} must be 16 lowercase hex characters: {uid!r}")


def validate_key_b64(key_b64: str, context: str = "key_b64") -> None:
    """Raise ``ValueError`` unless *key_b64* is an unpadded 256-bit key."""
    if not KEY_B64_RE.fullmatch(key_b64):
        raise ValueError(
            f"{context} must be a 43-character unpadded base64url string"
        )


# ===================================================================
#  User CSV management
# ===================================================================


def read_users() -> list[User]:
    """Read *security/users.csv* and return a list of ``User`` instances."""
    if not USERS_CSV.exists():
        print(f"Warning: {USERS_CSV} not found — no users configured.",
              file=sys.stderr)
        return []

    users: list[User] = []
    seen_uids: set[str] = set()
    seen_names: set[str] = set()

    with open(USERS_CSV, newline="") as f:
        reader = csv.reader(f)
        for row_num, row in enumerate(reader, start=1):
            if not row or row[0].startswith("#"):
                continue
            try:
                name = row[0].strip()
                uid = row[1].strip()
                key_b64 = row[2].strip()
                login_url = row[3].strip() if len(row) > 3 else ""

                if not name:
                    raise ValueError("name is empty")
                validate_uid(uid, "uid")
                validate_key_b64(key_b64)

                if uid in seen_uids:
                    raise ValueError(f"duplicate uid {uid}")
                seen_uids.add(uid)

                name_lower = name.lower()
                if name_lower in seen_names:
                    print(
                        f"Warning: duplicate user name {name!r} in users.csv; "
                        "access lists by name will use the first match.",
                        file=sys.stderr,
                    )
                seen_names.add(name_lower)

                key_bytes = base64url_decode(key_b64)
                if len(key_bytes) != 32:
                    raise ValueError(
                        f"key is {len(key_bytes)} bytes, expected 32"
                    )
                users.append(User(name, uid, key_bytes, login_url))
            except (IndexError, ValueError) as e:
                print(
                    f"Error: malformed row {row_num} in users.csv: {row} ({e})",
                    file=sys.stderr,
                )
                sys.exit(1)
    return users


def write_users(users: list[User]) -> None:
    """Write the full user list back to *security/users.csv*.

    The file contains bearer secrets, so create it with ``0600`` permissions
    and keep the containing directory private to the local user.
    """
    USERS_CSV.parent.mkdir(parents=True, exist_ok=True)
    USERS_CSV.parent.chmod(0o700)

    fd = os.open(USERS_CSV, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["# name", "uid", "key_b64", "login_url"])
        for u in users:
            validate_uid(u.id, "uid")
            writer.writerow([u.name, u.id, u.key_b64, u.login_url])
    USERS_CSV.chmod(0o600)


def add_user(name: str) -> User:
    """Generate a new user, append to CSV, and return the ``User``."""
    users = read_users()
    existing_uids = {u.id for u in users}

    # Collisions are extremely unlikely, but duplicate IDs would overwrite the
    # same out/users/<uid>/ directory, so check anyway.
    while True:
        uid = secrets.token_hex(8)          # 16-char hex, 64 bits entropy
        if uid not in existing_uids:
            break

    key_bytes = secrets.token_bytes(32)  # 256-bit AES key
    login_url = f"https://example.com/login#key={base64url_encode(key_bytes)}&uid={uid}"

    user = User(name.strip(), uid, key_bytes, login_url)
    if not user.name:
        raise ValueError("user name must not be empty")

    users.append(user)
    write_users(users)

    return user


def remove_user(uid: str) -> User | None:
    """Remove the user with *uid* from the CSV.  Returns the removed
    ``User``, or ``None`` if no matching user was found."""
    users = read_users()
    for i, u in enumerate(users):
        if u.id == uid:
            removed = users.pop(i)
            write_users(users)
            return removed
    return None
