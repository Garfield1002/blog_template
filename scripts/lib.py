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
#  User CSV management
# ===================================================================


def read_users() -> list[User]:
    """Read *security/users.csv* and return a list of ``User`` instances."""
    if not USERS_CSV.exists():
        print(f"Warning: {USERS_CSV} not found — no users configured.",
              file=sys.stderr)
        return []

    users: list[User] = []
    with open(USERS_CSV, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            try:
                name = row[0]
                uid = row[1]
                key_b64 = row[2]
                login_url = row[3] if len(row) > 3 else ""
                key_bytes = base64url_decode(key_b64)
                if len(key_bytes) != 32:
                    print(
                        f"Error: user {uid} key is {len(key_bytes)} bytes, "
                        f"expected 32.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                users.append(User(name, uid, key_bytes, login_url))
            except (IndexError, ValueError) as e:
                print(
                    f"Warning: malformed row in users.csv: {row} ({e})",
                    file=sys.stderr,
                )
                continue
    return users


def write_users(users: list[User]) -> None:
    """Write the full user list back to *security/users.csv*."""
    USERS_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["# name", "uid", "key_b64", "login_url"])
        for u in users:
            writer.writerow([u.name, u.id, u.key_b64, u.login_url])


def add_user(name: str) -> User:
    """Generate a new user, append to CSV, and return the ``User``."""
    uid = secrets.token_hex(8)          # 16-char hex, 64 bits entropy
    key_bytes = secrets.token_bytes(32)  # 256-bit AES key
    login_url = f"https://example.com/login#key={base64url_encode(key_bytes)}&uid={uid}"

    user = User(name, uid, key_bytes, login_url)

    users = read_users()
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
