"""Primitives for user auth: password hashing, session tokens and the password policy.

Kept apart from the HTTP layer so the store, the CLI and the API all share one definition of how
a password is hashed and how a session token is minted. The token the client holds is random; the
database stores only its SHA-256 hash, so a database read never yields a usable token.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

import bcrypt

MIN_PASSWORD_LEN = 8
SESSION_TTL = timedelta(days=30)

# Built-in default admin credentials, used only to seed a fresh install. Surfaced in the CLI and
# README so a first-run operator can open the UI, with a nudge to change it.
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "Argus123"  # noqa: S105 — documented default


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_session_token() -> tuple[str, str]:
    """Return a fresh `(token, token_hash)`. The caller stores the hash and returns the token."""
    token = secrets.token_urlsafe(32)  # 256 bits of entropy
    return token, token_hash(token)


def validate_password(plain: str) -> None:
    """Raise `ValueError` when the password is too short to accept."""
    if len(plain) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")


def session_expiry(now: datetime) -> datetime:
    return now + SESSION_TTL
