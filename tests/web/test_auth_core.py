"""Password hashing, session-token generation and the password policy."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cyllex_argus.web import auth_core


def test_hash_and_verify_password():
    hashed = auth_core.hash_password("s3cret-long")
    assert hashed != "s3cret-long"
    assert auth_core.verify_password("s3cret-long", hashed)
    assert not auth_core.verify_password("wrong", hashed)


def test_new_session_token_is_high_entropy_and_its_hash_matches():
    token1, hash1 = auth_core.new_session_token()
    token2, _ = auth_core.new_session_token()
    assert token1 != token2 and len(token1) >= 32
    assert auth_core.token_hash(token1) == hash1
    assert hash1 != token1  # the stored form is the hash, never the token itself


def test_validate_password_rejects_too_short():
    with pytest.raises(ValueError):
        auth_core.validate_password("short")  # fewer than MIN_PASSWORD_LEN
    auth_core.validate_password("longenough")  # does not raise


def test_session_expiry_is_in_the_future():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert auth_core.session_expiry(now) > now
