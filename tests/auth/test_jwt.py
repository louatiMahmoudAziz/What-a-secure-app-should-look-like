"""JWT access-token tests (FR-AUTH-007/008)."""

import uuid

import pytest

from app.auth.jwt import TokenError, create_access_token, decode_access_token


def test_round_trip_claims():
    sub = str(uuid.uuid4())
    token, _ = create_access_token(sub, "user")
    claims = decode_access_token(token)
    assert claims["sub"] == sub
    assert claims["role"] == "user"
    assert "jti" in claims and "exp" in claims and "iat" in claims


def test_expired_token_rejected():
    token, _ = create_access_token(str(uuid.uuid4()), "user", lifetime_minutes=-1)
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_tampered_token_rejected():
    token, _ = create_access_token(str(uuid.uuid4()), "user")
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    with pytest.raises(TokenError):
        decode_access_token(tampered)


def test_garbage_token_rejected():
    with pytest.raises(TokenError):
        decode_access_token("not.a.jwt")


def test_claims_are_minimal():
    token, _ = create_access_token(str(uuid.uuid4()), "admin")
    claims = decode_access_token(token)
    assert set(claims.keys()) == {"sub", "role", "iat", "exp", "jti"}
