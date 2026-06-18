"""JWT access tokens (FR-AUTH-007/008).

Short-lived (15 min) HS256 tokens with minimal claims: sub, role, iat, exp, jti.
A stolen access token is only useful until exp; longer-lived sessions are handled
by rotating refresh tokens instead.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt

from app.core.config import settings

ALGORITHM = "HS256"


class TokenError(Exception):
    """Raised for any invalid, malformed, or expired access token."""


def create_access_token(
    subject: str, role: str, *, lifetime_minutes: int | None = None
) -> tuple[str, datetime]:
    """Return (token, expiration). `subject` is the user UUID as a string."""
    minutes = lifetime_minutes or settings.access_token_lifetime_minutes
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=minutes)
    claims = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = pyjwt.encode(claims, settings.jwt_signing_key, algorithm=ALGORITHM)
    return token, exp


def decode_access_token(token: str) -> dict:
    """Decode and validate a token. Raises TokenError on any problem."""
    try:
        return pyjwt.decode(
            token,
            settings.jwt_signing_key,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub", "role"]},
        )
    except pyjwt.PyJWTError as exc:
        raise TokenError("invalid token") from exc
