"""FastAPI auth dependencies: resolve the current user from a Bearer token and
enforce role requirements.

Disabled accounts are rejected here (FR-AUTH: disabled-account rejection), so a
valid token for a since-disabled user grants nothing.
"""

import uuid

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session as DbSession

from app.auth.jwt import TokenError, decode_access_token
from app.core import metrics
from app.db.models import ROLE_ADMIN, STATUS_ACTIVE, User
from app.db.session import get_db

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    authorization: str | None = Header(default=None),
    db: DbSession = Depends(get_db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _UNAUTHORIZED
    token = authorization.split(" ", 1)[1].strip()
    try:
        claims = decode_access_token(token)
        user_id = uuid.UUID(claims["sub"])
    except (TokenError, KeyError, ValueError) as exc:
        raise _UNAUTHORIZED from exc

    user = db.get(User, user_id)
    if user is None or user.status != STATUS_ACTIVE:
        raise _UNAUTHORIZED
    return user


def require_admin_user(user: User = Depends(get_current_user)) -> User:
    if user.role != ROLE_ADMIN:
        metrics.increment(metrics.AUTHORIZATION_DENIAL)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required"
        )
    return user
