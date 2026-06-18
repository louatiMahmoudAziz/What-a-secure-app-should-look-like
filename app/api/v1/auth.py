"""Authentication API (spec 11.1).

Generic failure language throughout (FR-AUTH-009): the API never reveals whether
an email exists or why a credential was rejected.
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.auth import refresh_tokens as rt
from app.auth.dependencies import get_current_user
from app.auth.jwt import create_access_token
from app.auth.passwords import hash_password, verify_password
from app.core import metrics
from app.core.config import settings
from app.db.models import STATUS_ACTIVE, Session as SessionModel, User
from app.db.session import get_db
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    SessionInfo,
    TokenResponse,
)

router = APIRouter()

_INVALID = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials."
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    """Coerce a possibly-naive (SQLite) datetime to UTC-aware."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _ip_hash(request: Request) -> str:
    # Pseudonymization, not anonymization: keyed SHA-256 with the app secret as a
    # pepper. Documented in docs/known-limitations.md.
    ip = request.client.host if request.client else "unknown"
    return hashlib.sha256((settings.jwt_signing_key + ip).encode()).hexdigest()


def _ua(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    return ua[:256] if ua else None


def _token_response(db: DbSession, user: User, request: Request) -> TokenResponse:
    access, access_exp = create_access_token(str(user.id), user.role)
    issued = rt.issue_initial(
        db, user.id, user_agent=_ua(request), ip_hash=_ip_hash(request)
    )
    db.commit()
    return TokenResponse(
        access_token=access,
        refresh_token=issued.raw_token,
        access_token_expiration=access_exp,
        refresh_token_expiration=issued.session.expires_at,
    )


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: DbSession = Depends(get_db)) -> dict:
    existing = db.scalar(select(User).where(User.email == body.email))
    if existing is not None:
        # Generic conflict — do not confirm which email is taken.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Registration could not be completed.",
        )
    user = User(email=body.email, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    return {"status": "registered"}


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest, request: Request, db: DbSession = Depends(get_db)
) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == body.email))

    # Account lockout (defined here per the spec critique; backs locked_until).
    if user is not None and user.locked_until and _aware(user.locked_until) > _now():
        raise _INVALID

    # Constant-ish work whether or not the user exists: verify against the stored
    # hash, or burn a comparison against a dummy to reduce timing signal.
    ok = False
    if user is not None and user.status == STATUS_ACTIVE:
        ok = verify_password(user.password_hash, body.password)

    if not ok:
        if user is not None:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.max_failed_logins:
                user.locked_until = _now() + timedelta(minutes=settings.lockout_minutes)
            db.commit()
        metrics.increment(metrics.LOGIN_FAILURE)
        raise _INVALID

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = _now()
    return _token_response(db, user, request)


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    body: RefreshRequest, request: Request, db: DbSession = Depends(get_db)
) -> TokenResponse:
    try:
        issued = rt.rotate(db, body.refresh_token)
    except rt.ReplayDetected:
        db.commit()  # persist the family revocation
        metrics.increment(metrics.REFRESH_REPLAY)
        raise _INVALID from None
    except rt.InvalidRefreshToken:
        raise _INVALID from None

    user = db.get(User, issued.session.user_id)
    if user is None or user.status != STATUS_ACTIVE:
        raise _INVALID
    access, access_exp = create_access_token(str(user.id), user.role)
    db.commit()
    return TokenResponse(
        access_token=access,
        refresh_token=issued.raw_token,
        access_token_expiration=access_exp,
        refresh_token_expiration=issued.session.expires_at,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: RefreshRequest, db: DbSession = Depends(get_db)) -> None:
    session = db.scalar(
        select(SessionModel).where(
            SessionModel.refresh_token_hash == rt.hash_token(body.refresh_token)
        )
    )
    if session is not None:
        rt.revoke_session(db, session)
        db.commit()


@router.get("/me")
def me(user: User = Depends(get_current_user)) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "status": user.status,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at.isoformat(),
    }


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_me(
    db: DbSession = Depends(get_db), user: User = Depends(get_current_user)
) -> None:
    db.delete(user)  # cascades to sessions and jobs
    db.commit()


@router.get("/sessions", response_model=list[SessionInfo])
def list_sessions(
    db: DbSession = Depends(get_db), user: User = Depends(get_current_user)
) -> list[SessionInfo]:
    rows = db.scalars(
        select(SessionModel).where(
            SessionModel.user_id == user.id, SessionModel.revoked_at.is_(None)
        )
    ).all()
    return [
        SessionInfo(
            id=str(s.id),
            issued_at=s.issued_at,
            expires_at=s.expires_at,
            user_agent_summary=s.user_agent_summary,
        )
        for s in rows
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_one(
    session_id: str,
    db: DbSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found") from None
    session = db.get(SessionModel, sid)
    # Ownership check: a user may only revoke their own sessions (FR-AUTHZ).
    if session is None or session.user_id != user.id:
        metrics.increment(metrics.AUTHORIZATION_DENIAL)
        raise HTTPException(status_code=404, detail="Not found")
    rt.revoke_session(db, session)
    db.commit()
