"""Rotating refresh tokens with replay detection (FR-AUTH-010/011).

Design:
  * The raw refresh token is opaque high-entropy randomness. Only its SHA-256
    hash is stored, so a database leak does not expose usable tokens.
  * Every refresh ROTATES the token: the presented session is revoked and a new
    session is issued in the same family.
  * Presenting an already-revoked token = replay. We then revoke the ENTIRE
    family (all sessions descended from the original login) and signal the
    caller, who increments a metric and returns a generic 401.

This bounds the damage from a stolen refresh token: the moment either the
legitimate user or the attacker uses the rotated token, the other's copy becomes
a replay that nukes the family.
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.core.config import settings
from app.db.models import Session as SessionModel

TOKEN_BYTES = 48


class ReplayDetected(Exception):
    """Raised when a revoked refresh token is presented again."""


class InvalidRefreshToken(Exception):
    """Raised when a refresh token is unknown or expired."""


@dataclass(frozen=True)
class IssuedRefresh:
    raw_token: str
    session: SessionModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    """Coerce a possibly-naive datetime to UTC-aware.

    SQLite has no timezone storage: DateTime(timezone=True) columns round-trip
    as naive. We store everything in UTC, so attaching UTC restores the truth.
    PostgreSQL returns aware datetimes and passes through unchanged.
    """
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def hash_token(raw: str) -> str:
    """SHA-256 hex digest of a raw token (suitable for equality lookup)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _new_raw() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def issue_initial(
    db: DbSession,
    user_id: uuid.UUID,
    *,
    user_agent: str | None = None,
    ip_hash: str | None = None,
) -> IssuedRefresh:
    """Create the first session of a new family (called at login)."""
    raw = _new_raw()
    session = SessionModel(
        user_id=user_id,
        refresh_token_hash=hash_token(raw),
        session_family_id=uuid.uuid4(),
        issued_at=_now(),
        expires_at=_now() + timedelta(days=settings.refresh_token_lifetime_days),
        user_agent_summary=user_agent,
        source_ip_hash=ip_hash,
    )
    db.add(session)
    db.flush()
    return IssuedRefresh(raw_token=raw, session=session)


def rotate(db: DbSession, raw_token: str) -> IssuedRefresh:
    """Validate + rotate a refresh token.

    Raises InvalidRefreshToken if unknown/expired, or ReplayDetected (after
    revoking the whole family) if the token was already used/revoked.
    """
    token_hash = hash_token(raw_token)
    session = db.scalar(
        select(SessionModel).where(SessionModel.refresh_token_hash == token_hash)
    )
    if session is None:
        raise InvalidRefreshToken("unknown token")

    if session.revoked_at is not None:
        # Replay: this token was already rotated or logged out. Burn the family.
        _revoke_family(db, session.session_family_id)
        raise ReplayDetected("refresh token replay")

    if _aware(session.expires_at) <= _now():
        raise InvalidRefreshToken("expired token")

    # Rotate: revoke current, issue successor in the same family.
    raw = _new_raw()
    successor = SessionModel(
        user_id=session.user_id,
        refresh_token_hash=hash_token(raw),
        session_family_id=session.session_family_id,
        issued_at=_now(),
        expires_at=_now() + timedelta(days=settings.refresh_token_lifetime_days),
        user_agent_summary=session.user_agent_summary,
        source_ip_hash=session.source_ip_hash,
    )
    db.add(successor)
    db.flush()
    session.revoked_at = _now()
    session.replaced_by_session_id = successor.id
    db.flush()
    return IssuedRefresh(raw_token=raw, session=successor)


def _revoke_family(db: DbSession, family_id: uuid.UUID) -> None:
    sessions = db.scalars(
        select(SessionModel).where(SessionModel.session_family_id == family_id)
    ).all()
    for s in sessions:
        if s.revoked_at is None:
            s.revoked_at = _now()
    db.flush()


def revoke_session(db: DbSession, session: SessionModel) -> None:
    """Revoke a single session (logout / revoke-one)."""
    if session.revoked_at is None:
        session.revoked_at = _now()
        db.flush()


def revoke_all_for_user(db: DbSession, user_id: uuid.UUID) -> int:
    """Revoke every active session for a user. Returns count revoked."""
    sessions = db.scalars(
        select(SessionModel).where(
            SessionModel.user_id == user_id, SessionModel.revoked_at.is_(None)
        )
    ).all()
    for s in sessions:
        s.revoked_at = _now()
    db.flush()
    return len(sessions)
