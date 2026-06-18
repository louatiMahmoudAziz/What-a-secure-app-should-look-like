"""SQLAlchemy models (spec 12). UUIDs for all externally visible IDs
(FR-AUTHZ-006). Roles/statuses stored as strings for cross-dialect portability.

AuditEvent and SecurityIncident hash-chaining land in Phase 3; this module
covers the Phase 2 surface: User, Session, ProcessingJob.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

# Role / status / job constants (kept as plain strings, validated in code).
ROLE_USER = "user"
ROLE_ADMIN = "admin"

STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"

JOB_EMBED = "EMBED"
JOB_EXTRACT = "EXTRACT"
JOB_VERIFY = "VERIFY"

JOB_PENDING = "PENDING"
JOB_PROCESSING = "PROCESSING"
JOB_SUCCEEDED = "SUCCEEDED"
JOB_FAILED = "FAILED"
JOB_EXPIRED = "EXPIRED"
JOB_DELETED = "DELETED"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=ROLE_USER)
    status: Mapped[str] = mapped_column(String(16), default=STATUS_ACTIVE)
    mfa_enabled: Mapped[bool] = mapped_column(default=False)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(String(512), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )

    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    jobs: Mapped[list["ProcessingJob"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    session_family_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    replaced_by_session_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, default=None
    )
    user_agent_summary: Mapped[str | None] = mapped_column(String(256), default=None)
    source_ip_hash: Mapped[str | None] = mapped_column(String(64), default=None)

    user: Mapped["User"] = relationship(back_populates="sessions")


class ProcessingJob(Base):
    __tablename__ = "processing_jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    job_type: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default=JOB_PENDING)
    source_filename_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    input_size_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    output_size_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    payload_size_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    capacity_utilization: Mapped[int | None] = mapped_column(Integer, default=None)
    algorithm_version: Mapped[int | None] = mapped_column(Integer, default=None)
    artifact_storage_key: Mapped[str | None] = mapped_column(String(128), default=None)
    artifact_checksum: Mapped[str | None] = mapped_column(String(64), default=None)
    processing_time_ms: Mapped[int | None] = mapped_column(Integer, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    failure_category: Mapped[str | None] = mapped_column(String(32), default=None)

    user: Mapped["User"] = relationship(back_populates="jobs")
