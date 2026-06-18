"""Administrator API (spec 11.4).

Admins review METADATA and operational signals only — never plaintext payloads,
keys, tokens, or MFA secrets (FR-AUTHZ-004, role boundary in spec 5.3). Every
route is gated by require_admin_user.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.auth.dependencies import require_admin_user
from app.db.models import (
    STATUS_ACTIVE,
    STATUS_DISABLED,
    ProcessingJob,
    User,
)
from app.db.session import get_db

router = APIRouter()


@router.get("/users")
def list_users(
    db: DbSession = Depends(get_db), _: User = Depends(require_admin_user)
) -> list[dict]:
    rows = db.scalars(select(User)).all()
    return [
        {"id": str(u.id), "email": u.email, "role": u.role, "status": u.status}
        for u in rows
    ]


@router.patch("/users/{user_id}/status")
def set_status(
    user_id: str,
    new_status: str,
    db: DbSession = Depends(get_db),
    _: User = Depends(require_admin_user),
) -> dict:
    if new_status not in (STATUS_ACTIVE, STATUS_DISABLED):
        raise HTTPException(status_code=400, detail="Invalid status")
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found") from None
    target = db.get(User, uid)
    if target is None:
        raise HTTPException(status_code=404, detail="Not found")
    target.status = new_status
    db.commit()
    return {"id": str(target.id), "status": target.status}


@router.get("/jobs")
def list_all_jobs(
    db: DbSession = Depends(get_db), _: User = Depends(require_admin_user)
) -> list[dict]:
    rows = db.scalars(select(ProcessingJob)).all()
    # Metadata only — no artifacts, no payloads.
    return [
        {
            "job_id": str(j.id),
            "user_id": str(j.user_id),
            "job_type": j.job_type,
            "status": j.status,
            "created_at": j.created_at.isoformat(),
        }
        for j in rows
    ]


