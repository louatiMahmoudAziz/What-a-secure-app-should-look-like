"""Jobs API (spec 11.3) with object-level authorization on every route
(FR-AUTHZ-005). Embed/extract/verify call the Phase 1 engine.

Phase 2 scope: synchronous processing, job metadata persisted, artifacts
returned inline. Short-lived download links + Blob storage are Phase 3/5.
"""

import hashlib
import time
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from PIL import Image
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.auth.dependencies import get_current_user
from app.core import metrics
from app.core.config import settings
from app.db.models import (
    JOB_EMBED,
    JOB_EXTRACT,
    JOB_SUCCEEDED,
    JOB_VERIFY,
    ProcessingJob,
    User,
)
from app.db.session import get_db
from app.files.validators import FileValidationError, validate_png
from app.schemas.jobs import JobSummary
from app.services.embed_service import embed_payload
from app.services.extract_service import ExtractionError, extract_payload
from app.steganography.capacity import max_payload_bytes
from app.steganography.lsb_png import CapacityError
from app.steganography.verifier import verify as verify_image

router = APIRouter()

_BAD_UPLOAD = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="The uploaded file could not be processed.",
)


def _load_png(upload: UploadFile) -> tuple[Image.Image, bytes]:
    raw = upload.file.read()
    if len(raw) > settings.max_upload_bytes:
        metrics.increment(metrics.INVALID_UPLOAD)
        raise _BAD_UPLOAD
    try:
        image = validate_png(
            raw,
            max_upload_bytes=settings.max_upload_bytes,
            max_dimension=settings.max_image_dimension,
            max_pixels=settings.max_decoded_pixels,
        )
    except FileValidationError as exc:
        metrics.increment(metrics.INVALID_UPLOAD)
        raise _BAD_UPLOAD from exc
    return image, raw


@router.post("/embed")
def embed(
    image: UploadFile = File(...),
    passphrase: str = Form(...),
    payload: str = Form(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    img, raw = _load_png(image)
    payload_bytes = payload.encode("utf-8")
    if len(payload_bytes) > settings.max_payload_bytes:
        raise _BAD_UPLOAD
    start = time.perf_counter()
    try:
        stego = embed_payload(img, payload_bytes, passphrase)
    except CapacityError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds image capacity.",
        ) from exc
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    job = ProcessingJob(
        user_id=user.id,
        job_type=JOB_EMBED,
        status=JOB_SUCCEEDED,
        source_filename_hash=hashlib.sha256(
            (image.filename or "").encode()
        ).hexdigest(),
        input_size_bytes=len(raw),
        output_size_bytes=len(stego),
        payload_size_bytes=len(payload_bytes),
        capacity_utilization=int(
            100 * len(payload_bytes) / max(max_payload_bytes(img), 1)
        ),
        algorithm_version=1,
        artifact_checksum=hashlib.sha256(stego).hexdigest(),
        processing_time_ms=elapsed_ms,
    )
    db.add(job)
    db.commit()
    metrics.increment(metrics.EMBED_JOB)
    return Response(
        content=stego,
        media_type="image/png",
        headers={
            "X-Job-Id": str(job.id),
            "X-Processing-Time-Ms": str(elapsed_ms),
        },
    )


@router.post("/extract")
def extract(
    image: UploadFile = File(...),
    passphrase: str = Form(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    img, _ = _load_png(image)
    try:
        payload = extract_payload(img, passphrase)
    except ExtractionError as exc:
        metrics.increment(metrics.CRYPTO_AUTH_FAILURE)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Payload extraction failed: the embedded content could not be "
                "authenticated."
            ),
        ) from exc
    db.add(
        ProcessingJob(
            user_id=user.id,
            job_type=JOB_EXTRACT,
            status=JOB_SUCCEEDED,
            payload_size_bytes=len(payload),
            algorithm_version=1,
        )
    )
    db.commit()
    metrics.increment(metrics.EXTRACT_JOB)
    return Response(content=payload, media_type="application/octet-stream")


@router.post("/verify")
def verify_endpoint(
    image: UploadFile = File(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    img, _ = _load_png(image)
    result = verify_image(img)
    db.add(
        ProcessingJob(user_id=user.id, job_type=JOB_VERIFY, status=JOB_SUCCEEDED)
    )
    db.commit()
    metrics.increment(metrics.VERIFY_JOB)
    return {
        "compatible_payload_detected": result.compatible_payload_detected,
        "envelope_structure_valid": result.envelope_structure_valid,
        "format_version": result.format_version,
        "algorithm_version": result.algorithm_version,
    }


@router.get("", response_model=list[JobSummary])
def list_jobs(
    db: DbSession = Depends(get_db), user: User = Depends(get_current_user)
) -> list[JobSummary]:
    rows = db.scalars(
        select(ProcessingJob).where(
            ProcessingJob.user_id == user.id, ProcessingJob.deleted_at.is_(None)
        )
    ).all()
    return [_summary(j) for j in rows]


@router.get("/{job_id}", response_model=JobSummary)
def get_job(
    job_id: str,
    db: DbSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> JobSummary:
    job = _owned_job_or_404(db, job_id, user)
    return _summary(job)


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_job(
    job_id: str,
    db: DbSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    from datetime import datetime, timezone

    job = _owned_job_or_404(db, job_id, user)
    job.deleted_at = datetime.now(timezone.utc)
    db.commit()


def _owned_job_or_404(db: DbSession, job_id: str, user: User) -> ProcessingJob:
    """Load a job ONLY if it belongs to the caller. A non-owner gets the same
    404 as a nonexistent job — no existence oracle (FR-AUTHZ-001)."""
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found") from None
    job = db.get(ProcessingJob, jid)
    if job is None or job.user_id != user.id or job.deleted_at is not None:
        metrics.increment(metrics.AUTHORIZATION_DENIAL)
        raise HTTPException(status_code=404, detail="Not found")
    return job


def _summary(job: ProcessingJob) -> JobSummary:
    return JobSummary(
        job_id=str(job.id),
        job_type=job.job_type,
        status=job.status,
        payload_size_bytes=job.payload_size_bytes,
        output_size_bytes=job.output_size_bytes,
        algorithm_version=job.algorithm_version,
        created_at=job.created_at,
        expires_at=job.expires_at,
    )
