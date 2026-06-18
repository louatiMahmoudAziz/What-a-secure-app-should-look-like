"""Job response schemas (spec 8). Phase 2 exposes job metadata; download links
and expiry semantics are completed in Phase 3."""

from datetime import datetime

from pydantic import BaseModel


class JobSummary(BaseModel):
    job_id: str
    job_type: str
    status: str
    payload_size_bytes: int | None = None
    output_size_bytes: int | None = None
    algorithm_version: int | None = None
    created_at: datetime
    expires_at: datetime | None = None
