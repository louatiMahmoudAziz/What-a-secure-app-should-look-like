"""Application entry point.

Wires routers, request-ID middleware, and (in dev/test) table creation.
"""

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi import Depends

from app.api.v1 import admin, auth, jobs
from app.auth.dependencies import require_admin_user
from app.core import metrics
from app.core.config import settings
from app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In local/test, create tables directly. Production uses Alembic migrations.
    if settings.app_env in ("local", "test"):
        init_db()
    yield


app = FastAPI(
    title="Secure Steganography Platform",
    description=(
        "Steganography conceals the presence of a message. It does not replace "
        "encryption. Payloads are encrypted and authenticated before embedding."
    ),
    version="0.2.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Generate a request ID when absent; echo it on every response (spec 13.1)."""
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    return response


@app.get("/health/live")
async def health_live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
async def health_ready() -> dict[str, str]:
    # TODO Phase 2/5: check PostgreSQL, Redis, tmp storage, crypto init.
    return {"status": "ready"}


@app.get("/metrics", tags=["observability"])
def get_metrics(_=Depends(require_admin_user)) -> dict:
    """In-process counters for local dev/debug. Superseded by Application Insights in production."""
    return metrics.snapshot()


app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(jobs.router, prefix="/api/v1/jobs", tags=["jobs"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
