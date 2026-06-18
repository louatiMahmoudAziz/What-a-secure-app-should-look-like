"""Shared pytest fixtures.

Each test gets an isolated in-memory SQLite database and a FastAPI TestClient
whose `get_db` dependency is overridden to use it.
"""

import io
import os

import numpy as np
import pytest
from PIL import Image

# Force test config BEFORE importing the app/settings.
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite://"  # in-memory
os.environ["JWT_SIGNING_KEY"] = "test-signing-key"

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.session import Base, get_db  # noqa: E402
from app.db import models  # noqa: E402,F401  (register tables)


@pytest.fixture()
def db_session():
    # StaticPool keeps a single in-memory DB shared across connections.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def client(db_session):
    from fastapi.testclient import TestClient

    from app.core import metrics
    from app.main import app

    metrics.reset()

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    # Disable the lifespan table-creation (we manage tables in the fixture).
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def png_bytes():
    def _make(w=128, h=128, mode="RGB", seed=0):
        rng = np.random.default_rng(seed)
        c = 4 if mode == "RGBA" else 3
        arr = rng.integers(0, 256, (h, w, c), dtype=np.uint8)
        buf = io.BytesIO()
        Image.fromarray(arr, mode=mode).save(buf, format="PNG")
        return buf.getvalue()

    return _make


# --- registration/login helpers -------------------------------------------------

VALID_PASSWORD = "correct horse battery staple"


def register_and_login(client, email="user@example.com", password=VALID_PASSWORD):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "password_confirmation": password,
        },
    )
    resp = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    return resp.json()


def auth_header(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}
