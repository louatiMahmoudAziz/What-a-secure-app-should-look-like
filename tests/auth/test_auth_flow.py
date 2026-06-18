"""Auth flow integration tests (spec 20.2)."""

from app.auth.jwt import create_access_token
from app.core import metrics
from tests.conftest import VALID_PASSWORD, auth_header, register_and_login


def test_register_and_login_returns_tokens(client):
    tokens = register_and_login(client)
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    assert tokens["token_type"] == "bearer"


def test_duplicate_registration_fails_safely(client):
    body = {
        "email": "dup@example.com",
        "password": VALID_PASSWORD,
        "password_confirmation": VALID_PASSWORD,
    }
    assert client.post("/api/v1/auth/register", json=body).status_code == 201
    # Second attempt: a clean 409, not a 500 or a stack trace.
    assert client.post("/api/v1/auth/register", json=body).status_code == 409


def test_register_rejects_extra_fields(client):
    # Mass-assignment defense: a smuggled role field must be rejected.
    body = {
        "email": "evil@example.com",
        "password": VALID_PASSWORD,
        "password_confirmation": VALID_PASSWORD,
        "role": "admin",
    }
    assert client.post("/api/v1/auth/register", json=body).status_code == 422


def test_password_mismatch_rejected(client):
    body = {
        "email": "mismatch@example.com",
        "password": VALID_PASSWORD,
        "password_confirmation": "something else entirely",
    }
    assert client.post("/api/v1/auth/register", json=body).status_code == 422


def test_login_wrong_password_is_generic(client):
    register_and_login(client, email="a@example.com")
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "a@example.com", "password": "wrong password here"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials."


def test_login_unknown_email_is_same_generic(client):
    # Must not reveal whether the email exists (FR-AUTH-009).
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@example.com", "password": "whatever password"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials."


def test_me_requires_auth(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_me_returns_no_secrets(client):
    tokens = register_and_login(client)
    body = client.get("/api/v1/auth/me", headers=auth_header(tokens)).json()
    assert "password_hash" not in body
    assert "mfa_secret_encrypted" not in body


def test_expired_access_token_rejected(client):
    tokens = register_and_login(client)
    me = client.get("/api/v1/auth/me", headers=auth_header(tokens)).json()
    expired, _ = create_access_token(me["id"], "user", lifetime_minutes=-1)
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401


def test_refresh_rotates_token(client):
    tokens = register_and_login(client)
    r1 = tokens["refresh_token"]
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 200
    r2 = resp.json()["refresh_token"]
    assert r2 != r1  # rotated


def test_refresh_replay_burns_family(client):
    tokens = register_and_login(client)
    r1 = tokens["refresh_token"]
    r2 = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": r1}
    ).json()["refresh_token"]

    # Replaying the already-rotated r1 is a replay: rejected...
    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": r1})
    assert replay.status_code == 401
    assert metrics.get(metrics.REFRESH_REPLAY) == 1

    # ...and it revokes the whole family, so r2 is now dead too.
    assert client.post(
        "/api/v1/auth/refresh", json={"refresh_token": r2}
    ).status_code == 401


def test_logout_revokes_refresh_token(client):
    tokens = register_and_login(client)
    r1 = tokens["refresh_token"]
    assert client.post("/api/v1/auth/logout", json={"refresh_token": r1}).status_code == 204
    # A logged-out token can no longer refresh.
    assert client.post(
        "/api/v1/auth/refresh", json={"refresh_token": r1}
    ).status_code == 401


def test_disabled_account_cannot_use_valid_token(client, db_session):
    from sqlalchemy import select

    from app.db.models import STATUS_DISABLED, User

    tokens = register_and_login(client, email="disable-me@example.com")
    user = db_session.scalar(
        select(User).where(User.email == "disable-me@example.com")
    )
    user.status = STATUS_DISABLED
    db_session.commit()
    # Token is still cryptographically valid, but the account is disabled.
    assert client.get("/api/v1/auth/me", headers=auth_header(tokens)).status_code == 401
