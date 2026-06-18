"""Object-level authorization tests (spec 20.3)."""

from app.core import metrics
from tests.conftest import auth_header, register_and_login


def _embed_job(client, tokens, png):
    resp = client.post(
        "/api/v1/jobs/embed",
        headers=auth_header(tokens),
        files={"image": ("in.png", png, "image/png")},
        data={"passphrase": "passphrase one", "payload": "top secret"},
    )
    assert resp.status_code == 200
    return resp.headers["X-Job-Id"]


def test_user_can_access_own_job(client, png_bytes):
    a = register_and_login(client, email="a@example.com")
    job_id = _embed_job(client, a, png_bytes())
    resp = client.get(f"/api/v1/jobs/{job_id}", headers=auth_header(a))
    assert resp.status_code == 200
    assert resp.json()["job_id"] == job_id


def test_user_cannot_read_another_users_job(client, png_bytes):
    a = register_and_login(client, email="a@example.com")
    b = register_and_login(client, email="b@example.com")
    job_id = _embed_job(client, a, png_bytes())
    # B gets a 404 — same as nonexistent, no existence oracle.
    resp = client.get(f"/api/v1/jobs/{job_id}", headers=auth_header(b))
    assert resp.status_code == 404


def test_user_cannot_delete_another_users_job(client, png_bytes):
    a = register_and_login(client, email="a@example.com")
    b = register_and_login(client, email="b@example.com")
    job_id = _embed_job(client, a, png_bytes())
    assert client.delete(
        f"/api/v1/jobs/{job_id}", headers=auth_header(b)
    ).status_code == 404
    # A's job is untouched.
    assert client.get(f"/api/v1/jobs/{job_id}", headers=auth_header(a)).status_code == 200


def test_owner_can_delete_then_job_gone(client, png_bytes):
    a = register_and_login(client, email="a@example.com")
    job_id = _embed_job(client, a, png_bytes())
    assert client.delete(f"/api/v1/jobs/{job_id}", headers=auth_header(a)).status_code == 204
    # Soft-deleted: no longer retrievable.
    assert client.get(f"/api/v1/jobs/{job_id}", headers=auth_header(a)).status_code == 404


def test_list_jobs_only_returns_own(client, png_bytes):
    a = register_and_login(client, email="a@example.com")
    b = register_and_login(client, email="b@example.com")
    _embed_job(client, a, png_bytes())
    _embed_job(client, a, png_bytes())
    _embed_job(client, b, png_bytes())
    a_jobs = client.get("/api/v1/jobs", headers=auth_header(a)).json()
    b_jobs = client.get("/api/v1/jobs", headers=auth_header(b)).json()
    assert len(a_jobs) == 2
    assert len(b_jobs) == 1


def test_regular_user_cannot_call_admin(client):
    a = register_and_login(client, email="a@example.com")
    resp = client.get("/api/v1/admin/users", headers=auth_header(a))
    assert resp.status_code == 403
    assert metrics.get(metrics.AUTHORIZATION_DENIAL) >= 1


def test_invalid_uuid_job_id_is_404(client):
    a = register_and_login(client, email="a@example.com")
    assert client.get(
        "/api/v1/jobs/not-a-uuid", headers=auth_header(a)
    ).status_code == 404


def test_embed_extract_round_trip_over_api(client, png_bytes):
    a = register_and_login(client, email="a@example.com")
    png = png_bytes()
    embed = client.post(
        "/api/v1/jobs/embed",
        headers=auth_header(a),
        files={"image": ("in.png", png, "image/png")},
        data={"passphrase": "round trip pass", "payload": "hello api"},
    )
    assert embed.status_code == 200
    stego = embed.content
    extract = client.post(
        "/api/v1/jobs/extract",
        headers=auth_header(a),
        files={"image": ("stego.png", stego, "image/png")},
        data={"passphrase": "round trip pass"},
    )
    assert extract.status_code == 200
    assert extract.content == b"hello api"


def test_extract_wrong_passphrase_is_generic_422(client, png_bytes):
    a = register_and_login(client, email="a@example.com")
    png = png_bytes()
    stego = client.post(
        "/api/v1/jobs/embed",
        headers=auth_header(a),
        files={"image": ("in.png", png, "image/png")},
        data={"passphrase": "right pass", "payload": "secret"},
    ).content
    resp = client.post(
        "/api/v1/jobs/extract",
        headers=auth_header(a),
        files={"image": ("stego.png", stego, "image/png")},
        data={"passphrase": "wrong pass"},
    )
    assert resp.status_code == 422
    assert "could not be authenticated" in resp.json()["detail"]


def test_fake_png_rejected_at_api(client):
    a = register_and_login(client, email="a@example.com")
    resp = client.post(
        "/api/v1/jobs/embed",
        headers=auth_header(a),
        files={"image": ("fake.png", b"\xff\xd8not a png", "image/png")},
        data={"passphrase": "pw", "payload": "x"},
    )
    assert resp.status_code == 400
    assert metrics.get(metrics.INVALID_UPLOAD) >= 1
