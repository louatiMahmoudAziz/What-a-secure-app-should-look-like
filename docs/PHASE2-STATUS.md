# Phase 2 — Authentication, Authorization, API Security (implemented)

## What works

| Area | Files | Notes |
| ---- | ----- | ----- |
| Data model | `app/db/models.py`, `app/db/session.py` | User, Session, ProcessingJob; UUID PKs; runs on SQLite (tests) and Postgres |
| Passwords | `app/auth/passwords.py` | Argon2id via argon2-cffi |
| Access tokens | `app/auth/jwt.py` | HS256, 15-min, minimal claims (sub/role/iat/exp/jti) |
| Refresh tokens | `app/auth/refresh_tokens.py` | opaque, hashed at rest, rotation, **replay → family revocation** |
| AuthN deps | `app/auth/dependencies.py` | Bearer resolution, disabled-account rejection |
| AuthZ | `app/auth/permissions.py` + inline ownership checks | object-level checks on every job route |
| Auth API | `app/api/v1/auth.py` | register, login (generic errors + lockout), refresh, logout, sessions |
| Jobs API | `app/api/v1/jobs.py` | embed/extract/verify (wired to Phase 1 engine), list/get/delete with ownership |
| User API | `app/api/v1/users.py` | GET/DELETE /me |
| Admin API | `app/api/v1/admin.py` | metadata-only, role-gated |
| Metrics | `app/core/metrics.py` | login_failure, authorization_denial, refresh_replay, etc. |

## Spec critique fixes applied in code

- **Account lockout policy defined** (`login`): `locked_until` is now actually
  set after `max_failed_logins` (default 10) for `lockout_minutes` (default 15).
- **IP hashing is pseudonymization, not anonymization** (`_ip_hash`): keyed
  SHA-256 with the app secret as pepper; flagged in `docs/known-limitations.md`.
- **DELETE /me cascade decided**: user + sessions + jobs removed; audit events
  (Phase 3) will be retained out of band.
- **Mass-assignment defense**: all request schemas use `extra="forbid"`, so a
  smuggled `role` field on registration is rejected (tested).
- **No existence oracle**: cross-user job access and unknown emails both return
  the same generic response as the "not found"/"invalid" case.

## Security properties under test (spec 20.2 / 20.3)

- register/login, duplicate-registration safe failure, password mismatch
- generic login errors for both wrong password and unknown email
- expired access token rejected, tampered token rejected
- refresh rotation; **replay detection burns the whole family**; logout revokes
- disabled account cannot use an otherwise-valid token
- user A cannot read/delete user B's job (404, no oracle)
- list jobs returns only the caller's jobs
- regular user cannot call admin endpoints (403, metric incremented)
- full embed→extract round trip over the HTTP API
- wrong passphrase → generic 422; fake PNG → 400

## How to verify

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -v          # Phase 1 + Phase 2, ~70 tests
```

The suite runs entirely on in-memory SQLite — no Postgres or Redis needed.
To run the real stack: `docker compose up --build` then open `/docs`.

## Deferred to later phases (intentionally)

- **Rate limiting** (`core/rate_limiting.py`) is still a stub — Redis-backed
  limiter + tests land with Phase 3 hardening. Counters exist; enforcement does not.
- **Alembic migrations**: tables are created via `init_db()` in dev/test;
  `alembic init` + real migrations are a Phase 2/3 follow-up before Postgres prod.
- **Audit events + hash chain** (replay currently increments a metric only) —
  Phase 3 adds the persisted, tamper-evident record.
- **Security headers / CORS** middleware — Phase 3.
