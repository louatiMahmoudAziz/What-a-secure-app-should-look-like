"""In-process metric counters (spec 22.1).

A minimal counter registry sufficient for tests and local runs. In Azure these
map to Application Insights custom metrics; the names here match spec 22.1.
"""

from collections import defaultdict
from threading import Lock

_counters: dict[str, int] = defaultdict(int)
_lock = Lock()

# Known metric names (spec 22.1) — not exhaustive, extended as features land.
LOGIN_FAILURE = "login_failure_count"
AUTHORIZATION_DENIAL = "authorization_denial_count"
RATE_LIMIT_TRIGGER = "rate_limit_trigger_count"
REFRESH_REPLAY = "refresh_token_replay_count"
INVALID_UPLOAD = "invalid_upload_count"
CRYPTO_AUTH_FAILURE = "crypto_authentication_failure_count"
EMBED_JOB = "embed_job_count"
EXTRACT_JOB = "extract_job_count"
VERIFY_JOB = "verify_job_count"


def increment(name: str, amount: int = 1) -> None:
    with _lock:
        _counters[name] += amount


def get(name: str) -> int:
    with _lock:
        return _counters[name]


def snapshot() -> dict[str, int]:
    with _lock:
        return dict(_counters)


def reset() -> None:
    """Test helper."""
    with _lock:
        _counters.clear()
