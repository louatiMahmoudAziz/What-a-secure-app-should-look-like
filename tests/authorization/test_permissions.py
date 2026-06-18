"""Unit tests for the pure authorization helpers (FR-AUTHZ-001..007)."""

import uuid

import pytest

from app.auth.permissions import (
    AuthorizationError,
    is_admin,
    require_admin,
    require_owner,
)
from app.core import metrics
from app.db.models import ROLE_ADMIN, ROLE_USER, User


def _user(role=ROLE_USER):
    return User(id=uuid.uuid4(), email="x@y.z", password_hash="h", role=role)


def test_owner_allowed():
    u = _user()
    require_owner(u, u.id)  # no raise


def test_non_owner_denied_and_counted():
    metrics.reset()
    u = _user()
    with pytest.raises(AuthorizationError):
        require_owner(u, uuid.uuid4())
    assert metrics.get(metrics.AUTHORIZATION_DENIAL) == 1


def test_admin_passes_require_admin():
    require_admin(_user(role=ROLE_ADMIN))  # no raise


def test_non_admin_denied():
    metrics.reset()
    with pytest.raises(AuthorizationError):
        require_admin(_user())
    assert metrics.get(metrics.AUTHORIZATION_DENIAL) == 1


def test_is_admin():
    assert is_admin(_user(role=ROLE_ADMIN))
    assert not is_admin(_user())
