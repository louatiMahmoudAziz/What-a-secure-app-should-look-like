"""Role + ownership authorization helpers (FR-AUTHZ-001..007).

These are deliberately tiny and pure so they can be unit-tested to high coverage
(target 95%+, spec 21.6) and reused at every object-level operation. A UUID being
hard to guess is NOT a substitute for these checks (FR-AUTHZ-007).
"""

import uuid

from app.core import metrics
from app.db.models import ROLE_ADMIN, User


class AuthorizationError(Exception):
    """Raised when an actor is not permitted to act on a resource."""


def is_admin(user: User) -> bool:
    return user.role == ROLE_ADMIN


def require_owner(actor: User, resource_owner_id: uuid.UUID) -> None:
    """Allow only the resource owner. Admins do NOT get implicit data access
    (FR-AUTHZ-004: admins see metadata via separate endpoints, not user content).
    """
    if actor.id != resource_owner_id:
        metrics.increment(metrics.AUTHORIZATION_DENIAL)
        raise AuthorizationError("not the resource owner")


def require_admin(actor: User) -> None:
    if not is_admin(actor):
        metrics.increment(metrics.AUTHORIZATION_DENIAL)
        raise AuthorizationError("admin role required")
