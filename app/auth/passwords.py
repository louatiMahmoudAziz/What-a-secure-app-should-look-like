"""Argon2id password hashing (FR-AUTH-003).

Argon2id is the current best-practice memory-hard hash for user passwords (it
won the Password Hashing Competition). We use argon2-cffi's sensible defaults.
Password material is never logged, returned, or stored in plaintext (FR-AUTH-004).
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Return an Argon2id hash string (includes salt + parameters)."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True iff the password matches. Never raises on mismatch."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True if the stored hash uses outdated parameters and should be upgraded."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return False
