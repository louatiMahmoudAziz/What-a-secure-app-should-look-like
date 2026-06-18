"""Argon2id password hashing tests (FR-AUTH-003/004)."""

from app.auth.passwords import hash_password, verify_password


def test_hash_is_not_plaintext():
    h = hash_password("super secret password")
    assert "super secret password" not in h
    assert h.startswith("$argon2id$")


def test_correct_password_verifies():
    h = hash_password("correct horse battery staple")
    assert verify_password(h, "correct horse battery staple")


def test_wrong_password_fails_without_raising():
    h = hash_password("correct horse battery staple")
    assert verify_password(h, "wrong password") is False


def test_same_password_different_hashes():
    # Argon2 salts each hash, so two hashes of the same password differ.
    assert hash_password("repeat me") != hash_password("repeat me")


def test_garbage_hash_returns_false():
    assert verify_password("not-a-valid-hash", "whatever") is False
