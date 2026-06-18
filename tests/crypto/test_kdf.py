"""Tests for app.crypto.kdf — FR-CRYPTO-004/005.

Your job: implement app/crypto/kdf.py so these pass.

Required interface:
    generate_salt() -> bytes            # 16 random bytes, crypto-grade
    derive_key(passphrase: str, salt: bytes) -> bytes   # 32 bytes via scrypt
"""

from app.crypto.kdf import derive_key, generate_salt


def test_key_is_32_bytes():
    key = derive_key("correct horse battery staple", generate_salt())
    assert isinstance(key, bytes)
    assert len(key) == 32  # AES-256 needs exactly 32 bytes


def test_same_inputs_same_key():
    # Determinism: extraction must re-derive the identical key from
    # the salt stored in the envelope header.
    salt = generate_salt()
    assert derive_key("passphrase", salt) == derive_key("passphrase", salt)


def test_different_salt_different_key():
    # FR-CRYPTO-005: fresh salt per derivation. Same passphrase must not
    # produce the same key twice across embeds.
    assert derive_key("passphrase", generate_salt()) != derive_key(
        "passphrase", generate_salt()
    )


def test_different_passphrase_different_key():
    salt = generate_salt()
    assert derive_key("passphrase-a", salt) != derive_key("passphrase-b", salt)


def test_salt_is_16_random_bytes():
    salts = {generate_salt() for _ in range(100)}
    assert all(isinstance(s, bytes) and len(s) == 16 for s in salts)
    assert len(salts) == 100  # no collisions in 100 draws


def test_unicode_passphrase_supported():
    # Users will type non-ASCII passphrases. Encode explicitly (UTF-8),
    # never rely on a default encoding.
    salt = generate_salt()
    assert len(derive_key("مرحبا-pässwörd-密码", salt)) == 32
