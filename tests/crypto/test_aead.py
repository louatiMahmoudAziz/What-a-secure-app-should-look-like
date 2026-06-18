"""Tests for app.crypto.aead — FR-CRYPTO-002/003/008.

Your job: implement app/crypto/aead.py so these pass.

Required interface:
    class DecryptionError(Exception)    # the ONLY error decrypt may raise
    encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]
        # returns (nonce, ciphertext) — ciphertext includes the GCM tag
    decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes
"""

import os

import pytest

from app.crypto.aead import DecryptionError, decrypt, encrypt

KEY = os.urandom(32)


def test_round_trip():
    plaintext = b"attack at dawn"
    nonce, ct = encrypt(KEY, plaintext)
    assert decrypt(KEY, nonce, ct) == plaintext


def test_ciphertext_is_not_plaintext():
    nonce, ct = encrypt(KEY, b"attack at dawn")
    assert b"attack at dawn" not in ct


def test_nonce_is_12_bytes_and_unique():
    # FR-CRYPTO-003. Nonce reuse under GCM is CATASTROPHIC: it leaks the XOR
    # of plaintexts and enables tag forgery. 96-bit random nonce, every call.
    nonces = {encrypt(KEY, b"x")[0] for _ in range(1000)}
    assert all(len(n) == 12 for n in nonces)
    assert len(nonces) == 1000


def test_wrong_key_fails():
    nonce, ct = encrypt(KEY, b"secret")
    with pytest.raises(DecryptionError):
        decrypt(os.urandom(32), nonce, ct)


def test_tampered_ciphertext_fails():
    nonce, ct = encrypt(KEY, b"secret")
    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(DecryptionError):
        decrypt(KEY, nonce, tampered)


def test_tampered_tag_fails():
    # GCM appends the 16-byte tag; flip a bit in the last byte.
    nonce, ct = encrypt(KEY, b"secret")
    tampered = ct[:-1] + bytes([ct[-1] ^ 0x01])
    with pytest.raises(DecryptionError):
        decrypt(KEY, nonce, tampered)


def test_truncated_ciphertext_fails():
    nonce, ct = encrypt(KEY, b"secret")
    with pytest.raises(DecryptionError):
        decrypt(KEY, nonce, ct[: len(ct) // 2])


def test_garbage_input_raises_only_decryption_error():
    # FR-CRYPTO-008: every failure mode collapses to ONE exception type.
    # Callers must not be able to distinguish wrong-key from corrupt-data
    # (error-oracle resistance). No ValueError/IndexError may escape.
    with pytest.raises(DecryptionError):
        decrypt(KEY, b"\x00" * 12, b"not-real-ciphertext")


def test_empty_plaintext_round_trips():
    # Spec 20.4: empty-payload behavior must be defined. We define it as legal.
    nonce, ct = encrypt(KEY, b"")
    assert decrypt(KEY, nonce, ct) == b""


def test_max_payload_round_trips():
    blob = os.urandom(64 * 1024)  # 64 KiB ceiling (FR-STEG-005)
    nonce, ct = encrypt(KEY, blob)
    assert decrypt(KEY, nonce, ct) == blob
