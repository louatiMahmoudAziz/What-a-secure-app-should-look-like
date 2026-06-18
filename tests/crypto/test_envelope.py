"""Tests for app.crypto.envelope — FR-CRYPTO-007."""

import os

import pytest

from app.crypto.envelope import (
    HEADER_LEN,
    Envelope,
    EnvelopeError,
    parse_header,
)


def _make() -> Envelope:
    return Envelope(
        salt=os.urandom(16),
        nonce=os.urandom(12),
        ciphertext=os.urandom(100),
        kdf_n=2**14,
        kdf_r=8,
        kdf_p=1,
    )


def test_header_is_fixed_length():
    assert len(_make().header_bytes()) == HEADER_LEN


def test_round_trip_header_fields():
    env = _make()
    parsed = parse_header(env.serialize())
    assert parsed.salt == env.salt
    assert parsed.nonce == env.nonce
    assert parsed.ciphertext_length == len(env.ciphertext)
    assert parsed.kdf_n == env.kdf_n


def test_bad_magic_rejected():
    blob = bytearray(_make().serialize())
    blob[0] = 0x00
    with pytest.raises(EnvelopeError):
        parse_header(bytes(blob))


def test_unsupported_version_rejected():
    blob = bytearray(_make().serialize())
    blob[4] = 99  # format_version byte
    with pytest.raises(EnvelopeError):
        parse_header(bytes(blob))


def test_truncated_header_rejected():
    with pytest.raises(EnvelopeError):
        parse_header(b"STG1")
