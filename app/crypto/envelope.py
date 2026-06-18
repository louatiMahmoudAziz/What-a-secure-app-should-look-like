"""Versioned encrypted envelope (FR-CRYPTO-007).

Binary layout (big-endian), split into two regions to resolve the
permutation chicken-and-egg problem:

  ── HEADER REGION (fixed 46 bytes, embedded SEQUENTIALLY, unpermuted) ──
    magic_number       4 bytes   b"STG1"
    format_version     1 byte    uint8
    kdf_identifier     1 byte    uint8   (1 = scrypt)
    kdf_param_n        4 bytes   uint32
    kdf_param_r        2 bytes   uint16
    kdf_param_p        2 bytes   uint16
    salt              16 bytes
    nonce             12 bytes
    ciphertext_length  4 bytes   uint32
  ── CIPHERTEXT REGION (variable, embedded under pixel permutation) ──
    ciphertext         N bytes   (AES-GCM output, tag included)

The extractor reads the fixed header sequentially first. That gives it the salt
(to derive the key) and the ciphertext_length (to know how many permuted bits to
read) BEFORE it needs the permutation — which is seeded from the derived key.
"""

import struct
from dataclasses import dataclass

MAGIC = b"STG1"
FORMAT_VERSION = 1
KDF_SCRYPT = 1

# struct format for the fixed header: 4s B B I H H 16s 12s I
_HEADER_STRUCT = struct.Struct(">4sBBIHH16s12sI")
HEADER_LEN = _HEADER_STRUCT.size  # 46 bytes


class EnvelopeError(Exception):
    """Raised when an envelope header is malformed or unsupported.

    Callers in the extraction path must translate this into the same generic
    failure as a decryption error (FR-CRYPTO-008) — never surface the cause.
    """


@dataclass(frozen=True)
class Envelope:
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    kdf_n: int
    kdf_r: int
    kdf_p: int
    version: int = FORMAT_VERSION
    kdf_id: int = KDF_SCRYPT

    def header_bytes(self) -> bytes:
        """Serialize the fixed 46-byte header region."""
        return _HEADER_STRUCT.pack(
            MAGIC,
            self.version,
            self.kdf_id,
            self.kdf_n,
            self.kdf_r,
            self.kdf_p,
            self.salt,
            self.nonce,
            len(self.ciphertext),
        )

    def serialize(self) -> bytes:
        """Full envelope = header region || ciphertext region."""
        return self.header_bytes() + self.ciphertext


@dataclass(frozen=True)
class ParsedHeader:
    salt: bytes
    nonce: bytes
    ciphertext_length: int
    kdf_n: int
    kdf_r: int
    kdf_p: int
    version: int
    kdf_id: int


def parse_header(data: bytes) -> ParsedHeader:
    """Parse and validate the fixed header region.

    Raises EnvelopeError on bad magic, short input, or unsupported version/KDF.
    """
    if len(data) < HEADER_LEN:
        raise EnvelopeError("truncated header")
    magic, version, kdf_id, n, r, p, salt, nonce, ct_len = _HEADER_STRUCT.unpack(
        data[:HEADER_LEN]
    )
    if magic != MAGIC:
        raise EnvelopeError("bad magic number")
    if version != FORMAT_VERSION:
        raise EnvelopeError("unsupported format version")
    if kdf_id != KDF_SCRYPT:
        raise EnvelopeError("unsupported kdf")
    return ParsedHeader(
        salt=salt,
        nonce=nonce,
        ciphertext_length=ct_len,
        kdf_n=n,
        kdf_r=r,
        kdf_p=p,
        version=version,
        kdf_id=kdf_id,
    )
