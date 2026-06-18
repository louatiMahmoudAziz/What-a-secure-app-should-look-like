"""scrypt key derivation (FR-CRYPTO-004/005).

A human passphrase carries little entropy, so the KDF must be deliberately slow
and memory-hard to frustrate brute-force guessing. scrypt provides both and ships
inside the `cryptography` library, so the payload path needs no extra dependency.

The salt is NOT secret — it is stored in plaintext in the envelope header so the
extractor can re-derive the identical key. Its only job is to make every
derivation unique (FR-CRYPTO-005), defeating precomputed tables.
"""

import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_BYTES = 16
KEY_BYTES = 32  # AES-256

# scrypt cost parameters. Encoded into the envelope (kdf_parameters) so future
# versions can change them without breaking old artifacts.
SCRYPT_N = 2**14  # CPU/memory cost
SCRYPT_R = 8      # block size
SCRYPT_P = 1      # parallelization


def generate_salt() -> bytes:
    """Return a fresh cryptographically secure 16-byte salt."""
    return os.urandom(SALT_BYTES)


def derive_key(
    passphrase: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    """Derive a 32-byte key from a passphrase and salt using scrypt.

    Deterministic: identical inputs yield an identical key, which is what makes
    extraction possible. Passphrase is encoded UTF-8 explicitly so non-ASCII
    passphrases derive consistently across platforms.
    """
    kdf = Scrypt(salt=salt, length=KEY_BYTES, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))
