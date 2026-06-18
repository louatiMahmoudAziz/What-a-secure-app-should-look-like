"""AES-256-GCM authenticated encryption (FR-CRYPTO-002/003/008).

GCM gives confidentiality AND integrity in one pass: any modification to the
ciphertext, the 16-byte tag, or the nonce makes decryption fail.

Two non-negotiable properties:
  * Fresh 96-bit random nonce on EVERY encrypt call. Reusing a (key, nonce) pair
    under GCM leaks the XOR of plaintexts and enables tag forgery — catastrophic.
  * Every decryption failure raises exactly one exception type, DecryptionError,
    so a caller cannot distinguish wrong-key from corrupt-data (no error oracle).
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12  # 96-bit nonce is the GCM-recommended size


class DecryptionError(Exception):
    """Raised for ALL decryption failures (FR-CRYPTO-008). Carries no detail."""


def encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext. Returns (nonce, ciphertext_with_tag).

    The returned ciphertext already includes the GCM authentication tag appended
    by the library.
    """
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and authenticate. Raises DecryptionError on ANY failure.

    Catches InvalidTag (wrong key / tampered data / bad tag) and ValueError
    (malformed or truncated input, wrong nonce length) and collapses both into
    DecryptionError so no failure-cause information leaks to the caller.
    """
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError("payload could not be authenticated") from exc
