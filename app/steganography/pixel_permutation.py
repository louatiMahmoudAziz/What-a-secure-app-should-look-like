"""Pseudorandom pixel permutation (FR-STEG-009/010).

The ciphertext region is scattered across the image in a key-dependent order
rather than written in a naive sequential run. The permutation seed is derived
from the encryption key, so only a holder of the correct passphrase can compute
the same ordering. This is NOT a confidentiality control (the ciphertext is
already encrypted) — it avoids an obvious, easily-detected sequential LSB
pattern, per the spec's "do not use a naive repeated-key pattern" requirement.

Detectability of LSB steganography remains possible regardless; see the threat
model. Encryption, not permutation, is what protects the payload.
"""

import hashlib

import numpy as np

_DOMAIN = b"steg-permutation-v1"


def _seed_from_key(key: bytes) -> int:
    """Derive a reproducible 64-bit RNG seed from the encryption key."""
    digest = hashlib.sha256(_DOMAIN + key).digest()
    return int.from_bytes(digest[:8], "big")


def permuted_positions(key: bytes, positions: np.ndarray) -> np.ndarray:
    """Return `positions` reordered by a key-seeded permutation.

    Deterministic for a given (key, positions): embed and extract derive the
    identical ordering. Uses NumPy's PCG64 generator, whose output is stable
    across versions for a fixed seed.
    """
    rng = np.random.default_rng(_seed_from_key(key))
    return rng.permutation(positions)
