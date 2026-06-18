"""LSB embedding into PNG pixel data (FR-STEG-008).

Embedding layout mirrors the envelope's two regions (see crypto/envelope.py):
  * the fixed 46-byte header is written into the FIRST header_bits channel-byte
    LSBs, sequentially and unpermuted, so the extractor can read salt + length
    before it needs the key-seeded permutation;
  * the ciphertext is written into the REMAINING channel-byte LSBs in a
    key-seeded permuted order.

PNG only (FR-STEG-001/002): PNG is lossless, so LSBs survive a save/load cycle.
"""

import io

import numpy as np
from PIL import Image

from app.crypto.envelope import HEADER_LEN, Envelope
from app.steganography.pixel_permutation import permuted_positions

HEADER_BITS = HEADER_LEN * 8


class CapacityError(Exception):
    """Raised when an envelope does not fit in the carrier image."""


def _to_channels(image: Image.Image) -> tuple[np.ndarray, str, tuple[int, int]]:
    """Return a flat uint8 channel array plus the mode and size to rebuild."""
    mode = image.mode if image.mode in ("RGB", "RGBA") else "RGB"
    if image.mode != mode:
        image = image.convert(mode)
    arr = np.asarray(image, dtype=np.uint8)
    return arr.reshape(-1).copy(), mode, image.size


def _bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


def embed(image: Image.Image, envelope: Envelope) -> bytes:
    """Embed an envelope into the image. Returns PNG bytes."""
    flat, mode, size = _to_channels(image)
    total = flat.size

    header_bits = _bytes_to_bits(envelope.header_bytes())
    cipher_bits = _bytes_to_bits(envelope.ciphertext)

    if HEADER_BITS + cipher_bits.size > total:
        raise CapacityError("payload exceeds image capacity")

    # Region 1: header, sequential.
    flat[:HEADER_BITS] = (flat[:HEADER_BITS] & 0xFE) | header_bits

    # Region 2: ciphertext, permuted over the remaining channel bytes.
    remaining = np.arange(HEADER_BITS, total)
    order = permuted_positions(_perm_key(envelope), remaining)
    targets = order[: cipher_bits.size]
    flat[targets] = (flat[targets] & 0xFE) | cipher_bits

    width, height = size
    channels = 4 if mode == "RGBA" else 3
    out = flat.reshape((height, width, channels))
    buffer = io.BytesIO()
    # optimize=False keeps embedding deterministic; metadata is dropped by
    # default since we build a fresh image (FR: strip unnecessary metadata).
    Image.fromarray(out, mode=mode).save(buffer, format="PNG")
    return buffer.getvalue()


def _perm_key(envelope: Envelope) -> bytes:
    """Permutation seed key.

    The real key is derived from the passphrase at the service layer; here we
    seed the permutation from the salt+nonce so the embed step needs no
    passphrase. The extractor reconstructs the same seed from the parsed header.
    NOTE: this couples permutation order to public header fields, which is
    acceptable because permutation is an obfuscation layer, not a secret (see
    pixel_permutation docstring). For a key-bound permutation, pass the derived
    key from the service layer instead.
    """
    return envelope.salt + envelope.nonce


def read_header_region(image: Image.Image) -> bytes:
    """Read the raw 46 header bytes from the sequential region."""
    flat, _, _ = _to_channels(image)
    if flat.size < HEADER_BITS:
        raise CapacityError("image too small to contain a header")
    header_bits = flat[:HEADER_BITS] & 1
    return _bits_to_bytes(header_bits.astype(np.uint8))


def read_ciphertext_region(
    image: Image.Image, perm_key: bytes, ciphertext_length: int
) -> bytes:
    """Read ciphertext_length bytes from the permuted region."""
    flat, _, _ = _to_channels(image)
    total = flat.size
    remaining = np.arange(HEADER_BITS, total)
    order = permuted_positions(perm_key, remaining)
    n_bits = ciphertext_length * 8
    if n_bits > order.size:
        raise CapacityError("declared ciphertext length exceeds image")
    targets = order[:n_bits]
    cipher_bits = (flat[targets] & 1).astype(np.uint8)
    return _bits_to_bytes(cipher_bits)
