"""Verification (spec 8.3).

DESIGN DECISION (resolves the spec's impossible requirement): without the
passphrase the GCM tag CANNOT be verified — that needs the key. So verify
performs a STRUCTURAL check only: does the image contain a well-formed envelope
header (valid magic, supported version/KDF, self-consistent declared length)?

It reports `envelope_structure_valid`, NOT cryptographic integrity, and never
reveals plaintext. True integrity verification happens during extraction, which
requires the passphrase.

We also deliberately do NOT echo the declared payload size to anonymous callers,
to avoid leaking metadata from an unauthenticated header.
"""

from dataclasses import dataclass

from PIL import Image

from app.crypto.envelope import EnvelopeError, parse_header
from app.steganography.capacity import total_capacity_bytes
from app.steganography.lsb_png import CapacityError, read_header_region


@dataclass(frozen=True)
class VerifyResult:
    compatible_payload_detected: bool
    envelope_structure_valid: bool
    format_version: int | None
    algorithm_version: int | None


def verify(image: Image.Image) -> VerifyResult:
    """Structural-only check. Never raises for ordinary 'no payload' cases."""
    try:
        header = parse_header(read_header_region(image))
    except (EnvelopeError, CapacityError, ValueError):
        return VerifyResult(False, False, None, None)

    # Self-consistency: the declared ciphertext can't exceed the image.
    declared_ok = header.ciphertext_length <= total_capacity_bytes(image)
    return VerifyResult(
        compatible_payload_detected=True,
        envelope_structure_valid=declared_ok,
        format_version=header.version,
        algorithm_version=header.kdf_id,
    )
