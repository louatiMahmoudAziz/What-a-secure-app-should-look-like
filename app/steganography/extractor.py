"""Envelope extraction and decryption (FR-CRYPTO-008).

Every failure mode — wrong passphrase, modified image, truncated ciphertext,
bad tag, corrupt header, unsupported version — collapses into one generic
ExtractionError. The caller must not be able to tell them apart.
"""

from PIL import Image

from app.crypto.aead import DecryptionError, decrypt
from app.crypto.envelope import EnvelopeError, parse_header
from app.crypto.kdf import derive_key
from app.steganography.lsb_png import (
    CapacityError,
    read_ciphertext_region,
    read_header_region,
)


class ExtractionError(Exception):
    """Generic, detail-free extraction failure (FR-CRYPTO-008)."""


GENERIC_MESSAGE = (
    "Payload extraction failed: the embedded content could not be authenticated."
)


def extract(image: Image.Image, passphrase: str) -> bytes:
    """Extract and decrypt the embedded payload. Raises ExtractionError on any
    failure, always with the same generic message."""
    try:
        header = parse_header(read_header_region(image))
        perm_key = header.salt + header.nonce
        ciphertext = read_ciphertext_region(
            image, perm_key, header.ciphertext_length
        )
        key = derive_key(
            passphrase, header.salt, n=header.kdf_n, r=header.kdf_r, p=header.kdf_p
        )
        return decrypt(key, header.nonce, ciphertext)
    except (EnvelopeError, DecryptionError, CapacityError, ValueError) as exc:
        raise ExtractionError(GENERIC_MESSAGE) from exc
