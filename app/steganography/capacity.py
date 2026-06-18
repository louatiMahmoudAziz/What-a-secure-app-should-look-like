"""Capacity calculation (FR-STEG-006/007).

We embed one bit per channel byte (the least-significant bit). An RGB image of
W×H pixels therefore holds W·H·3 bits = W·H·3/8 bytes of raw envelope data.

Usable payload capacity subtracts the fixed envelope header and the GCM tag,
since those consume embedding space but are not the user's plaintext.
"""

from PIL import Image

from app.crypto.envelope import HEADER_LEN

GCM_TAG_BYTES = 16


def channel_count(image: Image.Image) -> int:
    """Number of 8-bit channels we embed into (RGB → 3, RGBA → 4)."""
    return 4 if image.mode == "RGBA" else 3


def total_capacity_bytes(image: Image.Image) -> int:
    """Total raw envelope bytes the image can hold (1 bit per channel byte)."""
    width, height = image.size
    return (width * height * channel_count(image)) // 8


def max_payload_bytes(image: Image.Image) -> int:
    """Maximum plaintext payload that fits, after envelope overhead."""
    usable = total_capacity_bytes(image) - HEADER_LEN - GCM_TAG_BYTES
    return max(usable, 0)


def fits(image: Image.Image, payload_len: int) -> bool:
    """True if a payload of payload_len bytes fits in the image (FR-STEG-007)."""
    return payload_len <= max_payload_bytes(image)
