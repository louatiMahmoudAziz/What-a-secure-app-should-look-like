"""Extract workflow orchestration (spec 8.2).

Thin wrapper over the steganography extractor so the API layer depends on a
service, not the low-level module. All failures surface as ExtractionError.
"""

from PIL import Image

from app.steganography.extractor import ExtractionError, extract

__all__ = ["ExtractionError", "extract_payload"]


def extract_payload(image: Image.Image, passphrase: str) -> bytes:
    """Return the decrypted payload or raise ExtractionError (generic)."""
    return extract(image, passphrase)
