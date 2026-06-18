"""Hostile-file validation (spec 9.1).

Defends the image decoder against malicious uploads BEFORE any pixel processing.
Checks, in cheap-to-expensive order: declared size, PNG magic bytes, decoder
success, format, color mode, dimensions, and decoded pixel count
(decompression-bomb guard).

All rejections raise FileValidationError with a stable machine code; the API
layer maps these to a generic "could not be processed" response (spec 14.4) so
no decoder internals leak.
"""

import io

from PIL import Image, UnidentifiedImageError

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

DEFAULT_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB
DEFAULT_MAX_DIMENSION = 4096
DEFAULT_MAX_PIXELS = 16_000_000
ALLOWED_MODES = {"RGB", "RGBA", "L", "P"}


class FileValidationError(Exception):
    """Raised when an uploaded file fails validation. `code` is stable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_png(
    data: bytes,
    *,
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
    max_dimension: int = DEFAULT_MAX_DIMENSION,
    max_pixels: int = DEFAULT_MAX_PIXELS,
) -> Image.Image:
    """Validate raw upload bytes as a safe PNG. Returns a loaded Image.

    Raises FileValidationError on any problem.
    """
    if len(data) == 0:
        raise FileValidationError("EMPTY_FILE", "empty upload")
    if len(data) > max_upload_bytes:
        raise FileValidationError("FILE_TOO_LARGE", "upload exceeds size limit")
    if not data.startswith(PNG_MAGIC):
        # Catches a JPEG/GIF/etc. renamed to .png (FR-STEG-002).
        raise FileValidationError("BAD_MAGIC", "not a PNG file")

    # Disarm decompression bombs: PIL raises DecompressionBombError past a
    # global threshold. We mutate that global only transiently and restore it in
    # `finally`, so concurrent/later validations are unaffected. We also enforce
    # our own explicit pixel ceiling after decode.
    original_max = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = max_pixels
    try:
        # verify() checks structural integrity without decoding pixels.
        with Image.open(io.BytesIO(data)) as probe:
            if probe.format != "PNG":
                raise FileValidationError("NOT_PNG", "decoder did not see a PNG")
            probe.verify()
        # Re-open: verify() leaves the image unusable for further operations.
        image = Image.open(io.BytesIO(data))
        image.load()
    except FileValidationError:
        raise
    except Image.DecompressionBombError as exc:
        raise FileValidationError("PIXEL_BOMB", "image too large to decode") from exc
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        raise FileValidationError("MALFORMED", "image could not be decoded") from exc
    finally:
        Image.MAX_IMAGE_PIXELS = original_max

    width, height = image.size
    if width > max_dimension or height > max_dimension:
        raise FileValidationError("DIMENSIONS", "image dimensions exceed limit")
    if width * height > max_pixels:
        raise FileValidationError("PIXEL_BOMB", "decoded pixel count exceeds limit")
    if image.mode not in ALLOWED_MODES:
        raise FileValidationError("COLOR_MODE", "unsupported color mode")

    return image
