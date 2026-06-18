"""Hostile-file validation tests (spec 20.5)."""

import io

import numpy as np
import pytest
from PIL import Image

from app.files.validators import FileValidationError, validate_png


def _png_bytes(w: int = 64, h: int = 64, mode: str = "RGB") -> bytes:
    arr = np.zeros((h, w, 4 if mode == "RGBA" else 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, mode=mode).save(buf, format="PNG")
    return buf.getvalue()


def test_valid_png_accepted():
    img = validate_png(_png_bytes())
    assert img.size == (64, 64)


def test_empty_file_rejected():
    with pytest.raises(FileValidationError) as e:
        validate_png(b"")
    assert e.value.code == "EMPTY_FILE"


def test_fake_png_rejected():
    # A JPEG/text blob renamed .png — magic bytes don't match.
    with pytest.raises(FileValidationError) as e:
        validate_png(b"\xff\xd8\xff\xe0 this is not a png")
    assert e.value.code == "BAD_MAGIC"


def test_malformed_png_rejected():
    # Correct magic, garbage body.
    blob = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    with pytest.raises(FileValidationError) as e:
        validate_png(blob)
    assert e.value.code == "MALFORMED"


def test_oversized_file_rejected():
    with pytest.raises(FileValidationError) as e:
        validate_png(_png_bytes(), max_upload_bytes=10)
    assert e.value.code == "FILE_TOO_LARGE"


def test_excessive_dimensions_rejected():
    data = _png_bytes(64, 64)
    with pytest.raises(FileValidationError) as e:
        validate_png(data, max_dimension=32)
    assert e.value.code == "DIMENSIONS"


def test_pixel_bomb_rejected():
    data = _png_bytes(64, 64)
    with pytest.raises(FileValidationError) as e:
        validate_png(data, max_pixels=100)
    assert e.value.code == "PIXEL_BOMB"
