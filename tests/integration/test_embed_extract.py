"""End-to-end embed → extract round trips and tamper resistance.

This is the acceptance test for Phase 1 (roadmap): valid round trip succeeds,
wrong passphrase fails, modified artifact fails, oversized payload rejected.
"""

import io

import numpy as np
import pytest
from PIL import Image

from app.crypto.aead import DecryptionError
from app.steganography.capacity import max_payload_bytes
from app.steganography.lsb_png import CapacityError
from app.steganography.verifier import verify
from app.services.embed_service import embed_payload
from app.services.extract_service import ExtractionError, extract_payload


def _image(w: int = 256, h: int = 256, mode: str = "RGB") -> Image.Image:
    rng = np.random.default_rng(0)
    channels = 4 if mode == "RGBA" else 3
    arr = rng.integers(0, 256, size=(h, w, channels), dtype=np.uint8)
    return Image.fromarray(arr, mode=mode)


def _reload(png_bytes: bytes) -> Image.Image:
    return Image.open(io.BytesIO(png_bytes))


def test_text_round_trip():
    payload = "the launch code is 0000".encode()
    stego = embed_payload(_image(), payload, "correct passphrase")
    assert extract_payload(_reload(stego), "correct passphrase") == payload


def test_binary_round_trip():
    payload = bytes(range(256)) * 10
    stego = embed_payload(_image(), payload, "pw")
    assert extract_payload(_reload(stego), "pw") == payload


def test_round_trip_rgba():
    payload = b"alpha channel payload"
    stego = embed_payload(_image(mode="RGBA"), payload, "pw")
    assert extract_payload(_reload(stego), "pw") == payload


def test_wrong_passphrase_fails():
    stego = embed_payload(_image(), b"secret", "right")
    with pytest.raises(ExtractionError):
        extract_payload(_reload(stego), "wrong")


def test_modified_artifact_fails():
    # Use a sizable payload and flip LSBs across a large block (well away from
    # the row-0 header region) so the scattered ciphertext is hit with
    # certainty — no statistical flakiness.
    stego = embed_payload(_image(), b"secret payload to protect" * 8, "pw")
    img = _reload(stego).convert("RGB")
    arr = np.asarray(img, dtype=np.uint8).copy()
    arr[20:236, 20:236, :] ^= 1  # ~140k channel bytes flipped; header untouched
    tampered = Image.fromarray(arr, mode="RGB")
    with pytest.raises(ExtractionError):
        extract_payload(tampered, "pw")


def test_oversized_payload_rejected():
    img = _image(64, 64)
    too_big = b"x" * (max_payload_bytes(img) + 1)
    with pytest.raises(CapacityError):
        embed_payload(img, too_big, "pw")


def test_max_payload_fits():
    img = _image(128, 128)
    payload = b"y" * max_payload_bytes(img)
    stego = embed_payload(img, payload, "pw")
    assert extract_payload(_reload(stego), "pw") == payload


def test_empty_payload_round_trips():
    stego = embed_payload(_image(), b"", "pw")
    assert extract_payload(_reload(stego), "pw") == b""


def test_verify_detects_structure_without_passphrase():
    stego = embed_payload(_image(), b"hello", "pw")
    result = verify(_reload(stego))
    assert result.compatible_payload_detected
    assert result.envelope_structure_valid


def test_verify_on_clean_image_finds_nothing():
    result = verify(_image())
    assert not result.compatible_payload_detected


def test_different_embeds_use_different_salts():
    # FR-CRYPTO-005: same payload + passphrase must not produce identical output.
    a = embed_payload(_image(), b"same", "pw")
    b = embed_payload(_image(), b"same", "pw")
    assert a != b


def test_decryptionerror_is_not_leaked_as_subtype():
    # The service boundary must only ever raise ExtractionError, never the
    # underlying DecryptionError (FR-CRYPTO-008).
    stego = embed_payload(_image(), b"secret", "right")
    try:
        extract_payload(_reload(stego), "wrong")
    except ExtractionError:
        pass
    else:
        raise AssertionError("expected ExtractionError")
    assert not issubclass(ExtractionError, DecryptionError)
