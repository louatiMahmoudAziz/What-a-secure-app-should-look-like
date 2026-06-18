"""Standalone smoke test for the Phase 1 engine — no pytest required.

Run from the repo root:
    pip install pillow numpy cryptography
    python scripts/smoke_test.py

Exercises the full encrypt → embed → extract → decrypt round trip plus the
core failure modes, and prints a human-readable pass/fail report.
"""

import io
import sys

import numpy as np
from PIL import Image

sys.path.insert(0, ".")

from app.services.embed_service import embed_payload  # noqa: E402
from app.services.extract_service import (  # noqa: E402
    ExtractionError,
    extract_payload,
)
from app.steganography.capacity import max_payload_bytes  # noqa: E402
from app.steganography.lsb_png import CapacityError  # noqa: E402
from app.steganography.verifier import verify  # noqa: E402


def make_image(w=256, h=256, mode="RGB"):
    rng = np.random.default_rng(0)
    c = 4 if mode == "RGBA" else 3
    return Image.fromarray(rng.integers(0, 256, (h, w, c), dtype=np.uint8), mode=mode)


def reload(png):
    return Image.open(io.BytesIO(png))


def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    return ok


def main() -> int:
    results = []

    # 1. Round trip
    msg = "the secret is buried under the third oak".encode()
    stego = embed_payload(make_image(), msg, "hunter2")
    results.append(check("round trip recovers payload",
                         extract_payload(reload(stego), "hunter2") == msg))

    # 2. Wrong passphrase
    try:
        extract_payload(reload(stego), "wrong")
        results.append(check("wrong passphrase rejected", False))
    except ExtractionError:
        results.append(check("wrong passphrase rejected", True))

    # 3. Tamper detection
    arr = np.asarray(reload(stego).convert("RGB"), dtype=np.uint8).copy()
    arr[20:236, 20:236, :] ^= 1
    try:
        extract_payload(Image.fromarray(arr, "RGB"), "hunter2")
        results.append(check("tampered artifact rejected", False))
    except ExtractionError:
        results.append(check("tampered artifact rejected", True))

    # 4. Oversized payload
    small = make_image(64, 64)
    try:
        embed_payload(small, b"x" * (max_payload_bytes(small) + 1), "pw")
        results.append(check("oversized payload rejected", False))
    except CapacityError:
        results.append(check("oversized payload rejected", True))

    # 5. Non-determinism (fresh salt + nonce)
    a = embed_payload(make_image(), b"same", "pw")
    b = embed_payload(make_image(), b"same", "pw")
    results.append(check("identical inputs produce different output", a != b))

    # 6. Verify (structural, no passphrase)
    results.append(check("verify detects embedded structure",
                         verify(reload(stego)).compatible_payload_detected))
    results.append(check("verify finds nothing in clean image",
                         not verify(make_image()).compatible_payload_detected))

    print()
    passed = sum(results)
    print(f"{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
