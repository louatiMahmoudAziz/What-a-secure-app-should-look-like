"""Embed workflow orchestration (spec 8.1).

Ties together: capacity check → key derivation → AEAD encryption → envelope
serialization → LSB embedding. Returns the stego PNG bytes.

The passphrase, derived key, and plaintext never leave this function's scope and
are never persisted (FR-CRYPTO-006).
"""

from PIL import Image

from app.crypto.aead import encrypt
from app.crypto.envelope import Envelope
from app.crypto.kdf import SCRYPT_N, SCRYPT_P, SCRYPT_R, derive_key, generate_salt
from app.steganography.capacity import fits
from app.steganography.lsb_png import CapacityError, embed


def embed_payload(image: Image.Image, payload: bytes, passphrase: str) -> bytes:
    """Encrypt `payload` under `passphrase` and embed it in `image`.

    Returns stego PNG bytes. Raises CapacityError if the payload does not fit.
    """
    if not fits(image, len(payload)):
        raise CapacityError("payload exceeds image capacity")

    salt = generate_salt()
    key = derive_key(passphrase, salt)
    nonce, ciphertext = encrypt(key, payload)

    envelope = Envelope(
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
        kdf_n=SCRYPT_N,
        kdf_r=SCRYPT_R,
        kdf_p=SCRYPT_P,
    )
    return embed(image, envelope)
