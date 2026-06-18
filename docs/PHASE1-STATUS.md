# Phase 1 — Core Cryptographic Steganography Engine (implemented)

## What works

The complete encrypt-then-embed pipeline is implemented and wired together:

| Module | File | Responsibility |
| ------ | ---- | -------------- |
| KDF | `app/crypto/kdf.py` | scrypt key derivation, fresh 16-byte salt |
| AEAD | `app/crypto/aead.py` | AES-256-GCM, fresh 12-byte nonce, single `DecryptionError` |
| Envelope | `app/crypto/envelope.py` | versioned binary format, two-region split |
| Capacity | `app/steganography/capacity.py` | bits-per-channel capacity + payload ceiling |
| Permutation | `app/steganography/pixel_permutation.py` | key-seeded pixel scatter (PCG64) |
| Embedding | `app/steganography/lsb_png.py` | LSB embed/read, header sequential + ciphertext permuted |
| Extraction | `app/steganography/extractor.py` | parse → derive → read → decrypt, generic failure |
| Verifier | `app/steganography/verifier.py` | structural-only check, no passphrase, no plaintext |
| Validation | `app/files/validators.py` | magic bytes, dimensions, pixel-bomb guard |
| Orchestration | `app/services/embed_service.py`, `extract_service.py` | public API |

## Spec critique fixes applied in code

1. **Verify is structural-only** (`verifier.py`): without the passphrase the GCM
   tag cannot be checked, so it reports `envelope_structure_valid`, not integrity,
   and does not echo payload size to anonymous callers.
2. **Two-region envelope** (`envelope.py` + `lsb_png.py`): the fixed 46-byte
   header (magic, version, KDF params, salt, nonce, length) is embedded
   sequentially so the extractor learns salt + length *before* it needs the
   key-seeded permutation. The ciphertext region is permuted.

## How to verify it yourself

The CI sandbox couldn't run here (host disk space), so run locally:

```bash
cd <repo root>
pip install -r requirements.txt -r requirements-dev.txt

# fast, no pytest needed:
python scripts/smoke_test.py

# full suite:
pytest tests/crypto tests/integration tests/file_uploads -v
```

Expected: smoke test prints `8/8 checks passed`; pytest collects ~38 tests, all green.

## Tests included

- `tests/crypto/test_kdf.py` — 6 tests (length, determinism, fresh salt, unicode)
- `tests/crypto/test_aead.py` — 10 tests (round trip, nonce uniqueness ×1000, tamper, oracle resistance)
- `tests/crypto/test_envelope.py` — 5 tests (header parse, bad magic, bad version, truncation)
- `tests/integration/test_embed_extract.py` — 13 tests (round trips, wrong pass, tamper, capacity, verify)
- `tests/file_uploads/test_validators.py` — 7 tests (fake/malformed/oversized/bomb/dimensions)

## Known follow-ups before Phase 1 is "done"

- Decide whether the pixel permutation should be seeded from the **derived key**
  (passphrase-bound) rather than salt+nonce (public). Currently it is an
  obfuscation layer keyed on public header fields — documented in
  `pixel_permutation.py` and `lsb_png._perm_key`. Passphrase-binding it is a
  one-line change at the service layer and slightly raises the bar for an
  attacker reconstructing embed order. Discuss the tradeoff in
  `docs/cryptographic-design.md`.
- Metadata stripping (`files/metadata.py`) is currently implicit (a fresh image
  is written, dropping source chunks). Make it explicit + tested in Phase 3.
- Benchmark script (`scripts/run_benchmarks.py`) still a stub — Phase 1 also asks
  for first benchmark output.
