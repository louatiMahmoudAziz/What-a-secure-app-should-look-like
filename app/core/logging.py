"""Structured JSON logging with mandatory redaction (spec 13.1/13.3).

Never log: plaintext payloads, passphrases, passwords, derived keys, JWTs,
refresh tokens, MFA secrets, raw image content. Redaction is tested (spec 20.6).
TODO Phase 3.
"""
