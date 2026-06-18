# Secure Steganography Platform

A secure-by-default FastAPI platform for encrypting, embedding, extracting, and verifying payloads in PNG images, with authentication, object-level authorization, hostile-file handling, audit logging, DevSecOps automation, Azure deployment, and reproducible security benchmarks.

> **Steganography conceals the presence of a message. It does not replace encryption. Payloads are encrypted and authenticated before embedding.**

## Architecture

<!-- TODO: insert docs/architecture-diagram.png -->

## Features

<!-- TODO: Phase 1+ -->

## Security Goals

<!-- TODO -->

## Non-Goals

This project does **not** claim: undetectable communication, anti-forensic capability, monitoring evasion, anonymity, production readiness without independent review, or resistance to steganalysis.

## Embed and Extract Workflow

<!-- TODO -->

## Cryptographic Design

Encrypt-then-embed: scrypt key derivation (fresh salt) → AES-256-GCM (fresh nonce) → versioned envelope → pseudorandom LSB embedding. See `docs/cryptographic-design.md`.

PNG is lossless and suitable for deterministic LSB embedding. JPEG is excluded initially because lossy recompression can destroy embedded content.

## File-Upload Security

<!-- TODO: see docs/secure-file-processing.md -->

## Authentication and Authorization

<!-- TODO: Argon2id, JWT (15 min), rotating refresh tokens, object-level authz -->

## DevSecOps Pipeline

<!-- TODO -->

## Azure Architecture

<!-- TODO: Phase 5 -->

## Benchmark Results

<!-- TODO: see docs/benchmark-results.md -->

## Setup

```bash
cp .env.example .env
docker compose up --build
# API: http://localhost:8000/docs
```

## Running Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest --cov=app
```

## Demo

See `docs/demo-script.md`.

## Known Limitations

See `docs/known-limitations.md`.

## Disclaimer

This project is an educational secure-software-engineering reference implementation using synthetic test data only. It is not intended for covert exfiltration, evasion of monitoring, or production deployment without independent security review. Steganography does not guarantee undetectability and does not replace encryption.
