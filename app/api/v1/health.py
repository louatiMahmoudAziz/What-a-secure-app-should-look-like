"""Health API (spec 11.5). Liveness is anonymous; readiness checks DB, Redis,
tmp storage, required env vars, crypto-service init, and Blob Storage in cloud mode.

TODO Phase 2 — move health routes here from main.py once DB exists.
"""
