"""event_hash = SHA-256(previous_event_hash || canonical_event_json) (spec 13.4).

Canonicalization must be deterministic (sorted keys, fixed separators).
TODO Phase 3.
"""
