"""Audit event recording (spec 13.2).

CONCURRENCY NOTE: serialize chain writes (PostgreSQL advisory lock or
SELECT ... FOR UPDATE on a chain-head row) or concurrent requests fork the
hash chain and verification fails.
TODO Phase 3.
"""
