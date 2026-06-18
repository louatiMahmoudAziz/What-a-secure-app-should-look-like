"""Security headers middleware (spec 14.1). HSTS only in production.
Relaxed CSP scoped to /docs only (Swagger UI needs inline scripts).

TODO Phase 2.
"""
