from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from datetime import datetime, timezone
import time
import uuid

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, app_env:str ="dev"):
        super().__init__(app)
        self.app_env = app_env
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()

        response = await call_next(request)
        
        req_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        if self.app_env == "prod":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-Request-ID"] = request.headers.get("X-Request-ID", "")
        duration_ms = int((time.perf_counter() - start) * 1000)
        
        ts = datetime.now(timezone.utc).isoformat()
        client_ip = getattr(request.client, "host", "-")
        print(f"ts={ts} request_id={req_id} method={request.method} path={request.url.path} "
              f"status={response.status_code} duration_ms={duration_ms} client_ip={client_ip}")
        return response
    

def build_middleware(app_env: str, allow_origins: list[str]) -> list[Middleware]:
    return [
        Middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        ),
        Middleware(SecurityHeadersMiddleware, app_env=app_env),
    ]
