import os
from functools import lru_cache

class Settings:
    def __init__(self):
        self.app_env = os.getenv("APP_ENV", "dev")
        cors_origins = os.getenv(
            "CORS_ALLOW_ORIGINS",
            "http://localhost:8000,http://127.0.0.1:8000"
        )
        self.cors_allow_origins = [o.strip() for o in cors_origins.split(",") if o.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()
