"""Application settings loaded from environment (.env.example documents all keys)."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_env: str = "local"
    database_url: str = "sqlite:///./steg.db"
    redis_url: str = ""
    jwt_signing_key: str = "dev-only-insecure-key-change-me"
    password_min_length: int = 12
    password_max_length: int = 128
    max_failed_logins: int = 10
    lockout_minutes: int = 15
    access_token_lifetime_minutes: int = 15
    refresh_token_lifetime_days: int = 7
    max_upload_bytes: int = 10 * 1024 * 1024
    max_image_dimension: int = 4096
    max_decoded_pixels: int = 16_000_000
    max_payload_bytes: int = 64 * 1024
    stego_retention_minutes: int = 30
    plaintext_retention_minutes: int = 5
    tmp_storage_dir: str = "/tmp/steg-artifacts"
    log_level: str = "INFO"


settings = Settings()
