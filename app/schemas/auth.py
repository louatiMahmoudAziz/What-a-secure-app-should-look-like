"""Auth request/response schemas.

`extra="forbid"` rejects unexpected request fields (FR-AUTH-002), so an attacker
cannot smuggle e.g. a `role` field into registration (mass-assignment defense).
"""

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from app.core.config import settings

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(_Strict):
    email: str
    password: str
    password_confirmation: str

    @field_validator("email")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v) or len(v) > 320:
            raise ValueError("invalid email")
        return v

    @field_validator("password")
    @classmethod
    def _password_length(cls, v: str) -> str:
        if not (settings.password_min_length <= len(v) <= settings.password_max_length):
            raise ValueError(
                f"password must be {settings.password_min_length}-"
                f"{settings.password_max_length} characters"
            )
        return v

    @model_validator(mode="after")
    def _passwords_match(self) -> "RegisterRequest":
        if self.password != self.password_confirmation:
            raise ValueError("passwords do not match")
        return self


class LoginRequest(_Strict):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return v.strip().lower()


class RefreshRequest(_Strict):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    access_token_expiration: datetime
    refresh_token_expiration: datetime
    token_type: str = "bearer"


class SessionInfo(BaseModel):
    id: str
    issued_at: datetime
    expires_at: datetime
    user_agent_summary: str | None = None
    current: bool = False
