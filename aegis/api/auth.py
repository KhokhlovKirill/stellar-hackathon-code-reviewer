<<<<<<< Updated upstream
"""Small HMAC-signed bearer token auth for the admin API.

The frontend can treat this as a JWT-shaped token. We keep it stdlib-only to avoid
adding auth framework complexity while still having expiry and signature checks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, cast

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aegis.config import get_settings

_bearer = HTTPBearer(auto_error=False)
_bearer_dependency = Depends(_bearer)


def issue_token(subject: str, ttl_seconds: int = 86_400) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": subject, "iat": int(time.time()), "exp": int(time.time()) + ttl_seconds}
    signing_input = f"{_b64(header)}.{_b64(payload)}"
    sig = hmac.new(_key(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64_bytes(sig)}"


def verify_token(token: str) -> dict[str, Any]:
    try:
        head, payload, sig = token.split(".")
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc
    expected = _b64_bytes(hmac.new(_key(), f"{head}.{payload}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="invalid token signature")
    data = _unb64(payload)
    if int(data.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=401, detail="token expired")
    return data


async def require_admin(
    credentials: HTTPAuthorizationCredentials | None = _bearer_dependency,
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="missing bearer token")
    data = verify_token(credentials.credentials)
    sub = str(data.get("sub") or "")
    if not sub:
        raise HTTPException(status_code=401, detail="invalid subject")
    return sub


def _key() -> bytes:
    return get_settings().vault_key.encode()


def _b64(data: dict[str, Any]) -> str:
    return _b64_bytes(json.dumps(data, separators=(",", ":"), sort_keys=True).encode())


def _b64_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> dict[str, Any]:
    padded = data + "=" * (-len(data) % 4)
    return cast(dict[str, Any], json.loads(base64.urlsafe_b64decode(padded.encode())))
=======
"""JWT authentication for the Aegis API."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from aegis.config import get_settings
from aegis.observability.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])
_bearer = HTTPBearer(auto_error=False)

_ALGORITHM = "HS256"
_ACCESS_TOKEN_EXPIRE_MINUTES = 60
_REFRESH_TOKEN_EXPIRE_DAYS = 30


# ── Pydantic models ───────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = _ACCESS_TOKEN_EXPIRE_MINUTES * 60


class RefreshRequest(BaseModel):
    refresh_token: str


# ── Helper functions ──────────────────────────────────────────────────────────

def create_access_token(subject: str, extra: dict | None = None) -> str:
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
        **(extra or {}),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(days=_REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.jwt_refresh_secret_key, algorithm=_ALGORITHM)


def verify_token(token: str, secret: str, expected_type: str = "access") -> dict:
    """Decode and validate a JWT. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, secret, algorithms=[_ALGORITHM])
        if payload.get("type") != expected_type:
            raise HTTPException(status_code=401, detail="Invalid token type")
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict:
    """FastAPI dependency — validates Bearer token and returns user payload."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    settings = get_settings()
    payload = verify_token(credentials.credentials, settings.jwt_secret_key)
    return payload


async def get_current_admin(user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """Require admin role."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """Authenticate and issue JWT tokens.

    In a real deployment this would verify against a user database.
    For now it supports a simple admin:admin default for local dev.
    """
    settings = get_settings()

    # Simple credential check — replace with DB lookup in production
    expected_user = settings.admin_username
    expected_pass = settings.admin_password

    if request.username != expected_user or request.password != expected_pass:
        log.warning("auth.login_failed", username=request.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        subject=request.username,
        extra={"role": "admin"},
    )
    refresh_token = create_refresh_token(subject=request.username)

    log.info("auth.login_success", username=request.username)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest):
    """Issue new access token using refresh token."""
    settings = get_settings()
    payload = verify_token(request.refresh_token, settings.jwt_refresh_secret_key, expected_type="refresh")
    subject = payload.get("sub", "")

    access_token = create_access_token(subject=subject, extra={"role": "admin"})
    new_refresh = create_refresh_token(subject=subject)

    return TokenResponse(access_token=access_token, refresh_token=new_refresh)


@router.get("/me")
async def me(user: Annotated[dict, Depends(get_current_user)]):
    """Return current user info."""
    return {"sub": user.get("sub"), "role": user.get("role")}
>>>>>>> Stashed changes
