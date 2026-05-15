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
