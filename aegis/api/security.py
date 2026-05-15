"""User password hashing + request→user resolution (API bearer & web cookie).

Password hashing is stdlib pbkdf2_hmac (no extra deps): 240k SHA-256 rounds,
16-byte per-user salt, stored as `salt_hex$hash_hex`. Comparison is constant-time.

Two auth entry points share the same signed token (aegis.api.auth):
  - require_user        : API — Authorization: Bearer <token>
  - current_user_web    : Web — httponly `aegis_session` cookie
Both resolve the token subject (user email) to a User row.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select

from aegis.api.auth import verify_token
from aegis.db import get_session
from aegis.db.models import User

_ROUNDS = 240_000
_SALT_BYTES = 16
SESSION_COOKIE = "aegis_session"  # cookie name, not a secret


def hash_password(password: str) -> str:
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ROUNDS)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ROUNDS)
    return hmac.compare_digest(dk.hex(), hash_hex)


async def _user_by_email(email: str) -> User | None:
    async with get_session() as s:
        return (
            await s.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()


async def require_user(request: Request) -> User:
    """API auth: Bearer token → User. 401 if missing/invalid/unknown."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    data = verify_token(auth.split(" ", 1)[1].strip())
    email = str(data.get("sub") or "")
    user = await _user_by_email(email) if email else None
    if user is None:
        raise HTTPException(status_code=401, detail="unknown user")
    return user


async def current_user_web(request: Request) -> User | None:
    """Web auth: session cookie → User or None (pages decide how to handle)."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        data = verify_token(token)
    except HTTPException:
        return None
    email = str(data.get("sub") or "")
    return await _user_by_email(email) if email else None


_current_user_web_dep = Depends(current_user_web)


async def require_user_web(
    user: User | None = _current_user_web_dep,
) -> User:
    if user is None:
        raise HTTPException(status_code=303, detail="login required",
                            headers={"Location": "/login"})
    return user
