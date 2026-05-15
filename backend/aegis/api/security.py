"""User password hashing and API bearer authentication."""

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
    """Bearer token → User. 401 if missing/invalid/unknown."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    data = verify_token(auth.split(" ", 1)[1].strip())
    email = str(data.get("sub") or "")
    user = await _user_by_email(email) if email else None
    if user is None:
        raise HTTPException(status_code=401, detail="unknown user")
    return user
