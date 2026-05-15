"""Admin bearer-token helpers."""

from __future__ import annotations

import os

os.environ.setdefault("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")

from aegis.api.auth import issue_token, verify_token


def test_issue_and_verify_admin_token() -> None:
    token = issue_token("admin", ttl_seconds=60)
    data = verify_token(token)
    assert data["sub"] == "admin"
    assert data["exp"] > data["iat"]
