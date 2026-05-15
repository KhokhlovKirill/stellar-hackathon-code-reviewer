"""API auth + project flow (replaces legacy Jinja web routes)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

os.environ.setdefault("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")

import pytest
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.api.security import hash_password, verify_password
from aegis.db.models import Project, Repository, User


def test_password_hash_roundtrip() -> None:
    h = hash_password("correct horse battery staple")
    assert "$" in h
    assert verify_password("correct horse battery staple", h)
    assert not verify_password("wrong", h)


def test_register_request_validation() -> None:
    from aegis.api.admin import RegisterRequest

    ok = RegisterRequest(email="  USER@Example.com ", password="longenough")
    assert ok.email == "user@example.com"

    with pytest.raises(ValueError, match="invalid email"):
        RegisterRequest(email="bad", password="longenough")


class _Result:
    def __init__(self, scalar: Any = None, scalars: list[Any] | None = None) -> None:
        self._scalar = scalar
        self._scalars = scalars or []

    def scalar_one_or_none(self) -> Any:
        return self._scalar

    def scalar_one(self) -> Any:
        return self._scalar if self._scalar is not None else 0

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return self._scalars

    def first(self) -> Any:
        return self._scalars[0] if self._scalars else None


class _FakeDB:
    def __init__(self) -> None:
        self.users: list[User] = []
        self.projects: list[Project] = []
        self.repos: list[Repository] = []
        self._uid = 0
        self._pid = 0


class _FakeSession:
    def __init__(self, db: _FakeDB) -> None:
        self.db = db

    async def execute(self, stmt: Any) -> _Result:
        sql = str(stmt).lower()
        params = stmt.compile().params

        if "from users" in sql:
            email = params.get("email_1")
            match = next((u for u in self.db.users if u.email == email), None)
            return _Result(scalar=match)

        if "count(repositories" in sql:
            pid = params.get("project_id_1")
            return _Result(scalar=sum(1 for r in self.db.repos if r.project_id == pid))

        if "from projects" in sql:
            owner = params.get("owner_id_1")
            name = params.get("name_1")
            if name is not None:
                dup = next(
                    (p for p in self.db.projects
                     if p.owner_id == owner and p.name == name), None
                )
                return _Result(scalar=dup.id if dup else None)
            owned = [p for p in self.db.projects if p.owner_id == owner]
            return _Result(scalars=owned)

        return _Result()

    def add(self, row: Any) -> None:
        if isinstance(row, User):
            self.db._uid += 1
            row.id = self.db._uid
            self.db.users.append(row)
        elif isinstance(row, Project):
            self.db._pid += 1
            row.id = self.db._pid
            self.db.projects.append(row)
        elif isinstance(row, Repository):
            self.db.repos.append(row)

    async def flush(self) -> None:
        return None


def _client_with_fake_db() -> tuple[TestClient, _FakeDB]:
    db = _FakeDB()

    @asynccontextmanager
    async def fake_session() -> AsyncIterator[_FakeSession]:
        yield _FakeSession(db)

    import aegis.api.admin as admin
    import aegis.api.security as sec

    app = create_app()
    client = TestClient(app)
    client._fake = (admin, sec, fake_session)  # type: ignore[attr-defined]
    return client, db


def test_register_login_create_project_api_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, db = _client_with_fake_db()
    admin, sec, fake_session = client._fake  # type: ignore[attr-defined]
    monkeypatch.setattr(admin, "get_session", fake_session)
    monkeypatch.setattr(sec, "get_session", fake_session)

    r = client.post(
        "/api/auth/register",
        json={
            "email": "dev@acme.io",
            "password": "supersecret",
            "display_name": "Dev",
        },
    )
    assert r.status_code == 201
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    r = client.get("/api/projects", headers=headers)
    assert r.status_code == 200
    assert r.json() == []

    r = client.post(
        "/api/projects",
        headers=headers,
        json={"name": "Payments API", "description": "core service"},
    )
    assert r.status_code == 201
    assert db.projects[0].name == "Payments API"
    pid = r.json()["id"]

    r = client.get(f"/api/projects/{pid}", headers=headers)
    assert r.status_code == 200
    assert r.json()["project"]["name"] == "Payments API"


def test_register_rejects_duplicate_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, db = _client_with_fake_db()
    admin, sec, fake_session = client._fake  # type: ignore[attr-defined]
    monkeypatch.setattr(admin, "get_session", fake_session)
    monkeypatch.setattr(sec, "get_session", fake_session)

    client.post(
        "/api/auth/register",
        json={"email": "a@b.co", "password": "longenough1"},
    )
    r = client.post(
        "/api/auth/register",
        json={"email": "a@b.co", "password": "longenough2"},
    )
    assert r.status_code == 409
    assert len(db.users) == 1


def test_login_wrong_password() -> None:
    client, _db = _client_with_fake_db()
    r = client.post(
        "/api/auth/login",
        json={"username": "nobody@x.io", "password": "wrong"},
    )
    assert r.status_code == 401


def test_projects_require_bearer() -> None:
    client = TestClient(create_app())
    assert client.get("/api/projects").status_code == 401
