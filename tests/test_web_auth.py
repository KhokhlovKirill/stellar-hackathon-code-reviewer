"""Web/API auth + project flow.

Split into three reliable layers:
  1. pure unit  — password hashing, email/password validation
  2. no-DB web  — routing/redirects/templates that never touch the DB
  3. flow       — register → login → create project → dashboard against a
                  small in-memory fake session (no Postgres needed)
"""

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

# ---------------------------------------------------------------------------- #
# 1. pure unit
# ---------------------------------------------------------------------------- #


def test_password_hash_roundtrip() -> None:
    h = hash_password("correct horse battery staple")
    assert "$" in h
    assert verify_password("correct horse battery staple", h)
    assert not verify_password("wrong", h)


def test_password_hash_is_salted() -> None:
    assert hash_password("same") != hash_password("same")


def test_verify_password_rejects_garbage() -> None:
    assert not verify_password("x", "not-a-valid-hash")
    assert not verify_password("x", "")


def test_register_request_validation() -> None:
    from aegis.api.admin import RegisterRequest

    ok = RegisterRequest(email="  USER@Example.com ", password="longenough")
    assert ok.email == "user@example.com"

    with pytest.raises(ValueError, match="invalid email"):
        RegisterRequest(email="bad", password="longenough")
    with pytest.raises(ValueError):
        RegisterRequest(email="a@b.co", password="short")


# ---------------------------------------------------------------------------- #
# 2. no-DB web routing
# ---------------------------------------------------------------------------- #


def test_login_and_register_pages_render() -> None:
    c = TestClient(create_app())
    assert c.get("/login").status_code == 200
    assert "Sign in" in c.get("/login").text
    assert c.get("/register").status_code == 200
    assert "Create your account" in c.get("/register").text


def test_index_redirects_to_login_when_anonymous() -> None:
    c = TestClient(create_app(), follow_redirects=False)
    r = c.get("/")
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_dashboard_requires_auth() -> None:
    c = TestClient(create_app(), follow_redirects=False)
    r = c.get("/dashboard")
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_bad_session_cookie_is_ignored() -> None:
    c = TestClient(create_app(), follow_redirects=False)
    c.cookies.set("aegis_session", "garbage.token.value")
    r = c.get("/dashboard")
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


# ---------------------------------------------------------------------------- #
# 3. register → login → project flow on an in-memory fake session
# ---------------------------------------------------------------------------- #


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
    """Shared store; one per test."""

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
            # create_project dup check uses owner_id + name; dashboard lists by owner
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

    import aegis.api.security as sec
    import aegis.web.routes as routes

    app = create_app()
    client = TestClient(app, follow_redirects=False)
    client._fake = (routes, sec, fake_session)  # type: ignore[attr-defined]
    return client, db


def test_register_login_create_project_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, db = _client_with_fake_db()
    routes, sec, fake_session = client._fake  # type: ignore[attr-defined]
    monkeypatch.setattr(routes, "get_session", fake_session)
    monkeypatch.setattr(sec, "get_session", fake_session)

    # Register
    r = client.post("/register", data={
        "email": "dev@acme.io", "password": "supersecret", "display_name": "Dev",
    })
    assert r.status_code == 303
    assert r.headers["location"] == "/dashboard"
    assert "aegis_session" in r.cookies
    assert len(db.users) == 1
    assert db.users[0].email == "dev@acme.io"
    assert verify_password("supersecret", db.users[0].password_hash)

    # Authenticated dashboard
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "Your projects" in r.text

    # Create a project
    r = client.post("/projects", data={"name": "Payments API",
                                       "description": "core service"})
    assert r.status_code == 303
    assert db.projects[0].name == "Payments API"
    assert db.projects[0].owner_id == db.users[0].id
    assert r.headers["location"] == f"/projects/{db.projects[0].id}"

    # Logout clears the cookie
    r = client.get("/logout")
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_register_rejects_duplicate_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, db = _client_with_fake_db()
    routes, sec, fake_session = client._fake  # type: ignore[attr-defined]
    monkeypatch.setattr(routes, "get_session", fake_session)
    monkeypatch.setattr(sec, "get_session", fake_session)

    client.post("/register", data={"email": "a@b.co", "password": "longenough1"})
    r = client.post("/register", data={"email": "a@b.co", "password": "longenough2"})
    assert r.status_code == 200
    assert "already registered" in r.text
    assert len(db.users) == 1


def test_login_wrong_password_shows_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _db = _client_with_fake_db()
    routes, sec, fake_session = client._fake  # type: ignore[attr-defined]
    monkeypatch.setattr(routes, "get_session", fake_session)
    monkeypatch.setattr(sec, "get_session", fake_session)

    client.post("/register", data={"email": "z@z.io", "password": "rightpass1"})
    client.cookies.clear()
    r = client.post("/login", data={"email": "z@z.io", "password": "WRONG"})
    assert r.status_code == 200
    assert "Invalid email or password" in r.text
