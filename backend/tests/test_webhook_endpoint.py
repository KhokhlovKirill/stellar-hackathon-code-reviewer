"""FastAPI webhook endpoint tests with DB/Redis/Arq patched out."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

os.environ.setdefault("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")
os.environ.setdefault("AEGIS_GITHUB_WEBHOOK_SECRET", "hook-secret")

from fastapi.testclient import TestClient

from aegis.api.app import create_app


class _Session:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    def add(self, row: Any) -> None:
        self.rows.append(row)


@asynccontextmanager
async def _session_cm() -> AsyncIterator[_Session]:
    yield _Session()


def _github_payload() -> dict[str, Any]:
    return {
        "action": "opened",
        "repository": {"id": 42, "full_name": "acme/api"},
        "pull_request": {
            "number": 7,
            "title": "Add endpoint",
            "base": {"sha": "base"},
            "head": {"sha": "head"},
        },
        "sender": {"login": "dev"},
    }


def _signature(body: bytes, secret: str = "hook-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_github_webhook_queues_scan(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from aegis.api import webhooks

    enqueued: list[tuple[str, str]] = []
    monkeypatch.setattr(webhooks, "webhook_secret", _secret)
    monkeypatch.setattr(webhooks, "claim", _claim_true)
    monkeypatch.setattr(webhooks, "get_session", lambda: _session_cm())

    async def _enqueue(scan_id, ev):  # type: ignore[no-untyped-def]
        enqueued.append((scan_id, ev.pr_id))

    monkeypatch.setattr(webhooks, "enqueue_scan", _enqueue)

    body = json.dumps(_github_payload()).encode()
    with TestClient(create_app()) as client:
        r = client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "delivery-1",
                "X-Hub-Signature-256": _signature(body),
            },
        )

    assert r.status_code == 202
    assert r.json()["status"] == "queued"
    assert len(r.json()["scan_id"]) == 32
    assert enqueued == [(r.json()["scan_id"], "7")]


def test_github_webhook_rejects_bad_signature(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from aegis.api import webhooks

    monkeypatch.setattr(webhooks, "webhook_secret", _secret)
    monkeypatch.setattr(webhooks, "claim", _claim_true)
    body = json.dumps(_github_payload()).encode()
    with TestClient(create_app()) as client:
        r = client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "delivery-2",
                "X-Hub-Signature-256": "sha256=bad",
            },
        )

    assert r.status_code == 401
    assert "signature" in r.json()["error"]


def test_github_webhook_duplicate_short_circuits(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from aegis.api import webhooks

    monkeypatch.setattr(webhooks, "webhook_secret", _secret)
    monkeypatch.setattr(webhooks, "claim", _claim_false)
    body = json.dumps(_github_payload()).encode()
    with TestClient(create_app()) as client:
        r = client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "delivery-3",
                "X-Hub-Signature-256": _signature(body),
            },
        )

    assert r.status_code == 202
    assert r.json() == {"status": "duplicate"}


def test_webhook_rejects_non_json_content_type() -> None:
    with TestClient(create_app()) as client:
        r = client.post(
            "/webhooks/github",
            content=b"{}",
            headers={"Content-Type": "text/plain"},
        )
    assert r.status_code == 415


async def _secret(*_: Any) -> str:
    return "hook-secret"


async def _claim_true(*_: Any) -> bool:
    return True


async def _claim_false(*_: Any) -> bool:
    return False
