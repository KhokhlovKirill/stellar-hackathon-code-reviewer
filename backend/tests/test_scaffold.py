"""Phase 0 gate tests: app boots, health/metrics work, schemas/redaction sane.

No DB/Redis required (readyz is allowed to report not-ready here).
"""

from __future__ import annotations

import os

os.environ.setdefault("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6379/0")
# Deterministic test Fernet key.
os.environ.setdefault("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")

from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.obs.logging import _scrub
from aegis.schemas import Finding, FindingSource, Severity


def test_healthz_and_metrics() -> None:
    with TestClient(create_app()) as client:
        r = client.get("/healthz")
        assert r.status_code == 200 and r.json()["status"] == "ok"
        m = client.get("/metrics")
        assert m.status_code == 200
        assert b"aegis_scans_total" in m.content


def test_severity_ordering() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.LOW.rank > Severity.INFO.rank


def test_finding_fingerprint_stable() -> None:
    f = Finding(
        file="app/db.py", line=42, cwe="CWE-89", severity=Severity.CRITICAL,
        confidence=0.9, source=FindingSource.DETERMINISTIC, title="SQLi",
        rationale="user input interpolated into SQL",
    )
    assert f.fingerprint() == f.model_copy().fingerprint()
    assert len(f.fingerprint()) == 40


def test_log_redaction_masks_secrets() -> None:
    s = _scrub("authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in s
    d = _scrub({"token": "supersecretvalue", "ok": "fine"})
    assert d["token"] == "«redacted»" and d["ok"] == "fine"
    aws = _scrub("key AKIAIOSFODNN7EXAMPLE here")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws
