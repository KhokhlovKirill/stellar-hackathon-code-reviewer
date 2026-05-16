"""Security KB unit tests — cosine math + kb_enrich stage (no network/DB)."""

from __future__ import annotations

import os

os.environ.setdefault("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")

import pytest

from aegis.kb.embeddings import _embed_text, cosine
from aegis.pipeline.kb_enrich import enrich_with_kb
from aegis.pipeline.state import PipelineState
from aegis.schemas import (
    Finding,
    FindingSource,
    Provider,
    PullRequest,
    ScanResult,
    Severity,
    WebhookEvent,
)


def test_cosine_identical_vectors() -> None:
    v = [0.1, 0.2, 0.3, 0.4]
    assert cosine(v, v) == pytest.approx(1.0)


def test_cosine_orthogonal_vectors() -> None:
    assert cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_cosine_handles_empty_and_mismatched() -> None:
    assert cosine([], [1.0]) == 0.0
    assert cosine([1.0, 2.0], [1.0]) == 0.0
    assert cosine([0.0, 0.0], [0.0, 0.0]) == 0.0


def test_cosine_similar_direction_high() -> None:
    assert cosine([1.0, 1.0, 1.0], [0.9, 1.1, 1.0]) > 0.99


def test_embed_text_compact_and_bounded() -> None:
    txt = _embed_text("SQL injection", "x" * 9000, "CWE-89")
    assert txt.startswith("[CWE-89] SQL injection")
    assert len(txt) <= 4000


def _state() -> PipelineState:
    ev = WebhookEvent(
        provider=Provider.GITHUB, kind="pr_opened", delivery_id="d1",
        repo_slug="o/r", repo_external_id="1", pr_id="7",
    )
    pr = PullRequest(
        provider=Provider.GITHUB, repo_slug="o/r", repo_external_id="1",
        pr_id="7", title="t", base_sha="a", head_sha="b",
        base_ref="main", head_ref="feat",
    )
    res = ScanResult(
        scan_id="s1", provider=Provider.GITHUB, repo_slug="o/r",
        pr_id="7", head_sha="b", started_at=__import__("datetime").datetime.now(
            __import__("datetime").UTC
        ),
    )
    return PipelineState(scan_id="s1", ev=ev, pr=pr, ctx=None, result=res, files=[])  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_kb_enrich_noop_when_no_findings() -> None:
    state = _state()
    await enrich_with_kb(state)
    assert state.kb_matches == {}


@pytest.mark.asyncio
async def test_kb_enrich_annotates_on_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegis.kb.store import SimilarHit

    state = _state()
    state.findings = [Finding(
        file="app/db.py", line=10, cwe="CWE-89", severity=Severity.HIGH,
        confidence=0.9, source=FindingSource.JUDGE, title="SQLi", rationale="bad",
    )]

    async def fake_query_similar(**_: object) -> list[SimilarHit]:
        return [SimilarHit(
            pr_id="142", scan_id="old", cwe="CWE-89",
            title="prior SQLi", file="app/db.py", similarity=0.91,
        )]

    monkeypatch.setattr("aegis.pipeline.kb_enrich.query_similar", fake_query_similar)
    await enrich_with_kb(state)

    fp = state.findings[0].fingerprint()
    assert fp in state.kb_matches
    assert state.kb_matches[fp][0]["pr_id"] == "142"
    assert "Recurring pattern" in state.findings[0].rationale
    assert "PR #142" in state.findings[0].rationale
