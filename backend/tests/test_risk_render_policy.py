"""Risk score, renderer and merge policy units."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.pipeline.policy import decide
from aegis.pipeline.render import render_inline_comment, render_summary
from aegis.pipeline.risk_score import compute_risk_score, risk_breakdown
from aegis.pipeline.state import PipelineState
from aegis.repos import RepoContext
from aegis.schemas import (
    EventKind,
    Finding,
    FindingSource,
    Provider,
    PullRequest,
    ScanResult,
    Severity,
    WebhookEvent,
)


def _finding(severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        file="app/db.py",
        line=42,
        diff_position=7,
        cwe="CWE-89",
        severity=severity,
        confidence=0.95,
        source=FindingSource.DETERMINISTIC,
        title="SQL injection via string concatenation",
        rationale="User-controlled uid is concatenated into a SQL query.",
        exploit="uid=1 OR 1=1--",
        fix="cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
        fix_is_suggestion=True,
    )


def _state(findings: list[Finding]) -> PipelineState:
    ev = WebhookEvent(
        provider=Provider.GITHUB,
        kind=EventKind.PR_OPENED,
        delivery_id="d",
        repo_slug="acme/api",
        repo_external_id="42",
        pr_id="7",
        head_sha="head",
    )
    pr = PullRequest(
        provider=Provider.GITHUB,
        repo_slug="acme/api",
        repo_external_id="42",
        pr_id="7",
        base_sha="base",
        head_sha="head",
    )
    ctx = RepoContext(
        repo_id=1,
        provider=Provider.GITHUB,
        slug="acme/api",
        access_token="tok",
        severity_gate="medium",
        merge_block="critical",
        ensemble_profile="det+don+judge",
        ignore_globs=[],
        lang="ru",
    )
    result = ScanResult(
        scan_id="scan",
        provider=Provider.GITHUB,
        repo_slug="acme/api",
        pr_id="7",
        head_sha="head",
        started_at=datetime.now(UTC),
        files_scanned=["app/db.py"],
    )
    return PipelineState(
        scan_id="scan",
        ev=ev,
        pr=pr,
        ctx=ctx,
        result=result,
        files=[],
        findings=findings,
    )


def test_risk_breakdown_caps_duplicate_cwe() -> None:
    findings = [_finding(), _finding(), _finding()]
    assert risk_breakdown(findings)["CWE-89"] == 80


async def test_compute_risk_score_sets_state_and_result() -> None:
    state = _state([_finding()])
    await compute_risk_score(state)
    assert state.risk_score == 40
    assert state.risk_label == "critical"
    assert state.result.risk_score == 40


def test_render_inline_comment_contains_fix_and_fingerprint() -> None:
    body = render_inline_comment(_finding())
    assert "CWE-89" in body
    assert "```suggestion" in body
    assert _finding().fingerprint() in body


def test_render_summary_includes_score_files_and_breakdown() -> None:
    # Fixture ctx.lang == "ru" → summary labels must be localized.
    state = _state([_finding()])
    state.risk_score = 40
    state.risk_label = "critical"
    summary = render_summary(state)
    assert "Оценка риска: **40/100**" in summary
    assert "`app/db.py`" in summary
    assert "`CWE-89`: +40" in summary
    assert "Обзор безопасности Aegis" in summary


def test_render_summary_english_when_lang_en() -> None:
    state = _state([_finding()])
    state.ctx.lang = "en"
    state.risk_score = 40
    state.risk_label = "critical"
    summary = render_summary(state)
    assert "Risk Score: **40/100**" in summary
    assert "Aegis security review" in summary


def test_policy_blocks_critical() -> None:
    state = _state([_finding()])
    state.risk_score = 40
    decision = decide(state)
    assert decision.block is True
    assert decision.state == "failure"
    assert decision.context == "aegis/security-gate"


def test_policy_allows_clean_pr() -> None:
    state = _state([])
    decision = decide(state)
    assert decision.block is False
    assert decision.state == "success"
