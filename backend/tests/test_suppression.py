"""False-positive suppression units."""

from __future__ import annotations

from aegis.pipeline.suppression import suppress_findings
from aegis.schemas import Finding, FindingSource, Severity


def _finding(title: str) -> Finding:
    return Finding(
        file="app/db.py",
        line=42,
        cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=0.9,
        source=FindingSource.JUDGE,
        title=title,
        rationale="r",
    )


def test_suppress_findings_by_fingerprint() -> None:
    a = _finding("a")
    b = _finding("b")
    kept, dropped = suppress_findings([a, b], {a.fingerprint()})
    assert kept == [b]
    assert dropped == [a]
