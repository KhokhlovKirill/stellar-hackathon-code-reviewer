"""Deterministic agent — runs SAST tools in parallel."""

from __future__ import annotations

import asyncio

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger
from aegis.observability.metrics import SCANNER_DURATION
from aegis.pipeline.deterministic.semgrep import run_semgrep
from aegis.pipeline.deterministic.bandit import run_bandit
from aegis.pipeline.deterministic.gitleaks import run_gitleaks
from aegis.pipeline.deterministic.sca import run_sca
from aegis.pipeline.deterministic.entropy import run_entropy_scan

log = get_logger(__name__)


async def deterministic_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Run all deterministic scanners in parallel.

    Updates:
        - state["deterministic_findings"]: merged list of all scanner findings
        - state["has_secret"]: True if gitleaks/entropy found something
        - state["scanner_errors"]: dict of scanner_name -> error_message
    """
    filtered_files = state.get("filtered_files", [])
    full_diff = state.get("full_diff", "")

    log.info("deterministic.start", files=len(filtered_files))

    # Prepare file patches list for scanners
    file_patches = [
        {"filename": f.get("filename", ""), "patch": f.get("patch", "")}
        for f in filtered_files
    ]

    # Run all scanners concurrently
    semgrep_task = asyncio.create_task(_run_scanner("semgrep", run_semgrep, file_patches))
    bandit_task = asyncio.create_task(_run_scanner("bandit", run_bandit, file_patches))
    gitleaks_task = asyncio.create_task(_run_scanner("gitleaks", run_gitleaks, file_patches))
    entropy_task = asyncio.create_task(_run_scanner("entropy", run_entropy_scan, file_patches))
    sca_task = asyncio.create_task(_run_scanner("sca", run_sca, file_patches))

    results = await asyncio.gather(
        semgrep_task, bandit_task, gitleaks_task, entropy_task, sca_task,
        return_exceptions=True,
    )

    all_findings: list[dict] = []
    scanner_errors: dict[str, str] = {}
    has_secret = False

    scanner_names = ["semgrep", "bandit", "gitleaks", "entropy", "sca"]
    for name, result in zip(scanner_names, results):
        if isinstance(result, Exception):
            scanner_errors[name] = str(result)
            log.warning("deterministic.scanner_error", scanner=name, error=str(result))
            continue

        findings, error = result
        if error:
            scanner_errors[name] = error
        all_findings.extend(findings)

        # Check for secrets
        if name in ("gitleaks", "entropy"):
            if any(f.get("severity") in ("critical", "high") for f in findings):
                has_secret = True

    # Deduplicate by fingerprint
    seen: set[str] = set()
    deduped: list[dict] = []
    for finding in all_findings:
        fp = finding.get("fingerprint", id(finding))
        if fp not in seen:
            seen.add(fp)
            deduped.append(finding)

    log.info(
        "deterministic.complete",
        total=len(all_findings),
        deduped=len(deduped),
        has_secret=has_secret,
        errors=list(scanner_errors.keys()),
    )

    return {
        **state,
        "deterministic_findings": deduped,
        "has_secret": has_secret,
        "scanner_errors": scanner_errors,
    }


async def _run_scanner(
    name: str,
    fn,
    file_patches: list[dict] | None = None,
    full_diff: str | None = None,
) -> tuple[list[dict], str | None]:
    """Run a scanner function, returning (findings, error)."""
    import time
    start = time.monotonic()
    try:
        if full_diff is not None:
            findings = await fn(full_diff)
        else:
            findings = await fn(file_patches)
        elapsed = time.monotonic() - start
        SCANNER_DURATION.labels(scanner=name).observe(elapsed)
        return findings, None
    except Exception as exc:
        elapsed = time.monotonic() - start
        SCANNER_DURATION.labels(scanner=name).observe(elapsed)
        return [], str(exc)
