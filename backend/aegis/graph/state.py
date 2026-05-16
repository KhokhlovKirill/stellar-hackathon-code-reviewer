"""Shared LangGraph state for the Aegis security-review graph.

`ScanGraphState` is a `TypedDict` (LangGraph's native state container). Every
node receives the full state and returns a partial update — LangGraph merges
the partial back in. Fields are populated by the node that produces them; any
node may read everything written upstream.
"""

from __future__ import annotations

from typing import Any, TypedDict

from aegis.schemas import FileChange, Finding


class ScanGraphState(TypedDict, total=False):
    """Full shared state threaded through every node.

    `total=False` so each node only has to return the fields it changes.
    """

    # ── Input ────────────────────────────────────────────────────────────────
    url: str
    token: str | None
    lang: str

    # ── Parsed identifiers ──────────────────────────────────────────────────
    slug: str
    pr_number: int
    pr_title: str
    pr_url: str
    pr_author: str
    head_sha: str

    # ── Diff ─────────────────────────────────────────────────────────────────
    diff_text: str
    all_files: list[FileChange]
    code_files: list[FileChange]
    files_scanned: int
    files_scanned_paths: list[str]

    # ── Findings ─────────────────────────────────────────────────────────────
    det_findings: list[Finding]
    findings: list[Finding]          # final merged + sorted
    degraded_reasons: list[str]

    # ── Review ───────────────────────────────────────────────────────────────
    summary: str
    finding_labels: dict[str, str]

    # ── Control / status ─────────────────────────────────────────────────────
    error: str | None
    skip_llm: bool                   # filter sets this when there are no files
    status: str                      # ok | error
    started_at: str
    finished_at: str

    # ── Trace (per-node duration / status for observability) ────────────────
    trace: list[dict[str, Any]]
