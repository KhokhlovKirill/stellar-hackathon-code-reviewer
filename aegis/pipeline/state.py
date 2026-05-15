"""PipelineState — the mutable context threaded through every pipeline stage.

Each stage reads what earlier stages produced and appends its own output. This is
the stable contract between the orchestrator and stages (docs/03 §3).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.repos import RepoContext
from aegis.schemas import FileChange, Finding, PullRequest, ScanResult, WebhookEvent


@dataclass(slots=True)
class PipelineState:
    scan_id: str
    ev: WebhookEvent
    pr: PullRequest
    ctx: RepoContext
    result: ScanResult
    files: list[FileChange]                              # all changed files
    code_files: list[FileChange] = field(default_factory=list)      # kept for analysis
    manifest_files: list[FileChange] = field(default_factory=list)   # dependency manifests
    findings: list[Finding] = field(default_factory=list)            # accumulates
    posted_refs: list[str] = field(default_factory=list)             # VCS comment ids
