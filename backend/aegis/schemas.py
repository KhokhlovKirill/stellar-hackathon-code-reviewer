"""Normalized domain models shared by every provider and pipeline stage.

The provider layer translates GitHub/GitLab/Bitbucket payloads into these; nothing
downstream knows which VCS it is talking to.
"""

from __future__ import annotations

import enum
import hashlib
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Provider(enum.StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"


class EventKind(enum.StrEnum):
    PR_OPENED = "pr_opened"          # opened / reopened / ready_for_review
    PR_UPDATED = "pr_updated"        # synchronize / new commits
    COMMENT = "comment"              # reply in a thread (dialog, C7)
    IGNORED = "ignored"              # known but not actionable


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class FindingSource(enum.StrEnum):
    DETERMINISTIC = "deterministic"   # semgrep / secrets / sca — confidence ~0.98
    LLM_A = "llm_a"                   # don-agent-v3
    LLM_B = "llm_b"                   # generalist
    JUDGE = "judge"                   # consolidated/arbitrated


class LineKind(enum.StrEnum):
    ADD = "add"
    DEL = "del"
    CTX = "ctx"


class DiffLine(BaseModel):
    kind: LineKind
    content: str
    new_lineno: int | None = None     # line number on the RIGHT (new) side
    old_lineno: int | None = None
    diff_position: int | None = None  # offset within the file diff (GitHub position API)


class Hunk(BaseModel):
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    lines: list[DiffLine]


class FileChange(BaseModel):
    path: str
    old_path: str | None = None
    status: str                        # added | modified | renamed | deleted
    is_binary: bool = False
    language: str | None = None
    hunks: list[Hunk] = Field(default_factory=list)

    def added_lines(self) -> list[DiffLine]:
        return [ln for h in self.hunks for ln in h.lines if ln.kind is LineKind.ADD]


class WebhookEvent(BaseModel):
    provider: Provider
    kind: EventKind
    delivery_id: str
    repo_slug: str                     # owner/name or workspace/repo
    repo_external_id: str
    pr_id: str
    pr_number: int | None = None
    base_sha: str | None = None
    head_sha: str | None = None
    title: str = ""
    actor: str = ""
    # comment-event extras (dialog)
    comment_id: str | None = None
    comment_body: str | None = None
    in_reply_to_id: str | None = None
    thread_id: str | None = None
    # Self-hosted GitLab: API base derived from the webhook payload's web_url
    # (e.g. https://git.example.com/api/v4). Carried explicitly so it survives
    # the web→queue→worker boundary instead of relying on shared mutable
    # provider state (which a concurrent scan could clobber).
    instance_api_base: str | None = None

    def dedupe_key(self) -> str:
        basis = ":".join([
            self.provider.value, self.delivery_id, self.repo_external_id,
            self.pr_id, self.head_sha or "",
        ])
        return hashlib.sha256(basis.encode()).hexdigest()


class PullRequest(BaseModel):
    provider: Provider
    repo_slug: str
    repo_external_id: str
    pr_id: str
    pr_number: int | None = None
    title: str = ""
    base_sha: str
    head_sha: str
    base_ref: str = ""
    head_ref: str = ""
    author: str = ""
    # See WebhookEvent.instance_api_base — propagated so every subsequent
    # provider call (diff, comments, status) targets the right GitLab host.
    instance_api_base: str | None = None


class Finding(BaseModel):
    file: str
    line: int                          # new-side line number
    diff_position: int | None = None
    cwe: str | None = None
    rule_id: str | None = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source: FindingSource
    title: str
    rationale: str                     # why exploitable in THIS code path
    exploit: str | None = None         # concrete scenario
    fix: str | None = None             # suggested fix (snippet or instruction)
    fix_is_suggestion: bool = False    # True -> render as one-click suggestion block

    def fingerprint(self) -> str:
        basis = f"{self.file}:{self.line}:{self.cwe or ''}:{self.rule_id or self.title}"
        return hashlib.sha1(basis.encode()).hexdigest()  # noqa: S324  (non-crypto id)


class ReviewComment(BaseModel):
    file: str
    line: int
    diff_position: int | None = None
    body: str
    finding_fingerprint: str


class MergePolicyDecision(BaseModel):
    block: bool
    state: str                         # success | failure | neutral
    context: str = "aegis/security"
    reason: str = ""


class DiscussionThread(BaseModel):
    thread_id: str
    pr_id: str
    comments: list[dict[str, Any]] = Field(default_factory=list)
    finding_fingerprint: str | None = None


class ScanResult(BaseModel):
    scan_id: str
    provider: Provider
    repo_slug: str
    pr_id: str
    head_sha: str
    started_at: datetime
    finished_at: datetime | None = None
    files_scanned: list[str] = Field(default_factory=list)
    files_skipped: list[dict[str, str]] = Field(default_factory=list)   # {path, reason}
    findings: list[Finding] = Field(default_factory=list)
    decision: MergePolicyDecision | None = None
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_label: str = "low"
    degraded: list[str] = Field(default_factory=list)         # e.g. ["local-secure", "judge"]
    est_sent_tokens: int = 0
    est_full_repo_tokens: int = 0
