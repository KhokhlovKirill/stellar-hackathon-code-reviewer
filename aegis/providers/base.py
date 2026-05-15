<<<<<<< Updated upstream
"""VCSProvider protocol + a shared authed HTTP helper.

Webhook parsing and diff fetch are implemented now (Phase 1). Comment/status/merge
operations are declared here and implemented in Phase 6; calling them before then
raises a clear NotImplementedError naming the phase, never a silent failure.
"""

from __future__ import annotations

import time
from typing import Any, Protocol

import httpx

from aegis.obs import get_logger, metrics
from aegis.schemas import (
    DiscussionThread,
    FileChange,
    MergePolicyDecision,
    Provider,
    PullRequest,
    ReviewComment,
    WebhookEvent,
)

log = get_logger("aegis.providers")


class VCSProvider(Protocol):
    provider: Provider

    def parse_event(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent: ...

    async def fetch_pull_request(self, ev: WebhookEvent, token: str) -> PullRequest: ...

    async def fetch_diff(self, pr: PullRequest, token: str) -> list[FileChange]: ...

    async def fetch_file(self, pr: PullRequest, token: str, path: str) -> str | None: ...

    async def post_inline_comment(
        self, pr: PullRequest, token: str, c: ReviewComment
    ) -> str: ...

    async def post_summary(self, pr: PullRequest, token: str, body: str) -> str: ...

    async def reply_in_thread(
        self, pr: PullRequest, token: str, thread_id: str, body: str
    ) -> str: ...

    async def set_status_check(
        self, pr: PullRequest, token: str, decision: MergePolicyDecision, url: str
    ) -> None: ...

    async def request_changes(self, pr: PullRequest, token: str, body: str) -> None: ...

    async def get_thread(
        self, pr: PullRequest, token: str, thread_id: str
    ) -> DiscussionThread: ...


class HttpMixin:
    """Authed httpx client with VCS-call metrics + audit logging."""

    provider: Provider
    base_url: str

    def _auth_headers(self, token: str) -> dict[str, str]:  # overridden per provider
        return {"Authorization": f"Bearer {token}"}

    async def _request(
        self,
        method: str,
        url: str,
        token: str,
        op: str,
        *,
        scan_id: str | None = None,
        **kw: Any,
    ) -> httpx.Response:
        full = url if url.startswith("http") else f"{self.base_url}{url}"
        headers = {**self._auth_headers(token), **kw.pop("headers", {})}
        t0 = time.monotonic()
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.request(method, full, headers=headers, **kw)
        dt = int((time.monotonic() - t0) * 1000)
        metrics.vcs_calls_total.labels(self.provider.value, op, str(resp.status_code)).inc()
        log.info(
            "vcs.call", provider=self.provider.value, op=op,
            code=resp.status_code, latency_ms=dt, scan_id=scan_id,
        )
        return resp
=======
"""Abstract base class for Git provider integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DiffFile:
    """Represents one changed file in a PR diff."""

    filename: str
    status: str  # added | modified | removed | renamed
    patch: str  # raw unified diff patch
    additions: int = 0
    deletions: int = 0
    raw_url: str | None = None
    blob_url: str | None = None
    sha: str | None = None
    language: str | None = None


@dataclass
class PRMetadata:
    """Normalised PR/MR metadata from any provider."""

    pr_number: int
    title: str
    author: str
    body: str
    base_branch: str
    head_branch: str
    head_sha: str
    url: str
    provider: str
    repo_slug: str
    is_draft: bool = False
    labels: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


class BaseProvider(ABC):
    """Common interface every VCS provider must implement."""

    def __init__(self, token: str, repo_slug: str) -> None:
        self.token = token
        self.repo_slug = repo_slug

    # ── Read operations ───────────────────────────────────────────────────────

    @abstractmethod
    async def fetch_pr_metadata(self, pr_number: int) -> PRMetadata:
        """Return normalised PR metadata."""

    @abstractmethod
    async def fetch_diff(self, pr_number: int) -> list[DiffFile]:
        """Return list of changed files with their patches."""

    @abstractmethod
    async def fetch_file_content(self, path: str, ref: str) -> str:
        """Return raw file content at given ref (for context enrichment)."""

    @abstractmethod
    async def fetch_file_lines(self, path: str, ref: str, start: int, end: int) -> str:
        """Return specific line range of a file for Smart Context Window."""

    # ── Write operations ──────────────────────────────────────────────────────

    @abstractmethod
    async def publish_inline_comment(
        self,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        body: str,
    ) -> str:
        """Post an inline review comment and return its ID."""

    @abstractmethod
    async def publish_pr_comment(self, pr_number: int, body: str) -> str:
        """Post a general PR comment and return its ID."""

    @abstractmethod
    async def update_pr_comment(self, comment_id: str, body: str) -> None:
        """Edit an existing PR comment."""

    @abstractmethod
    async def set_status_check(
        self,
        commit_sha: str,
        state: str,  # success | failure | pending | error
        description: str,
        context: str = "aegis/security-review",
    ) -> None:
        """Set a commit status check (blocks or unblocks merge)."""

    @abstractmethod
    async def create_fix_pr(
        self,
        base_branch: str,
        head_branch: str,
        title: str,
        body: str,
        files: dict[str, str],  # path → new content
    ) -> str:
        """Create a new PR with the autofix changes and return the PR URL."""

    @abstractmethod
    async def register_webhook(self, target_url: str, secret: str, events: list[str]) -> dict:
        """Register a webhook on the repository."""

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _redact_secret(self) -> str:
        """Return a redacted token string for logging."""
        if len(self.token) > 8:
            return f"{self.token[:4]}...{self.token[-4:]}"
        return "****"
>>>>>>> Stashed changes
