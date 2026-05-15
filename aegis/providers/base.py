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
