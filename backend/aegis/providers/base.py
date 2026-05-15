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

    # Autofix-PR surface (implemented per provider; used by aegis.pipeline.autofix).
    async def get_default_branch(self, pr: PullRequest, token: str) -> str: ...

    async def create_branch(
        self, pr: PullRequest, token: str, new_branch: str, from_sha: str
    ) -> None: ...

    async def create_or_update_file(
        self,
        pr: PullRequest,
        token: str,
        branch: str,
        path: str,
        content_b64: str,
        message: str,
        sha: str | None = None,
    ) -> None: ...

    async def open_pull_request(
        self,
        token: str,
        repo_slug: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str,
    ) -> str: ...


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
