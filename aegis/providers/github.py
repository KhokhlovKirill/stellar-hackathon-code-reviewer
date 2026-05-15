"""GitHub provider — webhook parse + diff fetch (Phase 1). Write ops: Phase 6."""

from __future__ import annotations

from typing import Any

from aegis.errors import ProviderError, WebhookPayloadError
from aegis.providers.base import HttpMixin
from aegis.providers.diffparse import parse_unified_diff
from aegis.schemas import (
    DiscussionThread,
    EventKind,
    FileChange,
    MergePolicyDecision,
    Provider,
    PullRequest,
    ReviewComment,
    WebhookEvent,
)

_PR_OPENED = {"opened", "reopened", "ready_for_review"}
_PR_UPDATED = {"synchronize", "edited"}


class GitHubProvider(HttpMixin):
    provider = Provider.GITHUB
    base_url = "https://api.github.com"

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def parse_event(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent:
        event = headers.get("x-github-event", "")
        delivery = headers.get("x-github-delivery", "")
        repo = payload.get("repository", {})
        slug = repo.get("full_name", "")
        repo_id = str(repo.get("id", ""))

        if event == "pull_request":
            action = payload.get("action", "")
            pr = payload.get("pull_request", {})
            if action in _PR_OPENED:
                kind = EventKind.PR_OPENED
            elif action in _PR_UPDATED:
                kind = EventKind.PR_UPDATED
            else:
                kind = EventKind.IGNORED
            return WebhookEvent(
                provider=self.provider, kind=kind, delivery_id=delivery,
                repo_slug=slug, repo_external_id=repo_id,
                pr_id=str(pr.get("number", "")), pr_number=pr.get("number"),
                base_sha=pr.get("base", {}).get("sha"),
                head_sha=pr.get("head", {}).get("sha"),
                title=pr.get("title", ""), actor=payload.get("sender", {}).get("login", ""),
            )

        if event in ("issue_comment", "pull_request_review_comment"):
            if payload.get("action") != "created":
                return self._ignored(delivery, slug, repo_id)
            comment = payload.get("comment", {})
            issue = payload.get("issue", payload.get("pull_request", {}))
            pr_num = issue.get("number") or payload.get("pull_request", {}).get("number")
            return WebhookEvent(
                provider=self.provider, kind=EventKind.COMMENT, delivery_id=delivery,
                repo_slug=slug, repo_external_id=repo_id, pr_id=str(pr_num or ""),
                pr_number=pr_num, actor=comment.get("user", {}).get("login", ""),
                comment_id=str(comment.get("id", "")),
                comment_body=comment.get("body", ""),
                in_reply_to_id=str(comment.get("in_reply_to_id", "") or ""),
                thread_id=str(comment.get("in_reply_to_id") or comment.get("id", "")),
            )

        if event == "ping":
            return self._ignored(delivery, slug, repo_id)
        raise WebhookPayloadError(f"unhandled github event '{event}'")

    def _ignored(self, delivery: str, slug: str, repo_id: str) -> WebhookEvent:
        return WebhookEvent(
            provider=self.provider, kind=EventKind.IGNORED, delivery_id=delivery,
            repo_slug=slug, repo_external_id=repo_id, pr_id="",
        )

    async def fetch_pull_request(self, ev: WebhookEvent, token: str) -> PullRequest:
        r = await self._request(
            "GET", f"/repos/{ev.repo_slug}/pulls/{ev.pr_id}", token, "get_pr"
        )
        if r.status_code != 200:
            raise ProviderError("github", "get_pr failed", r.status_code)
        d = r.json()
        return PullRequest(
            provider=self.provider, repo_slug=ev.repo_slug,
            repo_external_id=ev.repo_external_id, pr_id=ev.pr_id,
            pr_number=ev.pr_number, title=d.get("title", ""),
            base_sha=d["base"]["sha"], head_sha=d["head"]["sha"],
            base_ref=d["base"]["ref"], head_ref=d["head"]["ref"],
            author=d.get("user", {}).get("login", ""),
        )

    async def fetch_diff(self, pr: PullRequest, token: str) -> list[FileChange]:
        # Raw unified diff — only the changed hunks, never the whole repo (C2).
        r = await self._request(
            "GET", f"/repos/{pr.repo_slug}/pulls/{pr.pr_id}", token, "get_diff",
            headers={"Accept": "application/vnd.github.diff"},
        )
        if r.status_code != 200:
            raise ProviderError("github", "get_diff failed", r.status_code)
        return parse_unified_diff(r.text)

    async def fetch_file(self, pr: PullRequest, token: str, path: str) -> str | None:
        r = await self._request(
            "GET", f"/repos/{pr.repo_slug}/contents/{path}", token, "get_file",
            params={"ref": pr.head_sha},
            headers={"Accept": "application/vnd.github.raw+json"},
        )
        return r.text if r.status_code == 200 else None

    # ---- Phase 6 write ops ----
    async def post_inline_comment(self, pr: PullRequest, token: str, c: ReviewComment) -> str:
        raise NotImplementedError("github.post_inline_comment — Phase 6")

    async def post_summary(self, pr: PullRequest, token: str, body: str) -> str:
        raise NotImplementedError("github.post_summary — Phase 6")

    async def reply_in_thread(self, pr: PullRequest, token: str, thread_id: str, body: str) -> str:
        raise NotImplementedError("github.reply_in_thread — Phase 7")

    async def set_status_check(
        self, pr: PullRequest, token: str, decision: MergePolicyDecision, url: str
    ) -> None:
        raise NotImplementedError("github.set_status_check — Phase 6")

    async def request_changes(self, pr: PullRequest, token: str, body: str) -> None:
        raise NotImplementedError("github.request_changes — Phase 6")

    async def get_thread(self, pr: PullRequest, token: str, thread_id: str) -> DiscussionThread:
        raise NotImplementedError("github.get_thread — Phase 7")
