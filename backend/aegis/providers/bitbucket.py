"""Bitbucket Cloud provider — webhook parse + diff fetch (Phase 1). Write ops: Phase 6.

Auth: workspace access token / app password as Bearer. The /diff endpoint returns a
raw unified diff (changed-only), reused via the shared parser.
"""

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


class BitbucketProvider(HttpMixin):
    provider = Provider.BITBUCKET
    base_url = "https://api.bitbucket.org/2.0"

    def parse_event(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent:
        key = headers.get("x-event-key", "")
        delivery = headers.get("x-request-id", "") or headers.get("x-hook-uuid", "")
        repo = payload.get("repository", {})
        slug = repo.get("full_name", "")
        repo_id = str(repo.get("uuid", "") or slug)
        pr = payload.get("pullrequest", {})

        if key in ("pullrequest:created",):
            kind = EventKind.PR_OPENED
        elif key in ("pullrequest:updated",):
            kind = EventKind.PR_UPDATED
        elif key in ("pullrequest:comment_created",):
            comment = payload.get("comment", {})
            return WebhookEvent(
                provider=self.provider, kind=EventKind.COMMENT, delivery_id=delivery,
                repo_slug=slug, repo_external_id=repo_id,
                pr_id=str(pr.get("id", "")), pr_number=pr.get("id"),
                actor=payload.get("actor", {}).get("nickname", ""),
                comment_id=str(comment.get("id", "")),
                comment_body=comment.get("content", {}).get("raw", ""),
                in_reply_to_id=str((comment.get("parent") or {}).get("id", "") or ""),
                thread_id=str((comment.get("parent") or {}).get("id") or comment.get("id", "")),
            )
        else:
            raise WebhookPayloadError(f"unhandled bitbucket event '{key}'")

        src = pr.get("source", {})
        dst = pr.get("destination", {})
        return WebhookEvent(
            provider=self.provider, kind=kind, delivery_id=delivery,
            repo_slug=slug, repo_external_id=repo_id,
            pr_id=str(pr.get("id", "")), pr_number=pr.get("id"),
            base_sha=dst.get("commit", {}).get("hash"),
            head_sha=src.get("commit", {}).get("hash"),
            title=pr.get("title", ""),
            actor=payload.get("actor", {}).get("nickname", ""),
        )

    async def fetch_pull_request(self, ev: WebhookEvent, token: str) -> PullRequest:
        r = await self._request(
            "GET", f"/repositories/{ev.repo_slug}/pullrequests/{ev.pr_id}", token, "get_pr"
        )
        if r.status_code != 200:
            raise ProviderError("bitbucket", "get_pr failed", r.status_code)
        d = r.json()
        return PullRequest(
            provider=self.provider, repo_slug=ev.repo_slug,
            repo_external_id=ev.repo_external_id, pr_id=ev.pr_id,
            pr_number=ev.pr_number, title=d.get("title", ""),
            base_sha=d.get("destination", {}).get("commit", {}).get("hash", ""),
            head_sha=d.get("source", {}).get("commit", {}).get("hash", ""),
            base_ref=d.get("destination", {}).get("branch", {}).get("name", ""),
            head_ref=d.get("source", {}).get("branch", {}).get("name", ""),
            author=d.get("author", {}).get("nickname", ""),
        )

    async def fetch_diff(self, pr: PullRequest, token: str) -> list[FileChange]:
        r = await self._request(
            "GET", f"/repositories/{pr.repo_slug}/pullrequests/{pr.pr_id}/diff",
            token, "get_diff",
        )
        if r.status_code != 200:
            raise ProviderError("bitbucket", "get_diff failed", r.status_code)
        return parse_unified_diff(r.text)

    async def fetch_file(self, pr: PullRequest, token: str, path: str) -> str | None:
        r = await self._request(
            "GET", f"/repositories/{pr.repo_slug}/src/{pr.head_sha}/{path}",
            token, "get_file",
        )
        return r.text if r.status_code == 200 else None

    async def post_inline_comment(self, pr: PullRequest, token: str, c: ReviewComment) -> str:
        payload: dict[str, object] = {"content": {"raw": c.body}}
        if c.line > 0:
            payload["inline"] = {"path": c.file, "to": c.line}
        r = await self._request(
            "POST",
            f"/repositories/{pr.repo_slug}/pullrequests/{pr.pr_id}/comments",
            token,
            "post_inline_comment",
            json=payload,
        )
        if r.status_code not in (200, 201):
            raise ProviderError("bitbucket", "post_inline_comment failed", r.status_code)
        return str(r.json().get("id", ""))

    async def post_summary(self, pr: PullRequest, token: str, body: str) -> str:
        r = await self._request(
            "POST",
            f"/repositories/{pr.repo_slug}/pullrequests/{pr.pr_id}/comments",
            token,
            "post_summary",
            json={"content": {"raw": body}},
        )
        if r.status_code not in (200, 201):
            raise ProviderError("bitbucket", "post_summary failed", r.status_code)
        return str(r.json().get("id", ""))

    async def reply_in_thread(self, pr: PullRequest, token: str, thread_id: str, body: str) -> str:
        r = await self._request(
            "POST",
            f"/repositories/{pr.repo_slug}/pullrequests/{pr.pr_id}/comments",
            token,
            "reply_in_thread",
            json={"content": {"raw": body}, "parent": {"id": int(thread_id)}},
        )
        if r.status_code not in (200, 201):
            raise ProviderError("bitbucket", "reply_in_thread failed", r.status_code)
        return str(r.json().get("id", ""))

    async def set_status_check(
        self, pr: PullRequest, token: str, decision: MergePolicyDecision, url: str
    ) -> None:
        payload = {
            "state": "FAILED" if decision.state == "failure" else "SUCCESSFUL",
            "key": "aegis-security",
            "name": decision.context,
            "url": url,
            "description": decision.reason[:255],
        }
        r = await self._request(
            "POST",
            f"/repositories/{pr.repo_slug}/commit/{pr.head_sha}/statuses/build",
            token,
            "set_status_check",
            json=payload,
        )
        if r.status_code not in (200, 201):
            raise ProviderError("bitbucket", "set_status_check failed", r.status_code)

    async def request_changes(self, pr: PullRequest, token: str, body: str) -> None:
        await self.post_summary(pr, token, f"**Aegis requests changes**\n\n{body}")

    async def get_thread(self, pr: PullRequest, token: str, thread_id: str) -> DiscussionThread:
        r = await self._request(
            "GET",
            f"/repositories/{pr.repo_slug}/pullrequests/{pr.pr_id}/comments/{thread_id}",
            token,
            "get_thread",
        )
        if r.status_code != 200:
            raise ProviderError("bitbucket", "get_thread failed", r.status_code)
        d = r.json()
        return DiscussionThread(thread_id=thread_id, pr_id=pr.pr_id, comments=[d])

    async def get_default_branch(self, pr: PullRequest, token: str) -> str:
        r = await self._request(
            "GET", f"/repositories/{pr.repo_slug}", token, "get_repo"
        )
        if r.status_code != 200:
            raise ProviderError("bitbucket", "get_repo failed", r.status_code)
        return str(r.json().get("mainbranch", {}).get("name", "main"))

    async def create_branch(
        self, pr: PullRequest, token: str, new_branch: str, from_sha: str
    ) -> None:
        r = await self._request(
            "POST",
            f"/repositories/{pr.repo_slug}/refs/branches",
            token,
            "create_branch",
            json={"name": new_branch, "target": {"hash": from_sha}},
        )
        if r.status_code not in (200, 201):
            raise ProviderError("bitbucket", "create_branch failed", r.status_code)

    async def create_or_update_file(
        self,
        pr: PullRequest,
        token: str,
        branch: str,
        path: str,
        content_b64: str,
        message: str,
        sha: str | None = None,
    ) -> None:
        import base64
        content_bytes = base64.b64decode(content_b64)
        r = await self._request(
            "POST",
            f"/repositories/{pr.repo_slug}/src",
            token,
            "create_or_update_file",
            data={
                path: content_bytes.decode(),
                "message": message,
                "branch": branch,
            },
        )
        if r.status_code not in (200, 201):
            raise ProviderError("bitbucket", "create_or_update_file failed", r.status_code)

    async def open_pull_request(
        self,
        token: str,
        repo_slug: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str,
    ) -> str:
        r = await self._request(
            "POST",
            f"/repositories/{repo_slug}/pullrequests",
            token,
            "open_pull_request",
            json={
                "title": title,
                "description": body,
                "source": {"branch": {"name": head_branch}},
                "destination": {"branch": {"name": base_branch}},
            },
        )
        if r.status_code not in (200, 201):
            raise ProviderError("bitbucket", "open_pull_request failed", r.status_code)
        return str(r.json().get("links", {}).get("html", {}).get("href", ""))
