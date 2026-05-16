"""GitLab provider — webhook parse + diff fetch (Phase 1). Write ops: Phase 6."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from aegis.errors import ProviderError, WebhookPayloadError
from aegis.providers.base import HttpMixin
from aegis.providers.diffparse import language_of
from aegis.schemas import (
    DiffLine,
    DiscussionThread,
    EventKind,
    FileChange,
    Hunk,
    LineKind,
    MergePolicyDecision,
    Provider,
    PullRequest,
    ReviewComment,
    WebhookEvent,
)

_MR_OPENED = {"open", "reopen"}
_MR_UPDATED = {"update"}


class GitLabProvider(HttpMixin):
    provider = Provider.GITLAB

    @property
    def base_url(self) -> str:  # type: ignore[override]
        """Default GitLab API v4 base (GITLAB_BASE_URL setting, else gitlab.com).

        This is only the *fallback*. The actual instance for a given scan is
        resolved per-call from the carried `instance_api_base` (see `_root`);
        we deliberately keep no mutable per-instance override because the
        provider is a process-wide singleton shared by concurrent scans.
        """
        return self._default_root()

    @staticmethod
    def _default_root() -> str:
        from aegis.config import get_settings

        root = (get_settings().gitlab_base_url or "https://gitlab.com").rstrip("/")
        return f"{root}/api/v4"

    def _root(self, carried: str | None) -> str:
        """API root for this call: the instance that sent the webhook (carried
        on the event/PR) takes precedence over the global default.

        The scheme from the webhook payload is preserved as-is. We do NOT
        force https here: some self-hosted instances serve a TLS certificate
        that does not match their own hostname and instead 301-redirect
        http→https to a cert-valid canonical host. Forcing https on the literal
        host would fail certificate verification and break every call;
        following the server's own redirect (httpx `follow_redirects=True`)
        lands on the host its certificate is actually valid for."""
        return (carried or self._default_root()).rstrip("/")

    def _url(self, carried: str | None, path: str) -> str:
        """Absolute API URL so request routing never depends on shared state."""
        return f"{self._root(carried)}{path}"

    @staticmethod
    def _api_base_from_web_url(web_url: str) -> str | None:
        """Derive `<scheme>://<host>/api/v4` from a project web URL in a payload.

        The scheme is preserved from the payload. Some self-hosted GitLab
        instances present a certificate that does not match their own
        hostname and 301-redirect http→https to a cert-valid host; forcing
        https on the literal host would fail TLS verification. Following the
        server's redirect (httpx `follow_redirects=True`) is correct here.
        """
        m = re.match(r"^(https?)://([^/]+)", web_url or "")
        return f"{m.group(1)}://{m.group(2)}/api/v4" if m else None

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"PRIVATE-TOKEN": token}

    def parse_event(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent:
        kind_hdr = headers.get("x-gitlab-event", "")
        delivery = headers.get("x-gitlab-event-uuid", "")
        project = payload.get("project", {})
        slug = project.get("path_with_namespace", "")
        repo_id = str(project.get("id", ""))

        # Auto-target the GitLab instance that sent the webhook (handles
        # self-hosted instances without per-deploy config). Carried on the
        # event so the worker reconstructs the right host after the queue
        # round-trip; falls back to the GITLAB_BASE_URL setting otherwise.
        web_url = project.get("web_url") or payload.get("repository", {}).get("homepage", "")
        api_base = self._api_base_from_web_url(web_url)

        if kind_hdr == "Merge Request Hook":
            attrs = payload.get("object_attributes", {})
            action = attrs.get("action", "")
            if action in _MR_OPENED:
                kind = EventKind.PR_OPENED
            elif action in _MR_UPDATED:
                kind = EventKind.PR_UPDATED
            else:
                kind = EventKind.IGNORED
            return WebhookEvent(
                provider=self.provider, kind=kind, delivery_id=delivery,
                repo_slug=slug, repo_external_id=repo_id,
                pr_id=str(attrs.get("iid", "")), pr_number=attrs.get("iid"),
                base_sha=(attrs.get("diff_refs") or {}).get("base_sha"),
                head_sha=(attrs.get("diff_refs") or {}).get("head_sha")
                or attrs.get("last_commit", {}).get("id"),
                title=attrs.get("title", ""),
                actor=payload.get("user", {}).get("username", ""),
                instance_api_base=api_base,
            )

        if kind_hdr == "Note Hook":
            note = payload.get("object_attributes", {})
            if note.get("noteable_type") != "MergeRequest":
                return self._ignored(delivery, slug, repo_id, api_base)
            mr = payload.get("merge_request", {})
            return WebhookEvent(
                provider=self.provider, kind=EventKind.COMMENT, delivery_id=delivery,
                repo_slug=slug, repo_external_id=repo_id,
                pr_id=str(mr.get("iid", "")), pr_number=mr.get("iid"),
                actor=payload.get("user", {}).get("username", ""),
                comment_id=str(note.get("id", "")), comment_body=note.get("note", ""),
                thread_id=str(note.get("discussion_id") or note.get("id", "")),
                instance_api_base=api_base,
            )
        raise WebhookPayloadError(f"unhandled gitlab event '{kind_hdr}'")

    def _ignored(
        self, delivery: str, slug: str, repo_id: str, api_base: str | None = None
    ) -> WebhookEvent:
        return WebhookEvent(
            provider=self.provider, kind=EventKind.IGNORED, delivery_id=delivery,
            repo_slug=slug, repo_external_id=repo_id, pr_id="",
            instance_api_base=api_base,
        )

    def _pid(self, pr: PullRequest) -> str:
        return quote(pr.repo_slug, safe="") if pr.repo_slug else pr.repo_external_id

    @staticmethod
    def _created_id(resp: Any) -> str:
        """Extract the created object's id from a create response.

        GitLab create endpoints return a JSON object. If a misconfigured
        instance redirects and the body comes back as a list (e.g. a GET on a
        collection), don't blow up with "'list' object has no attribute
        'get'" — just return an empty ref. The comment/summary was still
        delivered; only our local bookkeeping ref is unknown.
        """
        try:
            body = resp.json()
        except Exception:
            return ""
        return str(body.get("id", "")) if isinstance(body, dict) else ""

    async def fetch_pull_request(self, ev: WebhookEvent, token: str) -> PullRequest:
        pid = quote(ev.repo_slug, safe="") if ev.repo_slug else ev.repo_external_id
        r = await self._request(
            "GET",
            self._url(ev.instance_api_base, f"/projects/{pid}/merge_requests/{ev.pr_id}"),
            token, "get_pr",
        )
        if r.status_code != 200:
            raise ProviderError("gitlab", "get_pr failed", r.status_code)
        d = r.json()
        refs = d.get("diff_refs") or {}
        return PullRequest(
            provider=self.provider, repo_slug=ev.repo_slug,
            repo_external_id=ev.repo_external_id, pr_id=ev.pr_id,
            pr_number=ev.pr_number, title=d.get("title", ""),
            base_sha=refs.get("base_sha") or d.get("sha", ""),
            head_sha=refs.get("head_sha") or d.get("sha", ""),
            base_ref=d.get("target_branch", ""), head_ref=d.get("source_branch", ""),
            author=d.get("author", {}).get("username", ""),
            instance_api_base=ev.instance_api_base,
        )

    async def fetch_diff(self, pr: PullRequest, token: str) -> list[FileChange]:
        # GitLab returns structured per-file diffs (already changed-only) — C2.
        r = await self._request(
            "GET",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}/changes",
            ),
            token, "get_diff",
        )
        if r.status_code != 200:
            raise ProviderError("gitlab", "get_diff failed", r.status_code)
        out: list[FileChange] = []
        for ch in r.json().get("changes", []):
            status = (
                "added" if ch.get("new_file") else
                "deleted" if ch.get("deleted_file") else
                "renamed" if ch.get("renamed_file") else "modified"
            )
            path = ch.get("new_path") or ch.get("old_path")
            hunks = _parse_gitlab_diff(ch.get("diff", ""))
            out.append(
                FileChange(
                    path=path, old_path=ch.get("old_path"), status=status,
                    is_binary=False, language=language_of(path), hunks=hunks,
                )
            )
        return out

    async def fetch_file(self, pr: PullRequest, token: str, path: str) -> str | None:
        from urllib.parse import quote as _q

        r = await self._request(
            "GET",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/repository/files/{_q(path, safe='')}/raw",
            ),
            token, "get_file", params={"ref": pr.head_sha},
        )
        return r.text if r.status_code == 200 else None

    async def post_inline_comment(self, pr: PullRequest, token: str, c: ReviewComment) -> str:
        payload: dict[str, object] = {"body": c.body}
        if c.line > 0:
            payload["position"] = {
                "position_type": "text",
                "base_sha": pr.base_sha,
                "start_sha": pr.base_sha,
                "head_sha": pr.head_sha,
                "new_path": c.file,
                "new_line": c.line,
            }
        r = await self._request(
            "POST",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}/discussions",
            ),
            token,
            "post_inline_comment",
            json=payload,
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "post_inline_comment failed", r.status_code)
        return self._created_id(r)

    async def post_summary(self, pr: PullRequest, token: str, body: str) -> str:
        r = await self._request(
            "POST",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}/notes",
            ),
            token,
            "post_summary",
            json={"body": body},
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "post_summary failed", r.status_code)
        return self._created_id(r)

    async def reply_in_thread(self, pr: PullRequest, token: str, thread_id: str, body: str) -> str:
        r = await self._request(
            "POST",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}"
                f"/discussions/{thread_id}/notes",
            ),
            token,
            "reply_in_thread",
            json={"body": body},
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "reply_in_thread failed", r.status_code)
        return self._created_id(r)

    async def set_status_check(
        self, pr: PullRequest, token: str, decision: MergePolicyDecision, url: str
    ) -> None:
        payload = {
            "state": "failed" if decision.state == "failure" else decision.state,
            "name": decision.context,
            "target_url": url,
            "description": decision.reason[:255],
        }
        r = await self._request(
            "POST",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/statuses/{pr.head_sha}",
            ),
            token,
            "set_status_check",
            json=payload,
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "set_status_check failed", r.status_code)

    async def request_changes(self, pr: PullRequest, token: str, body: str) -> None:
        await self.post_summary(pr, token, f"**Aegis requests changes**\n\n{body}")

    async def get_thread(self, pr: PullRequest, token: str, thread_id: str) -> DiscussionThread:
        r = await self._request(
            "GET",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}"
                f"/discussions/{thread_id}",
            ),
            token,
            "get_thread",
        )
        if r.status_code != 200:
            raise ProviderError("gitlab", "get_thread failed", r.status_code)
        d = r.json()
        return DiscussionThread(thread_id=thread_id, pr_id=pr.pr_id, comments=d.get("notes", []))

    async def get_default_branch(self, pr: PullRequest, token: str) -> str:
        r = await self._request(
            "GET",
            self._url(pr.instance_api_base, f"/projects/{self._pid(pr)}"),
            token, "get_repo",
        )
        if r.status_code != 200:
            raise ProviderError("gitlab", "get_repo failed", r.status_code)
        return str(r.json().get("default_branch", "main"))

    async def create_branch(
        self, pr: PullRequest, token: str, new_branch: str, from_sha: str
    ) -> None:
        from urllib.parse import quote as _q
        r = await self._request(
            "POST",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/repository/branches",
            ),
            token,
            "create_branch",
            json={"branch": new_branch, "ref": from_sha},
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "create_branch failed", r.status_code)
        _ = _q  # imported for future use

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
        from urllib.parse import quote as _q
        encoded = _q(path, safe="")
        # Try create first; if 400 (already exists) use PUT to update.
        payload = {
            "branch": branch,
            "content": content_b64,
            "commit_message": message,
            "encoding": "base64",
        }
        r = await self._request(
            "POST",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/repository/files/{encoded}",
            ),
            token,
            "create_file",
            json=payload,
        )
        if r.status_code in (200, 201):
            return
        r = await self._request(
            "PUT",
            self._url(
                pr.instance_api_base,
                f"/projects/{self._pid(pr)}/repository/files/{encoded}",
            ),
            token,
            "update_file",
            json=payload,
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "create_or_update_file failed", r.status_code)

    async def open_pull_request(
        self,
        token: str,
        repo_slug: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str,
    ) -> str:
        pid = quote(repo_slug, safe="")
        r = await self._request(
            "POST",
            f"/projects/{pid}/merge_requests",
            token,
            "open_pull_request",
            json={
                "title": title,
                "description": body,
                "source_branch": head_branch,
                "target_branch": base_branch,
            },
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "open_pull_request failed", r.status_code)
        return str(r.json().get("web_url", ""))


def _parse_gitlab_diff(diff: str) -> list[Hunk]:
    """Parse a single-file GitLab diff body (no ---/+++ header) into Hunks with
    right-side line numbers and per-file positions."""
    hunks: list[Hunk] = []
    pos = 0
    cur: Hunk | None = None
    new_ln = old_ln = 0
    for raw in diff.splitlines():
        if raw.startswith("@@"):
            pos += 1
            seg = raw.split("@@")[1].strip()  # -a,b +c,d
            minus, plus = seg.split(" ")
            old_start = int(minus[1:].split(",")[0])
            new_start = int(plus[1:].split(",")[0])
            old_ln, new_ln = old_start, new_start
            cur = Hunk(
                old_start=old_start, old_count=0, new_start=new_start,
                new_count=0, header=raw, lines=[],
            )
            hunks.append(cur)
            continue
        if cur is None:
            continue
        pos += 1
        if raw.startswith("+"):
            cur.lines.append(
                DiffLine(kind=LineKind.ADD, content=raw[1:], new_lineno=new_ln,
                         old_lineno=None, diff_position=pos)
            )
            new_ln += 1
        elif raw.startswith("-"):
            cur.lines.append(
                DiffLine(kind=LineKind.DEL, content=raw[1:], new_lineno=None,
                         old_lineno=old_ln, diff_position=pos)
            )
            old_ln += 1
        else:
            cur.lines.append(
                DiffLine(kind=LineKind.CTX, content=raw[1:] if raw else "",
                         new_lineno=new_ln, old_lineno=old_ln, diff_position=pos)
            )
            new_ln += 1
            old_ln += 1
    return hunks
