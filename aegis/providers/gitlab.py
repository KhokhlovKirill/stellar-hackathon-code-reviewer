<<<<<<< Updated upstream
"""GitLab provider — webhook parse + diff fetch (Phase 1). Write ops: Phase 6."""

from __future__ import annotations

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
    base_url = "https://gitlab.com/api/v4"

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"PRIVATE-TOKEN": token}

    def parse_event(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent:
        kind_hdr = headers.get("x-gitlab-event", "")
        delivery = headers.get("x-gitlab-event-uuid", "")
        project = payload.get("project", {})
        slug = project.get("path_with_namespace", "")
        repo_id = str(project.get("id", ""))

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
            )

        if kind_hdr == "Note Hook":
            note = payload.get("object_attributes", {})
            if note.get("noteable_type") != "MergeRequest":
                return self._ignored(delivery, slug, repo_id)
            mr = payload.get("merge_request", {})
            return WebhookEvent(
                provider=self.provider, kind=EventKind.COMMENT, delivery_id=delivery,
                repo_slug=slug, repo_external_id=repo_id,
                pr_id=str(mr.get("iid", "")), pr_number=mr.get("iid"),
                actor=payload.get("user", {}).get("username", ""),
                comment_id=str(note.get("id", "")), comment_body=note.get("note", ""),
                thread_id=str(note.get("discussion_id") or note.get("id", "")),
            )
        raise WebhookPayloadError(f"unhandled gitlab event '{kind_hdr}'")

    def _ignored(self, delivery: str, slug: str, repo_id: str) -> WebhookEvent:
        return WebhookEvent(
            provider=self.provider, kind=EventKind.IGNORED, delivery_id=delivery,
            repo_slug=slug, repo_external_id=repo_id, pr_id="",
        )

    def _pid(self, pr: PullRequest) -> str:
        return quote(pr.repo_slug, safe="") if pr.repo_slug else pr.repo_external_id

    async def fetch_pull_request(self, ev: WebhookEvent, token: str) -> PullRequest:
        pid = quote(ev.repo_slug, safe="") if ev.repo_slug else ev.repo_external_id
        r = await self._request(
            "GET", f"/projects/{pid}/merge_requests/{ev.pr_id}", token, "get_pr"
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
        )

    async def fetch_diff(self, pr: PullRequest, token: str) -> list[FileChange]:
        # GitLab returns structured per-file diffs (already changed-only) — C2.
        r = await self._request(
            "GET", f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}/changes",
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
            f"/projects/{self._pid(pr)}/repository/files/{_q(path, safe='')}/raw",
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
            f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}/discussions",
            token,
            "post_inline_comment",
            json=payload,
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "post_inline_comment failed", r.status_code)
        return str(r.json().get("id", ""))

    async def post_summary(self, pr: PullRequest, token: str, body: str) -> str:
        r = await self._request(
            "POST",
            f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}/notes",
            token,
            "post_summary",
            json={"body": body},
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "post_summary failed", r.status_code)
        return str(r.json().get("id", ""))

    async def reply_in_thread(self, pr: PullRequest, token: str, thread_id: str, body: str) -> str:
        r = await self._request(
            "POST",
            f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}/discussions/{thread_id}/notes",
            token,
            "reply_in_thread",
            json={"body": body},
        )
        if r.status_code not in (200, 201):
            raise ProviderError("gitlab", "reply_in_thread failed", r.status_code)
        return str(r.json().get("id", ""))

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
            f"/projects/{self._pid(pr)}/statuses/{pr.head_sha}",
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
            f"/projects/{self._pid(pr)}/merge_requests/{pr.pr_id}/discussions/{thread_id}",
            token,
            "get_thread",
        )
        if r.status_code != 200:
            raise ProviderError("gitlab", "get_thread failed", r.status_code)
        d = r.json()
        return DiscussionThread(thread_id=thread_id, pr_id=pr.pr_id, comments=d.get("notes", []))


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
=======
"""GitLab provider implementation using the GitLab REST API v4."""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from aegis.observability.logging import get_logger
from aegis.providers.base import BaseProvider, DiffFile, PRMetadata

log = get_logger(__name__)

_BASE = "https://gitlab.com/api/v4"

_SKIP_EXTENSIONS = {
    ".md", ".markdown", ".rst", ".txt", ".log",
    ".lock", ".sum", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".po", ".pot",
}


def _language_from_filename(name: str) -> str | None:
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "c",
        ".rs": "rust",
        ".sh": "bash",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".tf": "terraform",
        ".sql": "sql",
    }.get(ext)


class GitLabProvider(BaseProvider):
    """Implements BaseProvider for GitLab projects."""

    def __init__(self, token: str, repo_slug: str, base_url: str = _BASE) -> None:
        super().__init__(token=token, repo_slug=repo_slug)
        self._base_url = base_url
        self._project_id = quote(repo_slug, safe="")
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={
                "PRIVATE-TOKEN": token,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _get(self, path: str, **kwargs: Any) -> Any:
        r = await self._client.get(path, **kwargs)
        r.raise_for_status()
        return r.json()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _post(self, path: str, json: Any) -> Any:
        r = await self._client.post(path, json=json)
        r.raise_for_status()
        return r.json()

    async def fetch_pr_metadata(self, pr_number: int) -> PRMetadata:
        data = await self._get(f"/projects/{self._project_id}/merge_requests/{pr_number}")
        return PRMetadata(
            pr_number=pr_number,
            title=data["title"],
            author=data["author"]["username"],
            body=data.get("description") or "",
            base_branch=data["target_branch"],
            head_branch=data["source_branch"],
            head_sha=data["sha"],
            url=data["web_url"],
            provider="gitlab",
            repo_slug=self.repo_slug,
            is_draft=data.get("work_in_progress", False),
            labels=data.get("labels", []),
            extra={"iid": data.get("iid"), "merge_status": data.get("merge_status")},
        )

    async def fetch_diff(self, pr_number: int) -> list[DiffFile]:
        data = await self._get(
            f"/projects/{self._project_id}/merge_requests/{pr_number}/diffs"
        )
        files: list[DiffFile] = []
        for f in data:
            filename = f.get("new_path") or f.get("old_path", "")
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext in _SKIP_EXTENSIONS:
                continue
            files.append(
                DiffFile(
                    filename=filename,
                    status="added" if f.get("new_file") else
                           "removed" if f.get("deleted_file") else
                           "renamed" if f.get("renamed_file") else "modified",
                    patch=f.get("diff", ""),
                    language=_language_from_filename(filename),
                )
            )
        return files

    async def fetch_file_content(self, path: str, ref: str) -> str:
        try:
            data = await self._get(
                f"/projects/{self._project_id}/repository/files/{quote(path, safe='')}",
                params={"ref": ref},
            )
            content = data.get("content", "")
            if data.get("encoding") == "base64":
                return base64.b64decode(content).decode("utf-8", errors="replace")
            return content
        except httpx.HTTPStatusError:
            return ""

    async def fetch_file_lines(self, path: str, ref: str, start: int, end: int) -> str:
        content = await self.fetch_file_content(path, ref)
        lines = content.splitlines()
        return "\n".join(lines[max(0, start - 1) : end])

    async def publish_inline_comment(
        self,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        body: str,
    ) -> str:
        data = await self._post(
            f"/projects/{self._project_id}/merge_requests/{pr_number}/discussions",
            json={
                "body": body,
                "position": {
                    "position_type": "text",
                    "new_path": path,
                    "new_line": line,
                    "base_sha": commit_sha,
                    "head_sha": commit_sha,
                    "start_sha": commit_sha,
                },
            },
        )
        return str(data.get("id", ""))

    async def publish_pr_comment(self, pr_number: int, body: str) -> str:
        data = await self._post(
            f"/projects/{self._project_id}/merge_requests/{pr_number}/notes",
            json={"body": body},
        )
        return str(data.get("id", ""))

    async def update_pr_comment(self, comment_id: str, body: str) -> None:
        await self._client.put(
            f"/projects/{self._project_id}/merge_requests/0/notes/{comment_id}",
            json={"body": body},
        )

    async def set_status_check(
        self,
        commit_sha: str,
        state: str,
        description: str,
        context: str = "aegis/security-review",
    ) -> None:
        # Map GitHub state names → GitLab
        gl_state = {
            "success": "success",
            "failure": "failed",
            "pending": "pending",
            "error": "failed",
        }.get(state, "pending")

        await self._post(
            f"/projects/{self._project_id}/statuses/{commit_sha}",
            json={
                "state": gl_state,
                "name": context,
                "description": description[:250],
            },
        )

    async def create_fix_pr(
        self,
        base_branch: str,
        head_branch: str,
        title: str,
        body: str,
        files: dict[str, str],
    ) -> str:
        # Commit files to the head branch
        actions = []
        for path, content in files.items():
            actions.append({
                "action": "update",
                "file_path": path,
                "content": content,
            })

        await self._post(
            f"/projects/{self._project_id}/repository/commits",
            json={
                "branch": head_branch,
                "start_branch": base_branch,
                "commit_message": "fix: aegis autofix",
                "actions": actions,
            },
        )

        data = await self._post(
            f"/projects/{self._project_id}/merge_requests",
            json={
                "title": title,
                "description": body,
                "source_branch": head_branch,
                "target_branch": base_branch,
            },
        )
        return data["web_url"]

    async def register_webhook(self, target_url: str, secret: str, events: list[str]) -> dict:
        return await self._post(
            f"/projects/{self._project_id}/hooks",
            json={
                "url": target_url,
                "token": secret,
                "merge_requests_events": True,
                "note_events": True,
                "push_events": False,
            },
        )

    async def __aenter__(self) -> "GitLabProvider":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self._client.aclose()
>>>>>>> Stashed changes
