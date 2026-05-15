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
        raise NotImplementedError("gitlab.post_inline_comment — Phase 6")

    async def post_summary(self, pr: PullRequest, token: str, body: str) -> str:
        raise NotImplementedError("gitlab.post_summary — Phase 6")

    async def reply_in_thread(self, pr: PullRequest, token: str, thread_id: str, body: str) -> str:
        raise NotImplementedError("gitlab.reply_in_thread — Phase 7")

    async def set_status_check(
        self, pr: PullRequest, token: str, decision: MergePolicyDecision, url: str
    ) -> None:
        raise NotImplementedError("gitlab.set_status_check — Phase 6")

    async def request_changes(self, pr: PullRequest, token: str, body: str) -> None:
        raise NotImplementedError("gitlab.request_changes — Phase 6")

    async def get_thread(self, pr: PullRequest, token: str, thread_id: str) -> DiscussionThread:
        raise NotImplementedError("gitlab.get_thread — Phase 7")


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
