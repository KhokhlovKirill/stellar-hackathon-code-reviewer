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
