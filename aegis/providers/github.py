"""GitHub provider implementation using the GitHub REST API v3."""

from __future__ import annotations

import base64
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from aegis.observability.logging import get_logger
from aegis.providers.base import BaseProvider, DiffFile, PRMetadata

log = get_logger(__name__)

_BASE = "https://api.github.com"
_ACCEPT_RAW = "application/vnd.github.v3.raw"
_ACCEPT_DIFF = "application/vnd.github.v3.diff"
_ACCEPT_JSON = "application/vnd.github+json"

# Extensions filtered out by default
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
        ".hcl": "hcl",
        ".sql": "sql",
    }.get(ext)


class GitHubProvider(BaseProvider):
    """Implements BaseProvider for GitHub repositories."""

    def __init__(self, token: str, repo_slug: str) -> None:
        super().__init__(token=token, repo_slug=repo_slug)
        self._client = httpx.AsyncClient(
            base_url=_BASE,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": _ACCEPT_JSON,
                "X-GitHub-Api-Version": "2022-11-28",
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

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _patch(self, path: str, json: Any) -> Any:
        r = await self._client.patch(path, json=json)
        r.raise_for_status()
        return r.json()

    async def fetch_pr_metadata(self, pr_number: int) -> PRMetadata:
        data = await self._get(f"/repos/{self.repo_slug}/pulls/{pr_number}")
        return PRMetadata(
            pr_number=pr_number,
            title=data["title"],
            author=data["user"]["login"],
            body=data.get("body") or "",
            base_branch=data["base"]["ref"],
            head_branch=data["head"]["ref"],
            head_sha=data["head"]["sha"],
            url=data["html_url"],
            provider="github",
            repo_slug=self.repo_slug,
            is_draft=data.get("draft", False),
            labels=[lbl["name"] for lbl in data.get("labels", [])],
            extra={"node_id": data.get("node_id"), "mergeable": data.get("mergeable")},
        )

    async def fetch_diff(self, pr_number: int) -> list[DiffFile]:
        data = await self._get(f"/repos/{self.repo_slug}/pulls/{pr_number}/files")
        files: list[DiffFile] = []
        for f in data:
            filename = f["filename"]
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext in _SKIP_EXTENSIONS:
                continue
            files.append(
                DiffFile(
                    filename=filename,
                    status=f["status"],
                    patch=f.get("patch", ""),
                    additions=f.get("additions", 0),
                    deletions=f.get("deletions", 0),
                    raw_url=f.get("raw_url"),
                    blob_url=f.get("blob_url"),
                    sha=f.get("sha"),
                    language=_language_from_filename(filename),
                )
            )
        return files

    async def fetch_file_content(self, path: str, ref: str) -> str:
        try:
            data = await self._get(
                f"/repos/{self.repo_slug}/contents/{path}",
                params={"ref": ref},
            )
            if isinstance(data, dict) and data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            return ""
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
            f"/repos/{self.repo_slug}/pulls/{pr_number}/comments",
            json={
                "body": body,
                "commit_id": commit_sha,
                "path": path,
                "line": line,
                "side": "RIGHT",
            },
        )
        return str(data["id"])

    async def publish_pr_comment(self, pr_number: int, body: str) -> str:
        data = await self._post(
            f"/repos/{self.repo_slug}/issues/{pr_number}/comments",
            json={"body": body},
        )
        return str(data["id"])

    async def update_pr_comment(self, comment_id: str, body: str) -> None:
        await self._patch(
            f"/repos/{self.repo_slug}/issues/comments/{comment_id}",
            json={"body": body},
        )

    async def set_status_check(
        self,
        commit_sha: str,
        state: str,
        description: str,
        context: str = "aegis/security-review",
    ) -> None:
        await self._post(
            f"/repos/{self.repo_slug}/statuses/{commit_sha}",
            json={
                "state": state,
                "description": description[:140],
                "context": context,
                "target_url": "",
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
        # 1. Get base branch SHA
        ref_data = await self._get(f"/repos/{self.repo_slug}/git/ref/heads/{base_branch}")
        base_sha = ref_data["object"]["sha"]

        # 2. Create new branch
        await self._post(
            f"/repos/{self.repo_slug}/git/refs",
            json={"ref": f"refs/heads/{head_branch}", "sha": base_sha},
        )

        # 3. Commit each file
        for path, content in files.items():
            encoded = base64.b64encode(content.encode()).decode()
            # Try to get existing file SHA
            try:
                existing = await self._get(
                    f"/repos/{self.repo_slug}/contents/{path}",
                    params={"ref": head_branch},
                )
                file_sha = existing.get("sha", "")
            except httpx.HTTPStatusError:
                file_sha = ""

            payload: dict[str, Any] = {
                "message": f"fix: aegis autofix — {path}",
                "content": encoded,
                "branch": head_branch,
            }
            if file_sha:
                payload["sha"] = file_sha

            await self._client.put(
                f"/repos/{self.repo_slug}/contents/{path}",
                json=payload,
            )

        # 4. Open PR
        pr_data = await self._post(
            f"/repos/{self.repo_slug}/pulls",
            json={
                "title": title,
                "body": body,
                "head": head_branch,
                "base": base_branch,
            },
        )
        return pr_data["html_url"]

    async def register_webhook(self, target_url: str, secret: str, events: list[str]) -> dict:
        return await self._post(
            f"/repos/{self.repo_slug}/hooks",
            json={
                "name": "web",
                "active": True,
                "events": events,
                "config": {
                    "url": target_url,
                    "content_type": "json",
                    "secret": secret,
                    "insecure_ssl": "0",
                },
            },
        )

    async def __aenter__(self) -> "GitHubProvider":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self._client.aclose()
