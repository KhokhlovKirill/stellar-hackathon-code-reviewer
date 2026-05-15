"""Pull-mode scanner: fetch public GitHub PR diff → run analysis → return findings.

No webhook, no token required. Works on any public repo.
For private repos: pass access_token (optional).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from aegis.config import get_settings
from aegis.llm.parser import finding_schema, parse_findings
from aegis.llm.prompt import judge_messages, review_messages
from aegis.llm.router import LLMRouter
from aegis.obs import get_logger
from aegis.pipeline.deterministic.secrets import scan_secrets
from aegis.providers.diffparse import parse_unified_diff
from aegis.schemas import FileChange, Finding, FindingSource, Severity

log = get_logger("aegis.simple_scan")

_GH_API = "https://api.github.com"
_GH_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

# Files to skip in analysis (too large or irrelevant)
_SKIP_EXTENSIONS = {".lock", ".sum", ".mod", ".min.js", ".min.css", ".map", ".svg",
                    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf"}
_MAX_DIFF_BYTES = 300_000


@dataclass
class SimpleScanResult:
    repo: str
    pr_number: int
    pr_title: str
    pr_url: str
    pr_author: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    files_scanned: int = 0
    degraded: bool = False  # True if LLM was skipped


def _parse_github_url(url: str) -> tuple[str, int | None]:
    """Return (owner/repo, pr_number_or_None) from any GitHub URL."""
    url = url.strip().rstrip("/")
    # PR URL: github.com/owner/repo/pull/123
    m = re.search(r"github\.com/([^/]+/[^/]+)/pull/(\d+)", url)
    if m:
        return m.group(1).removesuffix(".git"), int(m.group(2))
    # Repo URL: github.com/owner/repo
    m = re.search(r"github\.com/([^/]+/[^/]+)", url)
    if m:
        return m.group(1).removesuffix(".git"), None
    # bare slug: owner/repo
    if re.match(r"^[^/]+/[^/]+$", url):
        return url, None
    raise ValueError(f"Cannot parse GitHub URL: {url!r}")


def _gh_headers(token: str | None) -> dict[str, str]:
    h = dict(_GH_HEADERS)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h



async def _fetch_latest_pr(slug: str, token: str | None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            f"{_GH_API}/repos/{slug}/pulls",
            params={"state": "open", "per_page": 1, "sort": "updated", "direction": "desc"},
            headers=_gh_headers(token),
        )
    if r.status_code != 200:
        raise ValueError(f"GitHub API {r.status_code}: {r.json().get('message', 'error')}")
    prs = r.json()
    if not prs:
        # No open PRs — try fetching closed ones
        async with httpx.AsyncClient(timeout=20) as client:
            r2 = await client.get(
                f"{_GH_API}/repos/{slug}/pulls",
                params={"state": "closed", "per_page": 1, "sort": "updated", "direction": "desc"},
                headers=_gh_headers(token),
            )
        prs = r2.json() if r2.status_code == 200 else []
    if not prs:
        raise ValueError("No pull requests found in this repository")
    return prs[0]  # type: ignore[no-any-return]


async def _fetch_pr(slug: str, pr_number: int, token: str | None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            f"{_GH_API}/repos/{slug}/pulls/{pr_number}",
            headers=_gh_headers(token),
        )
    if r.status_code != 200:
        raise ValueError(f"GitHub API {r.status_code}: {r.json().get('message', 'error')}")
    return r.json()  # type: ignore[no-any-return]


async def _fetch_diff(slug: str, pr_number: int, token: str | None) -> str:
    """Fetch PR diff via /files endpoint (works for all visibility levels)."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{_GH_API}/repos/{slug}/pulls/{pr_number}/files",
            params={"per_page": 100},
            headers=_gh_headers(token),
        )
    if r.status_code != 200:
        raise ValueError(f"Diff fetch failed: HTTP {r.status_code}: {r.json().get('message', '')}")

    files = r.json()
    if not isinstance(files, list):
        raise ValueError("Unexpected GitHub API response format")

    # Reconstruct unified diff from per-file patches
    parts: list[str] = []
    total_bytes = 0
    for f in files:
        patch = f.get("patch", "")
        if not patch:
            continue
        filename = f.get("filename", "")
        old_name = f.get("previous_filename", filename)
        header = f"--- a/{old_name}\n+++ b/{filename}\n{patch}\n"
        total_bytes += len(header)
        if total_bytes > _MAX_DIFF_BYTES:
            break
        parts.append(header)

    return "\n".join(parts)


def _filter_files(files: list[FileChange]) -> list[FileChange]:
    out = []
    for f in files:
        if any(f.path.endswith(ext) for ext in _SKIP_EXTENSIONS):
            continue
        if not f.hunks:
            continue
        out.append(f)
    return out


async def _get_local_context_tokens() -> int:
    """Return loaded context tokens from LM Studio, or a safe default."""
    try:
        v0_base = get_settings().lmstudio_base_url.rstrip("/").removesuffix("/v1")
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{v0_base}/api/v0/models")
        for m in r.json().get("data", []):
            if m.get("state") == "loaded" and m.get("type") in ("llm", "vlm"):
                return int(m.get("loaded_context_length", 8192))
    except Exception as exc:
        log.warning("simple_scan.context_probe_failed", error=str(exc))
    return 8192


def _trim_files_to_budget(files: list[FileChange], char_budget: int) -> list[FileChange]:
    """Return as many files as fit within char_budget (rough token proxy: 3 chars/token).

    Size includes formatting overhead from _format_diff (hunk headers, line prefixes).
    """
    out: list[FileChange] = []
    used = 0
    for f in files:
        # Match _format_diff: file header + hunk headers + "ADD old=X new=Y: content" per line
        file_header = len(f"FILE {f.path} language={f.language or 'unknown'} status={f.status}") + 1
        hunk_text = sum(
            len(h.header) + 1 +
            sum(len(f"ADD old= new=: {ln.content}") + 10 for ln in h.lines)
            for h in f.hunks
        )
        size = file_header + hunk_text
        if used + size > char_budget:
            break
        out.append(f)
        used += size
    return out or files[:1]  # always send at least 1 file


async def _run_llm(
    slug: str, pr_number: int, files: list[FileChange], det_findings: list[Finding]
) -> tuple[list[Finding], bool]:
    """Run LLM ensemble. Returns (findings, degraded)."""
    if not files:
        return [], False

    router = LLMRouter()
    schema = finding_schema()

    # Limit diff to local model's loaded context (reserve 4096 for response + ~500 system/meta)
    # Empirical: Qwen tokenizer ~2 chars/token for mixed code content (conservative)
    ctx_tokens = await _get_local_context_tokens()
    available_tokens = max(ctx_tokens - 4096 - 500, 2048)
    char_budget = int(available_tokens * 2.0)
    trimmed_files = _trim_files_to_budget(files, char_budget)
    if len(trimmed_files) < len(files):
        log.info(
            "simple_scan.diff_trimmed",
            total=len(files),
            sent=len(trimmed_files),
            ctx_tokens=ctx_tokens,
        )

    messages = review_messages(
        repo=slug,
        pr_id=str(pr_number),
        files=trimmed_files,
        deterministic_findings=det_findings,
        context_map={},
    )

    # Detector pass
    llm_findings: list[Finding] = []
    degraded = False
    try:
        completion = await router.complete(
            role="detector_a",
            messages=messages,
            schema=schema,
            max_tokens=4096,
        )
        raw = parse_findings(completion.content, source=FindingSource.LLM_B)
        llm_findings = [f for f in raw if f.severity in (
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
        )]
        log.info("simple_scan.llm_ok", tier=completion.tier, count=len(llm_findings))
    except Exception as exc:
        log.warning("simple_scan.llm_failed", error=str(exc))
        degraded = True
        return det_findings, degraded

    # Judge pass — consolidate + deduplicate
    all_candidates = det_findings + llm_findings
    if all_candidates:
        try:
            j_messages = judge_messages(
                repo=slug,
                pr_id=str(pr_number),
                files=trimmed_files,
                candidates=all_candidates,
                context_map={},
            )
            j_completion = await router.complete(
                role="judge",
                messages=j_messages,
                schema=schema,
                max_tokens=4096,
            )
            judged = parse_findings(j_completion.content, source=FindingSource.JUDGE)
            log.info("simple_scan.judge_ok", tier=j_completion.tier, count=len(judged))
            return judged, False
        except Exception as exc:
            log.warning("simple_scan.judge_failed", error=str(exc))
            # Return merged without judging
            return all_candidates, False

    return all_candidates, degraded


async def run_simple_scan(url: str, token: str | None = None) -> SimpleScanResult:
    """Main entry point: GitHub URL → analysis result."""
    try:
        slug, pr_number = _parse_github_url(url)
    except ValueError as exc:
        return SimpleScanResult(
            repo="", pr_number=0, pr_title="", pr_url=url, pr_author="",
            error=str(exc),
        )

    # Fetch PR metadata
    try:
        if pr_number is None:
            pr_data = await _fetch_latest_pr(slug, token)
            pr_number = int(pr_data["number"])
        else:
            pr_data = await _fetch_pr(slug, pr_number, token)
    except ValueError as exc:
        return SimpleScanResult(
            repo=slug, pr_number=pr_number or 0, pr_title="", pr_url=url, pr_author="",
            error=str(exc),
        )

    pr_title = pr_data.get("title", f"PR #{pr_number}")
    pr_url = pr_data.get("html_url", url)
    pr_author = (pr_data.get("user") or {}).get("login", "unknown")

    # Fetch unified diff
    try:
        diff_text = await _fetch_diff(slug, pr_number, token)
    except ValueError as exc:
        return SimpleScanResult(
            repo=slug, pr_number=pr_number, pr_title=pr_title,
            pr_url=pr_url, pr_author=pr_author, error=str(exc),
        )

    # Parse diff
    try:
        all_files = parse_unified_diff(diff_text)
    except Exception as exc:
        return SimpleScanResult(
            repo=slug, pr_number=pr_number, pr_title=pr_title,
            pr_url=pr_url, pr_author=pr_author, error=f"Diff parse error: {exc}",
        )

    code_files = _filter_files(all_files)
    files_scanned = len(code_files)

    # Deterministic scan (always)
    det_findings = scan_secrets(code_files)

    # LLM scan (local models with sequential swap, or cloud fallback)
    findings, degraded = await _run_llm(slug, pr_number, code_files, det_findings)

    # Free memory — unload LLM after scan completes
    try:
        from aegis.llm.lmstudio_manager import unload_all
        s = get_settings()
        if s.lmstudio_swap_models:
            await unload_all(s.lmstudio_base_url)
    except Exception as exc:
        log.warning("simple_scan.unload_failed", error=str(exc))

    # Sort by severity
    _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    findings.sort(key=lambda f: _sev_order.get(f.severity, 9))

    return SimpleScanResult(
        repo=slug,
        pr_number=pr_number,
        pr_title=pr_title,
        pr_url=pr_url,
        pr_author=pr_author,
        findings=findings,
        files_scanned=files_scanned,
        degraded=degraded,
    )
