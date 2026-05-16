"""VS Code extension REST API — no auth for scan endpoints, bearer auth for user data.

Prefix: /api/ext
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from aegis.api.security import require_user
from aegis.db import get_session
from aegis.db.models import (
    Feedback,
    FindingRow,
    Project,
    RepoPolicy,
    RepoSecret,
    Repository,
    Scan,
    User,
)
from aegis.llm.base import ChatMessage
from aegis.llm.router import LLMRouter
from aegis.obs import get_logger
from aegis.pipeline.dispatch import run_scan
from aegis.pipeline.risk_score import risk_breakdown, risk_label
from aegis.pipeline.simple_scan import run_simple_scan  # noqa: F401 (re-exported for tests)
from aegis.schemas import DiffLine, FileChange, Finding, Hunk, LineKind, Severity
from aegis.vault import decrypt

router = APIRouter(prefix="/api/ext", tags=["extension"])
log = get_logger("aegis.api.extension")

_user_dep = Depends(require_user)

_GH_API = "https://api.github.com"
_GH_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScanUrlRequest(BaseModel):
    url: str = Field(min_length=1)
    token: str | None = None
    lang: str = "ru"
    # "auto" = whatever AEGIS_USE_LANGGRAPH is set to (default); "graph" =
    # force the LangGraph DAG; "direct" = force run_simple_scan.
    engine: str = "auto"


class FindingOut(BaseModel):
    fingerprint: str
    file: str
    line: int
    cwe: str | None
    severity: str
    title: str
    rationale: str
    exploit: str | None
    fix: str | None
    rule_id: str | None = None
    confidence: float
    source: str
    short_label: str | None = None


class ScanUrlResponse(BaseModel):
    scan_id: str
    repo: str
    pr_number: int
    pr_title: str
    pr_url: str
    pr_author: str
    files_scanned: int
    degraded: bool
    findings: list[FindingOut]
    summary: str = ""


class RepoPolicyOut(BaseModel):
    severity_gate: str
    merge_block: str
    lang: str


class RepoInfoOut(BaseModel):
    id: int
    provider: str
    slug: str
    external_id: str
    status: str
    project_id: int | None
    project_name: str
    policy: RepoPolicyOut


class ScanSummaryOut(BaseModel):
    id: str
    pr_id: str
    status: str
    risk_score: int
    risk_label: str
    started_at: str
    finished_at: str | None
    files_scanned: int
    degraded: bool


class PRInfoOut(BaseModel):
    pr_number: int
    title: str
    author: str
    url: str
    head_branch: str
    base_branch: str
    state: str = ""
    created_at: str
    updated_at: str
    draft: bool
    last_scan: ScanSummaryOut | None = None


class ChatFinding(BaseModel):
    file: str
    line: int
    cwe: str | None = None
    severity: str
    title: str
    rationale: str
    exploit: str | None = None
    fix: str | None = None


class ChatScan(BaseModel):
    scan_id: str = ""
    repo: str = ""
    pr_number: int = 0
    pr_title: str = ""
    pr_url: str = ""
    pr_author: str = ""
    files_scanned: int = 0
    degraded: bool = False
    summary: str | None = None
    findings: list[ChatFinding] = Field(default_factory=list)


class ChatHistoryItem(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    finding: ChatFinding | None = None
    scan: ChatScan | None = None
    repo: str = ""
    message: str
    lang: str = "ru"
    history: list[ChatHistoryItem] = Field(default_factory=list)


class ChatResponse(BaseModel):
    reply: str
    proposed_patch: str | None = None


class ScanBranchRequest(BaseModel):
    diff: str = Field(min_length=1)
    repo_slug: str
    ref: str
    lang: str = "ru"


class FeedbackRequest(BaseModel):
    scan_id: str
    fingerprint: str
    kind: str = "false_positive"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_out_from_row(f: FindingRow) -> FindingOut:
    return FindingOut(
        fingerprint=f.fingerprint,
        file=f.file,
        line=f.line,
        cwe=f.cwe,
        severity=f.severity,
        title=f.title,
        rationale=f.rationale,
        exploit=f.exploit,
        fix=f.fix,
        rule_id=f.rule_id,
        confidence=f.confidence,
        source=f.source,
        short_label=None,
    )


def _scan_summary_from_row(s: Scan) -> ScanSummaryOut:
    files_scanned_count = len(s.files_scanned) if isinstance(s.files_scanned, list) else 0
    degraded_val = bool(s.degraded) if not isinstance(s.degraded, list) else len(s.degraded) > 0
    return ScanSummaryOut(
        id=s.id,
        pr_id=s.pr_id,
        status=s.status,
        risk_score=s.risk_score,
        risk_label=s.risk_label,
        started_at=s.started_at.isoformat(),
        finished_at=s.finished_at.isoformat() if s.finished_at else None,
        files_scanned=files_scanned_count,
        degraded=degraded_val,
    )


def _engine_to_pref(engine: str | None) -> bool | None:
    """Translate the request-level engine knob into the dispatcher argument.

    "auto" / unknown → None (let the global Settings.use_langgraph decide);
    "graph" → True (force the LangGraph orchestrator);
    "direct" → False (force run_simple_scan).
    """
    if engine == "graph":
        return True
    if engine == "direct":
        return False
    return None


def _gh_headers(token: str | None) -> dict[str, str]:
    h = dict(_GH_HEADERS)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _gl_api_base() -> str:
    from aegis.config import get_settings

    return f"{get_settings().gitlab_base_url.rstrip('/')}/api/v4"


def _gl_web_base() -> str:
    from aegis.config import get_settings

    return get_settings().gitlab_base_url.rstrip("/")


def _gl_headers(token: str | None) -> dict[str, str]:
    return {"PRIVATE-TOKEN": token} if token else {}


def _repo_pr_url(repo: Repository, pr_number: int) -> str:
    if repo.provider == "gitlab":
        return f"{_gl_web_base()}/{repo.slug}/-/merge_requests/{pr_number}"
    return f"https://github.com/{repo.slug}/pull/{pr_number}"


async def _get_repo_access_token(repo: Repository) -> str | None:
    """Fetch and decrypt the stored access_token for a repo."""
    async with get_session() as session:
        secret = (
            await session.execute(
                select(RepoSecret).where(
                    RepoSecret.repo_id == repo.id,
                    RepoSecret.kind == "access_token",
                )
            )
        ).scalar_one_or_none()
    if secret is None:
        return None
    try:
        return decrypt(secret.ciphertext)
    except Exception:
        return None


def _extract_diff_block(text: str) -> str | None:
    """Extract first ```diff ... ``` block from text, or None."""
    match = re.search(r"```diff\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # Also look for ```patch blocks
    match = re.search(r"```patch\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def _risk_score(findings: list[Finding]) -> tuple[int, str]:
    score = min(sum(risk_breakdown(findings).values()), 100)
    return score, risk_label(score, findings)


async def _persist_scan_result(
    *,
    scan_id: str,
    provider: str,
    repo_slug: str,
    pr_id: str,
    head_sha: str,
    files_scanned: list[str],
    degraded: list[str],
    findings: list[Finding],
    summary: str,
    finding_labels: dict[str, str] | None = None,
) -> None:
    """Persist extension-triggered scans so sidebars and detail views stay coherent."""
    score, label = _risk_score(findings)
    now = datetime.now(UTC)
    async with get_session() as session:
        session.add(
            Scan(
                id=scan_id,
                provider=provider,
                repo_slug=repo_slug,
                pr_id=pr_id,
                head_sha=head_sha,
                status="completed",
                degraded=degraded,
                files_scanned=files_scanned,
                risk_score=score,
                risk_label=label,
                decision={"summary": summary, "finding_labels": finding_labels or {}},
                started_at=now,
                finished_at=now,
            )
        )
        for f in findings:
            session.add(
                FindingRow(
                    scan_id=scan_id,
                    fingerprint=f.fingerprint(),
                    file=f.file,
                    line=f.line,
                    cwe=f.cwe,
                    rule_id=f.rule_id,
                    severity=f.severity.value,
                    confidence=f.confidence,
                    source=f.source.value,
                    title=f.title,
                    rationale=f.rationale,
                    exploit=f.exploit,
                    fix=f.fix,
                )
            )


def _scan_response(scan_id: str, result: Any) -> ScanUrlResponse:
    findings_out = [
        FindingOut(
            fingerprint=f.fingerprint(),
            file=f.file,
            line=f.line,
            cwe=f.cwe,
            severity=f.severity.value,
            title=f.title,
            rationale=f.rationale,
            exploit=f.exploit,
            fix=f.fix,
            rule_id=f.rule_id,
            confidence=f.confidence,
            source=f.source.value,
            short_label=result.finding_labels.get(f.fingerprint()),
        )
        for f in result.findings
    ]
    return ScanUrlResponse(
        scan_id=scan_id,
        repo=result.repo,
        pr_number=result.pr_number,
        pr_title=result.pr_title,
        pr_url=result.pr_url,
        pr_author=result.pr_author,
        files_scanned=result.files_scanned,
        degraded=result.degraded,
        findings=findings_out,
        summary=result.summary,
    )


async def _scan_registered_pr_response(
    repo: Repository,
    pr_number: int,
    access_token: str | None,
    lang: str,
    engine: str = "auto",
) -> ScanUrlResponse:
    result = await run_scan(
        _repo_pr_url(repo, pr_number),
        token=access_token,
        lang=lang,
        prefer_graph=_engine_to_pref(engine),
    )
    if result.error:
        raise HTTPException(status_code=422, detail=result.error)
    scan_id = uuid.uuid4().hex
    await _persist_scan_result(
        scan_id=scan_id,
        provider=repo.provider or "github",
        repo_slug=result.repo,
        pr_id=str(result.pr_number),
        head_sha=result.head_sha,
        files_scanned=result.files_scanned_paths,
        degraded=result.degraded_reasons,
        findings=result.findings,
        summary=result.summary,
        finding_labels=result.finding_labels,
    )
    return _scan_response(scan_id, result)


_FULL_SCAN_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php",
    ".c", ".h", ".cpp", ".cc", ".cs", ".rs", ".kt", ".scala", ".sh",
    ".sql", ".yaml", ".yml", ".tf", ".dockerfile",
}
_FULL_SCAN_MAX_FILES = 80
_FULL_SCAN_MAX_FILE_BYTES = 60_000


def _is_full_scan_candidate(path: str) -> bool:
    low = path.lower()
    if low.endswith("dockerfile") or "/dockerfile" in low:
        return True
    return any(low.endswith(ext) for ext in _FULL_SCAN_EXTS)


def _file_as_added_change(path: str, text: str) -> FileChange:
    from aegis.providers.diffparse import language_of

    lines = text.splitlines()[:1200]
    diff_lines = [
        DiffLine(
            kind=LineKind.ADD,
            content=line,
            new_lineno=i,
            old_lineno=None,
            diff_position=i + 1,
        )
        for i, line in enumerate(lines, start=1)
    ]
    return FileChange(
        path=path,
        old_path=None,
        status="added",
        is_binary=False,
        language=language_of(path),
        hunks=[
            Hunk(
                old_start=0,
                old_count=0,
                new_start=1,
                new_count=len(diff_lines),
                header=f"@@ -0,0 +1,{len(diff_lines)} @@",
                lines=diff_lines,
            )
        ],
    )


async def _github_default_branch(repo: Repository, token: str | None) -> tuple[str, str]:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            f"{_GH_API}/repos/{repo.slug}",
            headers=_gh_headers(token),
        )
    if r.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"GitHub API error {r.status_code}: {r.text[:160]}",
        )
    data = r.json()
    return str(data.get("default_branch") or "main"), str(data.get("pushed_at") or "")


async def _gitlab_default_branch(repo: Repository, token: str | None) -> tuple[str, str]:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            f"{_gl_api_base()}/projects/{quote(repo.slug, safe='')}",
            headers=_gl_headers(token),
        )
    if r.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"GitLab API error {r.status_code}: {r.text[:160]}",
        )
    data = r.json()
    return str(data.get("default_branch") or "main"), str(data.get("last_activity_at") or "")


async def _github_full_files(repo: Repository, token: str | None, branch: str) -> list[FileChange]:
    async with httpx.AsyncClient(timeout=30) as client:
        tree = await client.get(
            f"{_GH_API}/repos/{repo.slug}/git/trees/{quote(branch, safe='')}",
            params={"recursive": "1"},
            headers=_gh_headers(token),
        )
        if tree.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"GitHub tree error {tree.status_code}: {tree.text[:160]}",
            )
        entries = [
            item for item in tree.json().get("tree", [])
            if item.get("type") == "blob"
            and _is_full_scan_candidate(str(item.get("path") or ""))
            and int(item.get("size") or 0) <= _FULL_SCAN_MAX_FILE_BYTES
        ][:_FULL_SCAN_MAX_FILES]
        out: list[FileChange] = []
        for item in entries:
            path = str(item["path"])
            raw = await client.get(
                f"{_GH_API}/repos/{repo.slug}/contents/{quote(path, safe='/')}",
                params={"ref": branch},
                headers={**_gh_headers(token), "Accept": "application/vnd.github.raw+json"},
            )
            if raw.status_code == 200 and raw.text:
                out.append(_file_as_added_change(path, raw.text))
        return out


async def _gitlab_full_files(repo: Repository, token: str | None, branch: str) -> list[FileChange]:
    async with httpx.AsyncClient(timeout=30) as client:
        tree = await client.get(
            f"{_gl_api_base()}/projects/{quote(repo.slug, safe='')}/repository/tree",
            params={"recursive": "true", "per_page": _FULL_SCAN_MAX_FILES * 4, "ref": branch},
            headers=_gl_headers(token),
        )
        if tree.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"GitLab tree error {tree.status_code}: {tree.text[:160]}",
            )
        entries = [
            item for item in tree.json()
            if item.get("type") == "blob"
            and _is_full_scan_candidate(str(item.get("path") or ""))
        ][:_FULL_SCAN_MAX_FILES]
        out: list[FileChange] = []
        for item in entries:
            path = str(item["path"])
            file_url = (
                f"{_gl_api_base()}/projects/{quote(repo.slug, safe='')}"
                f"/repository/files/{quote(path, safe='')}/raw"
            )
            raw = await client.get(
                file_url,
                params={"ref": branch},
                headers=_gl_headers(token),
            )
            if raw.status_code == 200 and len(raw.content) <= _FULL_SCAN_MAX_FILE_BYTES:
                out.append(_file_as_added_change(path, raw.text))
        return out


async def _scan_registered_repo_response(
    repo: Repository,
    access_token: str | None,
    lang: str,
) -> ScanUrlResponse:
    from types import SimpleNamespace

    from aegis.pipeline.deterministic.secrets import scan_secrets
    from aegis.pipeline.simple_scan import _generate_scan_review, _run_llm

    if repo.provider == "gitlab":
        branch, marker = await _gitlab_default_branch(repo, access_token)
        code_files = await _gitlab_full_files(repo, access_token, branch)
        provider = "gitlab"
        repo_url = f"{_gl_web_base()}/{repo.slug}"
    else:
        branch, marker = await _github_default_branch(repo, access_token)
        code_files = await _github_full_files(repo, access_token, branch)
        provider = "github"
        repo_url = f"https://github.com/{repo.slug}"

    det_findings = scan_secrets(code_files)
    findings, degraded_reasons = await _run_llm(repo.slug, 0, code_files, det_findings, lang=lang)
    _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    findings.sort(key=lambda f: _sev_order.get(f.severity, 9))
    summary, finding_labels = await _generate_scan_review(
        repo.slug,
        0,
        f"Full repository scan: {branch}",
        len(code_files),
        findings,
        degraded_reasons,
        lang=lang,
    )
    scan_id = uuid.uuid4().hex
    await _persist_scan_result(
        scan_id=scan_id,
        provider=provider,
        repo_slug=repo.slug,
        pr_id=f"repo:{branch}",
        head_sha=marker or branch,
        files_scanned=[f.path for f in code_files],
        degraded=degraded_reasons,
        findings=findings,
        summary=summary,
        finding_labels=finding_labels,
    )
    return _scan_response(
        scan_id,
        SimpleNamespace(
            repo=repo.slug,
            pr_number=0,
            pr_title=f"Full repository scan: {branch}",
            pr_url=repo_url,
            pr_author="",
            files_scanned=len(code_files),
            degraded=bool(degraded_reasons),
            findings=findings,
            summary=summary,
            finding_labels=finding_labels,
        ),
    )


# ---------------------------------------------------------------------------
# POST /api/ext/scan/url
# ---------------------------------------------------------------------------


@router.post("/scan/url", response_model=ScanUrlResponse)
async def scan_url(req: ScanUrlRequest) -> ScanUrlResponse:
    """Scan a GitHub PR URL. No auth required."""
    from aegis.pipeline.simple_scan import _parse_repo_url

    result = await run_scan(
        req.url,
        req.token or None,
        lang=req.lang,
        prefer_graph=_engine_to_pref(req.engine),
    )
    if result.error:
        raise HTTPException(status_code=422, detail=result.error)
    scan_id = uuid.uuid4().hex
    provider = _parse_repo_url(req.url)[0]

    await _persist_scan_result(
        scan_id=scan_id,
        provider=provider,
        repo_slug=result.repo,
        pr_id=str(result.pr_number),
        head_sha=result.head_sha,
        files_scanned=result.files_scanned_paths,
        degraded=result.degraded_reasons,
        findings=result.findings,
        summary=result.summary,
        finding_labels=result.finding_labels,
    )

    return _scan_response(scan_id, result)


# ---------------------------------------------------------------------------
# GET /api/ext/repos
# ---------------------------------------------------------------------------


@router.get("/repos", response_model=list[RepoInfoOut])
async def list_ext_repos(user: User = _user_dep) -> list[RepoInfoOut]:
    """Return repos the authenticated user has access to (via their projects)."""
    async with get_session() as session:
        # Get all projects owned by user
        projects = (
            await session.execute(
                select(Project).where(Project.owner_id == user.id)
            )
        ).scalars().all()
        project_ids = [p.id for p in projects]
        project_names: dict[int, str] = {p.id: p.name for p in projects}

        # Get repos for those projects
        repos = (
            await session.execute(
                select(Repository).where(
                    Repository.project_id.in_(project_ids)
                )
            )
        ).scalars().all()

        out: list[RepoInfoOut] = []
        for repo in repos:
            policy = (
                await session.execute(
                    select(RepoPolicy).where(RepoPolicy.repo_id == repo.id)
                )
            ).scalar_one_or_none()

            pid = repo.project_id
            out.append(
                RepoInfoOut(
                    id=repo.id,
                    provider=repo.provider,
                    slug=repo.slug,
                    external_id=repo.external_id,
                    status=repo.status,
                    project_id=pid,
                    project_name=project_names.get(pid, "") if pid else "",
                    policy=RepoPolicyOut(
                        severity_gate=policy.severity_gate if policy else "medium",
                        merge_block=policy.merge_block if policy else "critical",
                        lang=policy.lang if policy else "ru",
                    ),
                )
            )
        return out


# ---------------------------------------------------------------------------
# GET /api/ext/repos/{repo_id}/prs
# ---------------------------------------------------------------------------


@router.get("/repos/{repo_id}/prs", response_model=list[PRInfoOut])
async def list_repo_prs(repo_id: int, user: User = _user_dep) -> list[PRInfoOut]:
    """Fetch recent PRs/MRs from the provider + attach last scan per PR."""
    async with get_session() as session:
        repo = (
            await session.execute(
                select(Repository).where(Repository.id == repo_id)
            )
        ).scalar_one_or_none()
        if repo is None:
            raise HTTPException(status_code=404, detail="repo not found")

        # Verify user owns the project
        if repo.project_id is not None:
            project = (
                await session.execute(
                    select(Project).where(Project.id == repo.project_id)
                )
            ).scalar_one_or_none()
            if project is None or project.owner_id != user.id:
                raise HTTPException(status_code=404, detail="repo not found")

    access_token = await _get_repo_access_token(repo)

    try:
        if repo.provider == "gitlab":
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(
                    f"{_gl_api_base()}/projects/{quote(repo.slug, safe='')}/merge_requests",
                    params={
                        "state": "all",
                        "order_by": "updated_at",
                        "sort": "desc",
                        "per_page": 50,
                    },
                    headers=_gl_headers(access_token),
                )
        else:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(
                    f"{_GH_API}/repos/{repo.slug}/pulls",
                    params={"state": "all", "per_page": 50, "sort": "updated", "direction": "desc"},
                    headers=_gh_headers(access_token),
                )
        if r.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"{repo.provider} API error {r.status_code}: {r.text[:200]}",
            )
        prs_data: list[dict[str, Any]] = r.json()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"GitHub API call failed: {exc}") from exc

    # Fetch last scan for each PR from DB
    pr_numbers = [
        int((pr.get("iid") if repo.provider == "gitlab" else pr.get("number")) or 0)
        for pr in prs_data
    ]
    pr_id_strs = [str(n) for n in pr_numbers]

    async with get_session() as session:
        scans = (
            await session.execute(
                select(Scan)
                .where(
                    Scan.repo_slug == repo.slug,
                    Scan.pr_id.in_(pr_id_strs),
                )
                .order_by(Scan.started_at.desc())
            )
        ).scalars().all()

    # Group by pr_id, keep latest
    latest_scan: dict[str, Scan] = {}
    for scan in scans:
        if scan.pr_id not in latest_scan:
            latest_scan[scan.pr_id] = scan

    out: list[PRInfoOut] = []
    for pr in prs_data:
        raw_number = pr.get("iid") if repo.provider == "gitlab" else pr.get("number")
        pr_num = int(raw_number or 0)
        pr_id_str = str(pr_num)
        last_scan_row = latest_scan.get(pr_id_str)
        if repo.provider == "gitlab":
            author = (pr.get("author") or {}).get("username", "")
            url = pr.get("web_url", "")
            head_branch = pr.get("source_branch", "")
            base_branch = pr.get("target_branch", "")
            draft = bool(pr.get("draft") or pr.get("work_in_progress"))
            state = pr.get("state", "")
        else:
            author = (pr.get("user") or {}).get("login", "")
            url = pr.get("html_url", "")
            head_branch = (pr.get("head") or {}).get("ref", "")
            base_branch = (pr.get("base") or {}).get("ref", "")
            draft = bool(pr.get("draft", False))
            state = pr.get("state", "")
        out.append(
            PRInfoOut(
                pr_number=pr_num,
                title=pr.get("title", ""),
                author=author,
                url=url,
                head_branch=head_branch,
                base_branch=base_branch,
                state=state,
                created_at=pr.get("created_at", ""),
                updated_at=pr.get("updated_at", ""),
                draft=draft,
                last_scan=_scan_summary_from_row(last_scan_row) if last_scan_row else None,
            )
        )
    return out


# ---------------------------------------------------------------------------
# GET /api/ext/repos/{repo_id}/scans
# ---------------------------------------------------------------------------


@router.get("/repos/{repo_id}/scans", response_model=list[ScanSummaryOut])
async def list_repo_scans(repo_id: int, user: User = _user_dep) -> list[ScanSummaryOut]:
    """Return recent 30 scans for a repo."""
    async with get_session() as session:
        repo = (
            await session.execute(
                select(Repository).where(Repository.id == repo_id)
            )
        ).scalar_one_or_none()
        if repo is None:
            raise HTTPException(status_code=404, detail="repo not found")

        if repo.project_id is not None:
            project = (
                await session.execute(
                    select(Project).where(Project.id == repo.project_id)
                )
            ).scalar_one_or_none()
            if project is None or project.owner_id != user.id:
                raise HTTPException(status_code=404, detail="repo not found")

        scans = (
            await session.execute(
                select(Scan)
                .where(Scan.repo_slug == repo.slug)
                .order_by(Scan.started_at.desc())
                .limit(30)
            )
        ).scalars().all()

        return [_scan_summary_from_row(s) for s in scans]


# ---------------------------------------------------------------------------
# GET /api/ext/scans/{scan_id}
# ---------------------------------------------------------------------------


@router.get("/scans/{scan_id}")
async def get_scan_detail(scan_id: str) -> dict[str, Any]:
    """Return full scan details + findings. No auth required."""
    async with get_session() as session:
        scan = (
            await session.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")

        findings = (
            await session.execute(
                select(FindingRow).where(FindingRow.scan_id == scan_id)
            )
        ).scalars().all()
        finding_labels = (scan.decision or {}).get("finding_labels", {})
        if not isinstance(finding_labels, dict):
            finding_labels = {}

        files_scanned_count = (
            len(scan.files_scanned) if isinstance(scan.files_scanned, list) else 0
        )
        degraded_val = (
            bool(scan.degraded)
            if not isinstance(scan.degraded, list)
            else len(scan.degraded) > 0
        )

        return {
            "scan": {
                "id": scan.id,
                "pr_id": scan.pr_id,
                "status": scan.status,
                "risk_score": scan.risk_score,
                "risk_label": scan.risk_label,
                "started_at": scan.started_at.isoformat(),
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "files_scanned": files_scanned_count,
                "degraded": degraded_val,
                "summary": (scan.decision or {}).get("summary", ""),
            },
            "findings": [
                {
                    "fingerprint": f.fingerprint,
                    "file": f.file,
                    "line": f.line,
                    "cwe": f.cwe,
                    "severity": f.severity,
                    "title": f.title,
                    "rationale": f.rationale,
                    "exploit": f.exploit,
                    "fix": f.fix,
                    "confidence": f.confidence,
                    "source": f.source,
                    "short_label": finding_labels.get(f.fingerprint),
                }
                for f in findings
            ],
        }


# ---------------------------------------------------------------------------
# POST /api/ext/chat
# ---------------------------------------------------------------------------


def _build_chat_messages(req: ChatRequest) -> list[ChatMessage]:
    """Assemble the messages list for a chat request (finding-context or free-form)."""
    language_name = "Russian" if req.lang == "ru" else "English"
    system_content = (
        "You are Aegis, an expert defensive security code reviewer. "
        "You help developers understand and fix security vulnerabilities. "
        "Be precise, educational, and constructive. "
        f"Respond only in {language_name}; this is the user's selected language. "
        "Use Markdown for formatting.\n\n"
        "When you propose a code fix, output it as a STRICT git unified diff "
        "inside a single ```diff fenced code block, following these rules "
        "exactly so the patch applies cleanly with `git apply`:\n"
        "1. Start the diff with `diff --git a/<path> b/<path>` then "
        "`--- a/<path>` and `+++ b/<path>`, using the real file path from the "
        "finding context (no leading `./`).\n"
        "2. Each hunk begins with `@@ -<oldStart>,<oldLen> +<newStart>,"
        "<newLen> @@`. Count lines correctly: context+removed = oldLen, "
        "context+added = newLen.\n"
        "3. Every line inside a hunk MUST begin with a single space (context), "
        "`+` (added) or `-` (removed). A blank/empty line in the file is a "
        "context line written as a single space character — never emit a "
        "zero-length line inside a hunk.\n"
        "4. Include at least 3 lines of unchanged context around each change "
        "and keep that context identical to the current file.\n"
        "5. Put NO prose, comments, or markdown inside the ```diff block — "
        "explanations go in normal text before or after the block.\n"
        "Keep the patch minimal and scoped to the security fix."
    )
    messages: list[ChatMessage] = [{"role": "system", "content": system_content}]

    if req.finding:
        f = req.finding
        ctx = (
            f"## Security Finding Context\n"
            f"**File:** `{f.file}` (line {f.line})\n"
            f"**Severity:** {f.severity.upper()}\n"
            f"**CWE:** {f.cwe or 'N/A'}\n"
            f"**Title:** {f.title}\n\n"
            f"**Rationale:**\n{f.rationale}\n\n"
        )
        if f.exploit:
            ctx += f"**Exploit scenario:**\n{f.exploit}\n\n"
        if f.fix:
            ctx += f"**Suggested fix direction:**\n{f.fix}\n\n"
        if req.repo:
            ctx += f"**Repository:** `{req.repo}`\n"
        messages.append({"role": "user", "content": ctx})
        messages.append({
            "role": "assistant",
            "content": (
                "Контекст finding получен. Чем помочь?"
                if req.lang == "ru"
                else "I have the finding context. How can I help you with it?"
            ),
        })
    elif req.scan:
        scan = req.scan
        findings = [
            {
                "file": f.file,
                "line": f.line,
                "cwe": f.cwe,
                "severity": f.severity,
                "title": f.title,
                "rationale": f.rationale,
                "exploit": f.exploit,
                "fix": f.fix,
            }
            for f in scan.findings[:30]
        ]
        ctx = (
            "## Pull Request Security Review Context\n"
            f"**Repository:** `{scan.repo or req.repo}`\n"
            f"**Pull request:** #{scan.pr_number} {scan.pr_title}\n"
            f"**URL:** {scan.pr_url or 'N/A'}\n"
            f"**Files scanned:** {scan.files_scanned}\n"
            f"**Degraded:** {scan.degraded}\n\n"
            f"**Coordinator summary:**\n{scan.summary or 'No summary available.'}\n\n"
            f"**Findings JSON:**\n{json.dumps(findings, ensure_ascii=False)}"
        )
        messages.append({"role": "user", "content": ctx})
        messages.append({
            "role": "assistant",
            "content": (
                "Контекст всего pull request review получен: summary и findings. "
                "Задайте вопрос по PR."
                if req.lang == "ru"
                else (
                    "I have the full pull request review context, including the "
                    "coordinator summary and findings. Ask me about the whole PR."
                )
            ),
        })
    else:
        messages.append({
            "role": "user",
            "content": "I'm a developer with questions about application security.",
        })
        messages.append({
            "role": "assistant",
            "content": (
                "Привет. Я Aegis, security reviewer. Задайте вопрос про "
                "уязвимости, безопасную разработку или threat modeling."
                if req.lang == "ru"
                else (
                    "Hello! I'm Aegis, your security reviewer. Ask me anything about "
                    "security vulnerabilities, secure coding practices, or threat modeling."
                )
            ),
        })

    for turn in req.history:
        messages.append({"role": turn.role, "content": turn.content})

    messages.append({"role": "user", "content": req.message})
    return messages


@router.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    """Conversational chat about a security finding or general security topic. No auth required."""
    router_obj = LLMRouter()
    messages = _build_chat_messages(req)

    text_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"reply": {"type": "string"}},
        "required": ["reply"],
    }

    try:
        completion = await router_obj.complete(
            role="judge",
            messages=messages,
            schema=text_schema,
            max_tokens=2048,
        )
        reply_text = completion.content
    except Exception as exc:
        log.warning("ext.chat.llm_failed", error=str(exc))
        raise HTTPException(status_code=503, detail=f"LLM unavailable: {exc}") from exc

    proposed_patch = _extract_diff_block(reply_text)
    return ChatResponse(reply=reply_text, proposed_patch=proposed_patch)


@router.post("/chat/stream")
async def chat_stream(req: ChatRequest) -> StreamingResponse:
    """SSE streaming chat. Each event: `data: {"token":"..."}\n\n`. Final: `data: [DONE]\n\n`."""
    router_obj = LLMRouter()
    messages = _build_chat_messages(req)

    async def event_generator() -> AsyncIterator[str]:
        try:
            async for token in router_obj.stream_chat(
                role="judge", messages=messages, max_tokens=2048
            ):
                payload = json.dumps({"token": token}, ensure_ascii=False)
                yield f"data: {payload}\n\n"
        except Exception as exc:
            log.warning("ext.chat_stream.failed", error=str(exc))
            err_payload = json.dumps({"error": str(exc)})
            yield f"data: {err_payload}\n\n"
        finally:
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# POST /api/ext/scan/pr  — scan a PR by repo_id + pr_number, uses stored token
# ---------------------------------------------------------------------------


class ScanPRRequest(BaseModel):
    repo_id: int
    pr_number: int
    lang: str = "ru"
    engine: str = "auto"  # auto | graph | direct — see ScanUrlRequest.engine


class ScanRepoRequest(BaseModel):
    repo_id: int
    lang: str = "ru"


@router.post("/scan/pr", response_model=ScanUrlResponse)
async def scan_pr(req: ScanPRRequest, user: User = _user_dep) -> ScanUrlResponse:
    """Scan a registered PR using the stored repo access token. Auth required."""
    async with get_session() as session:
        repo = (
            await session.execute(
                select(Repository).where(Repository.id == req.repo_id)
            )
        ).scalar_one_or_none()
        if repo is None:
            raise HTTPException(status_code=404, detail="repo not found")

        # Ownership check
        if repo.project_id is not None:
            project = (
                await session.execute(
                    select(Project).where(Project.id == repo.project_id)
                )
            ).scalar_one_or_none()
            if project is None or project.owner_id != user.id:
                raise HTTPException(status_code=404, detail="repo not found")

    access_token = await _get_repo_access_token(repo)
    return await _scan_registered_pr_response(
        repo,
        req.pr_number,
        access_token,
        req.lang,
        getattr(req, "engine", "auto"),
    )


@router.post("/scan/repo", response_model=ScanUrlResponse)
async def scan_repo(req: ScanRepoRequest, user: User = _user_dep) -> ScanUrlResponse:
    """Scan the default branch of a registered GitHub/GitLab repository."""
    async with get_session() as session:
        repo = (
            await session.execute(
                select(Repository).where(Repository.id == req.repo_id)
            )
        ).scalar_one_or_none()
        if repo is None:
            raise HTTPException(status_code=404, detail="repo not found")

        if repo.project_id is not None:
            project = (
                await session.execute(
                    select(Project).where(Project.id == repo.project_id)
                )
            ).scalar_one_or_none()
            if project is None or project.owner_id != user.id:
                raise HTTPException(status_code=404, detail="repo not found")

    return await _scan_registered_repo_response(
        repo,
        await _get_repo_access_token(repo),
        req.lang,
    )


# ---------------------------------------------------------------------------
# POST /api/ext/scan/branch
# ---------------------------------------------------------------------------


@router.post("/scan/branch", response_model=ScanUrlResponse)
async def scan_branch(req: ScanBranchRequest) -> ScanUrlResponse:
    """Scan a raw unified diff (current branch). No auth required."""
    from aegis.pipeline.deterministic.secrets import scan_secrets
    from aegis.pipeline.simple_scan import _generate_scan_review, _run_llm
    from aegis.providers.diffparse import parse_unified_diff

    _SKIP_EXTENSIONS = {
        ".lock", ".sum", ".mod", ".min.js", ".min.css", ".map",
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf",
    }

    try:
        all_files = parse_unified_diff(req.diff)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Diff parse error: {exc}") from exc

    code_files = [
        f for f in all_files
        if not any(f.path.endswith(ext) for ext in _SKIP_EXTENSIONS) and f.hunks
    ]
    files_scanned = len(code_files)

    # Deterministic secrets scan
    det_findings = scan_secrets(code_files)

    all_findings, degraded_reasons = await _run_llm(
        req.repo_slug,
        0,
        code_files,
        det_findings,
        lang=req.lang,
    )
    _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    all_findings.sort(key=lambda f: _sev_order.get(f.severity, 9))

    scan_id = uuid.uuid4().hex
    summary, finding_labels = await _generate_scan_review(
        req.repo_slug,
        0,
        req.ref,
        files_scanned,
        all_findings,
        degraded_reasons,
        lang=req.lang,
    )
    findings_out = [
        FindingOut(
            fingerprint=f.fingerprint(),
            file=f.file,
            line=f.line,
            cwe=f.cwe,
            severity=f.severity.value,
            title=f.title,
            rationale=f.rationale,
            exploit=f.exploit,
            fix=f.fix,
            rule_id=f.rule_id,
            confidence=f.confidence,
            source=f.source.value,
            short_label=finding_labels.get(f.fingerprint()),
        )
        for f in all_findings
    ]

    await _persist_scan_result(
        scan_id=scan_id,
        provider="local",
        repo_slug=req.repo_slug,
        pr_id=req.ref,
        head_sha=req.ref,
        files_scanned=[f.path for f in code_files],
        degraded=degraded_reasons,
        findings=all_findings,
        summary=summary,
        finding_labels=finding_labels,
    )

    return ScanUrlResponse(
        scan_id=scan_id,
        repo=req.repo_slug,
        pr_number=0,
        pr_title=req.ref,
        pr_url="",
        pr_author="",
        files_scanned=files_scanned,
        degraded=bool(degraded_reasons),
        findings=findings_out,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# POST /api/ext/feedback
# ---------------------------------------------------------------------------


class FeedbackOut(BaseModel):
    ok: bool


@router.post("/feedback", response_model=FeedbackOut)
async def record_feedback(req: FeedbackRequest) -> FeedbackOut:
    """Record developer feedback (false positive, helpful). No auth required."""
    async with get_session() as session:
        session.add(
            Feedback(
                scan_id=req.scan_id,
                finding_fingerprint=req.fingerprint,
                kind=req.kind,
                author="extension",
            )
        )
        await session.flush()
    return FeedbackOut(ok=True)


# ---------------------------------------------------------------------------
# VS Code OAuth-style login page
# ---------------------------------------------------------------------------

_VSCODE_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to Aegis</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .card {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.10);
    padding: 40px 44px 36px;
    width: 100%;
    max-width: 400px;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 28px;
  }
  .logo svg { flex-shrink: 0; }
  .logo-text { font-size: 20px; font-weight: 700; color: #0f172a; letter-spacing: -0.3px; }
  h1 { font-size: 22px; font-weight: 700; color: #0f172a; margin-bottom: 6px; }
  .subtitle { font-size: 14px; color: #64748b; margin-bottom: 28px; line-height: 1.5; }
  .field { margin-bottom: 16px; }
  label { display: block; font-size: 13px; font-weight: 500; color: #374151; margin-bottom: 6px; }
  input {
    width: 100%;
    border: 1.5px solid #e2e8f0;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 15px;
    color: #0f172a;
    outline: none;
    transition: border-color 0.15s;
    background: #fff;
  }
  input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.12); }
  button {
    width: 100%;
    background: #0f172a;
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 11px 0;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
    margin-top: 8px;
  }
  button:hover { background: #1e293b; }
  button:disabled { background: #94a3b8; cursor: not-allowed; }
  .error {
    background: #fef2f2;
    border: 1px solid #fecaca;
    color: #dc2626;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13px;
    margin-bottom: 16px;
    display: none;
  }
  .success {
    text-align: center;
    display: none;
  }
  .success-icon {
    width: 56px; height: 56px;
    background: #dcfce7;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 16px;
  }
  .success h2 { font-size: 20px; font-weight: 700; color: #0f172a; margin-bottom: 8px; }
  .success p { font-size: 14px; color: #64748b; line-height: 1.6; }
  .manual-link { margin-top: 12px; }
  .manual-link a {
    font-size: 13px; color: #3b82f6; text-decoration: none; font-weight: 500;
  }
  .manual-link a:hover { text-decoration: underline; }
  .spinner {
    display: inline-block; width: 16px; height: 16px;
    border: 2px solid rgba(255,255,255,0.4);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle; margin-right: 6px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
      <path d="M16 2L4 7v9c0 7.18 5.2 13.9 12 15.5C22.8 29.9 28 23.18 28 16V7L16 2z"
            fill="#0f172a"/>
      <path d="M12 16l2.5 2.5 5.5-5.5" stroke="#fff" stroke-width="2.2"
            stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span class="logo-text">Aegis Security</span>
  </div>

  <div id="form-view">
    <h1>Sign in</h1>
    <p class="subtitle">Sign in to access security findings directly in VS Code.</p>

    <div id="error-box" class="error"></div>

    <div class="field">
      <label for="username">Username or email</label>
      <input id="username" type="text" autocomplete="username" autofocus
             placeholder="admin" />
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input id="password" type="password" autocomplete="current-password"
             placeholder="••••••••" />
    </div>
    <button id="submit-btn" type="button">Sign in</button>
  </div>

  <div id="success-view" class="success">
    <div class="success-icon">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
        <path d="M5 13l4 4L19 7" stroke="#16a34a" stroke-width="2.5"
              stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <h2>Signed in!</h2>
    <p>Returning to VS Code…<br>If nothing happens,
      <span class="manual-link"><a id="manual-link" href="#">click here</a></span>.
    </p>
  </div>
</div>

<script>
  const API_BASE = window.location.origin;

  async function doLogin() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const btn = document.getElementById('submit-btn');
    const errBox = document.getElementById('error-box');

    if (!username || !password) {
      showError('Please enter your username and password.');
      return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Signing in…';
    errBox.style.display = 'none';

    try {
      const res = await fetch(API_BASE + '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || 'Invalid credentials');
      }

      const { access_token } = await res.json();
      const vscodeUri = 'vscode://aegis.aegis-security/auth?token=' +
                        encodeURIComponent(access_token) +
                        '&username=' + encodeURIComponent(username);

      document.getElementById('manual-link').href = vscodeUri;
      document.getElementById('form-view').style.display = 'none';
      document.getElementById('success-view').style.display = 'block';

      // Redirect to VS Code
      window.location.href = vscodeUri;

    } catch (err) {
      showError(err.message || 'Sign in failed. Please try again.');
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  }

  function showError(msg) {
    const box = document.getElementById('error-box');
    box.textContent = msg;
    box.style.display = 'block';
  }

  document.getElementById('submit-btn').addEventListener('click', doLogin);
  document.getElementById('password').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doLogin();
  });
  document.getElementById('username').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('password').focus();
  });
</script>
</body>
</html>"""


@router.get("/auth/vscode-login", response_class=HTMLResponse)
async def vscode_login_page() -> HTMLResponse:
    """Browser-based login page that redirects to VS Code after successful auth."""
    return HTMLResponse(_VSCODE_LOGIN_HTML)
