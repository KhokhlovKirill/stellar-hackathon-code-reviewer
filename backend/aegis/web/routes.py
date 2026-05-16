"""Web control plane routes: register → login → projects → scans.

Forms post to these routes; on success we set the httponly session cookie and
redirect (POST-redirect-GET). Every page except auth requires a logged-in user.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import func, select

from aegis.api.auth import issue_token
from aegis.api.security import (
    SESSION_COOKIE,
    current_user_web,
    hash_password,
    require_user_web,
    verify_password,
)
from aegis.db import get_session
from aegis.db.models import (
    FindingRow,
    Project,
    RepoPolicy,
    RepoSecret,
    Repository,
    Scan,
    User,
)
from aegis.obs import get_logger
from aegis.schemas import Provider
from aegis.vault import encrypt

log = get_logger("aegis.web")
router = APIRouter(tags=["web"])


def _templates_dir() -> Path:
    configured = Path(os.environ.get("AEGIS_FRONTEND_TEMPLATES", "../frontend/templates"))
    if configured.is_absolute():
        return configured
    backend_root = Path(__file__).resolve().parents[2]
    return (backend_root / configured).resolve()


templates = Jinja2Templates(directory=str(_templates_dir()))

# Dependency singletons (avoids B008; mirrors aegis.api.auth style).
_user_web = Depends(require_user_web)
_user_opt = Depends(current_user_web)

_EMAIL_OK = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _set_session(resp: RedirectResponse, email: str) -> RedirectResponse:
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=issue_token(email),
        httponly=True,
        samesite="lax",
        max_age=86_400,
        path="/",
    )
    return resp


def _page(request: Request, name: str, **ctx: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, name, ctx)


# ----------------------------------------------------------------------------- #
# Auth
# ----------------------------------------------------------------------------- #
@router.get("/", response_class=HTMLResponse)
async def index(user: User | None = _user_opt) -> RedirectResponse:
    target = "/dashboard" if user else "/login"
    return RedirectResponse(target, status_code=303)


@router.get("/register", response_class=HTMLResponse)
async def register_form(request: Request) -> HTMLResponse:
    return _page(request, "register.html", error=None)


@router.post("/register")
async def register_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(""),
) -> Any:
    email = email.strip().lower()
    if not _EMAIL_OK.match(email):
        return _page(request, "register.html", error="Enter a valid email address.")
    if len(password) < 8:
        return _page(request, "register.html",
                     error="Password must be at least 8 characters.")
    async with get_session() as s:
        dup = (
            await s.execute(select(User.id).where(User.email == email))
        ).scalar_one_or_none()
        if dup is not None:
            return _page(request, "register.html",
                         error="That email is already registered.")
        s.add(User(
            email=email,
            password_hash=hash_password(password),
            display_name=display_name.strip() or email.split("@")[0],
        ))
    log.info("web.user_registered", email=email)
    return _set_session(RedirectResponse("/dashboard", status_code=303), email)


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request) -> HTMLResponse:
    return _page(request, "login.html", error=None)


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
) -> Any:
    email = email.strip().lower()
    async with get_session() as s:
        user = (
            await s.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
    if user is None or not verify_password(password, user.password_hash):
        return _page(request, "login.html", error="Invalid email or password.")
    return _set_session(RedirectResponse("/dashboard", status_code=303), email)


@router.get("/logout")
async def logout() -> RedirectResponse:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# ----------------------------------------------------------------------------- #
# Projects
# ----------------------------------------------------------------------------- #
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request, user: User = _user_web
) -> HTMLResponse:
    async with get_session() as s:
        projects = (
            await s.execute(
                select(Project).where(Project.owner_id == user.id)
                .order_by(Project.created_at.desc())
            )
        ).scalars().all()
        rows = []
        for p in projects:
            n = int((await s.execute(
                select(func.count(Repository.id)).where(Repository.project_id == p.id)
            )).scalar_one())
            rows.append({"id": p.id, "name": p.name,
                         "description": p.description, "repo_count": n})
    return _page(request, "dashboard.html", user=user, projects=rows)


@router.post("/projects")
async def create_project_submit(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    user: User = _user_web,
) -> Any:
    name = name.strip()
    if not name:
        return RedirectResponse("/dashboard", status_code=303)
    async with get_session() as s:
        dup = (await s.execute(
            select(Project.id).where(
                Project.owner_id == user.id, Project.name == name
            )
        )).scalar_one_or_none()
        if dup is not None:
            return RedirectResponse(f"/projects/{dup}", status_code=303)
        project = Project(owner_id=user.id, name=name,
                           description=description.strip())
        s.add(project)
        await s.flush()
        pid = project.id
    log.info("web.project_created", owner=user.email, project=name)
    return RedirectResponse(f"/projects/{pid}", status_code=303)


async def _owned(s: Any, project_id: int, user_id: int) -> Project | None:
    p = (
        await s.execute(select(Project).where(Project.id == project_id))
    ).scalar_one_or_none()
    return p if (p and p.owner_id == user_id) else None


@router.get("/projects/{project_id}", response_class=HTMLResponse)
async def project_detail(
    request: Request, project_id: int, user: User = _user_web
) -> Any:
    async with get_session() as s:
        project = await _owned(s, project_id, user.id)
        if project is None:
            return RedirectResponse("/dashboard", status_code=303)
        repos = (await s.execute(
            select(Repository).where(Repository.project_id == project_id)
        )).scalars().all()
        slugs = [r.slug for r in repos]
        scans = (
            (await s.execute(
                select(Scan).where(Scan.repo_slug.in_(slugs))
                .order_by(Scan.started_at.desc()).limit(50)
            )).scalars().all()
            if slugs else []
        )
        repo_rows = [
            {"id": r.id, "provider": r.provider, "slug": r.slug,
             "status": r.status} for r in repos
        ]
        scan_rows = [
            {"id": s_.id, "repo_slug": s_.repo_slug, "pr_id": s_.pr_id,
             "status": s_.status, "risk_score": s_.risk_score,
             "risk_label": s_.risk_label,
             "started_at": s_.started_at.strftime("%Y-%m-%d %H:%M")}
            for s_ in scans
        ]
    return _page(request, "project.html", user=user, project=project,
                 repos=repo_rows, scans=scan_rows,
                 providers=[p.value for p in Provider])


@router.post("/projects/{project_id}/repos")
async def add_repo_submit(
    request: Request,
    project_id: int,
    provider: str = Form(...),
    external_id: str = Form(...),
    slug: str = Form(...),
    access_token: str = Form(...),
    webhook_secret: str = Form(...),
    severity_gate: str = Form("medium"),
    merge_block: str = Form("critical"),
    user: User = _user_web,
) -> Any:
    try:
        prov = Provider(provider)
    except ValueError:
        return RedirectResponse(f"/projects/{project_id}", status_code=303)
    async with get_session() as s:
        if await _owned(s, project_id, user.id) is None:
            return RedirectResponse("/dashboard", status_code=303)
        existing = (await s.execute(
            select(Repository).where(
                Repository.provider == prov.value,
                Repository.external_id == external_id.strip(),
            )
        )).scalar_one_or_none()
        repo = existing or Repository(
            provider=prov.value, external_id=external_id.strip(),
            slug=slug.strip(), status="active",
        )
        repo.slug = slug.strip()
        repo.project_id = project_id
        if existing is None:
            s.add(repo)
            await s.flush()
        s.add(RepoSecret(repo_id=repo.id, kind="access_token",
                         ciphertext=encrypt(access_token)))
        s.add(RepoSecret(repo_id=repo.id, kind="webhook_secret",
                         ciphertext=encrypt(webhook_secret)))
        policy = (
            await s.execute(
                select(RepoPolicy).where(RepoPolicy.repo_id == repo.id)
            )
        ).scalar_one_or_none() or RepoPolicy(repo_id=repo.id)
        policy.severity_gate = severity_gate
        policy.merge_block = merge_block
        s.add(policy)
    log.info("web.repo_added", project_id=project_id, slug=slug)
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


@router.post("/projects/{project_id}/quick-connect")
async def quick_connect_submit(
    request: Request,
    project_id: int,
    repo_url: str = Form(...),
    access_token: str = Form(...),
    public_url: str = Form(...),
    severity_gate: str = Form("medium"),
    merge_block: str = Form("critical"),
    user: User = _user_web,
) -> Any:
    import re
    import secrets as _secrets

    import httpx

    from aegis.vault import encrypt

    async with get_session() as s:
        if await _owned(s, project_id, user.id) is None:
            return RedirectResponse("/dashboard", status_code=303)

    # parse slug from URL
    url = repo_url.strip().rstrip("/")
    m = re.search(r"github\.com/([^/]+/[^/]+)", url)
    if not m:
        slug_raw = url
    else:
        slug_raw = m.group(1).removesuffix(".git")

    _gh_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }

    # fetch repo info
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://api.github.com/repos/{slug_raw}", headers=_gh_headers
            )
        if r.status_code != 200:
            msg = r.json().get("message", "")
            return _page(request, "project.html",
                         user=user,
                         project={"id": project_id, "name": "", "description": ""},
                         repos=[], scans=[],
                         providers=[p.value for p in Provider],
                         qc_error=f"GitHub API error {r.status_code}: {msg}")
        info = r.json()
    except httpx.HTTPError as exc:
        return _page(request, "project.html",
                     user=user,
                     project={"id": project_id, "name": "", "description": ""},
                     repos=[], scans=[],
                     providers=[p.value for p in Provider],
                     qc_error=f"Network error: {exc}")

    external_id = str(info["id"])
    canonical_slug = info["full_name"]
    webhook_secret_val = _secrets.token_hex(24)
    webhook_url = f"{public_url.rstrip('/')}/webhooks/github"

    # register webhook on GitHub
    hook_id = None
    async with httpx.AsyncClient(timeout=15) as client:
        hr = await client.post(
            f"https://api.github.com/repos/{canonical_slug}/hooks",
            headers=_gh_headers,
            json={
                "name": "web", "active": True, "events": ["pull_request"],
                "config": {
                    "url": webhook_url, "content_type": "json",
                    "secret": webhook_secret_val, "insecure_ssl": "0",
                },
            },
        )
    if hr.status_code in (200, 201):
        hook_id = hr.json().get("id")

    async with get_session() as s:
        existing = (await s.execute(
            select(Repository).where(
                Repository.provider == Provider.GITHUB.value,
                Repository.external_id == external_id,
            )
        )).scalar_one_or_none()
        repo = existing or Repository(
            provider=Provider.GITHUB.value, external_id=external_id,
            slug=canonical_slug, status="active",
        )
        repo.slug = canonical_slug
        repo.project_id = project_id
        if existing is None:
            s.add(repo)
            await s.flush()
        s.add(RepoSecret(
            repo_id=repo.id, kind="access_token", ciphertext=encrypt(access_token)
        ))
        s.add(RepoSecret(
            repo_id=repo.id, kind="webhook_secret", ciphertext=encrypt(webhook_secret_val)
        ))
        policy = (
            await s.execute(select(RepoPolicy).where(RepoPolicy.repo_id == repo.id))
        ).scalar_one_or_none() or RepoPolicy(repo_id=repo.id)
        policy.severity_gate = severity_gate
        policy.merge_block = merge_block
        s.add(policy)
        await s.flush()

    log.info("web.quick_connect", project_id=project_id, slug=canonical_slug,
             hook_id=hook_id, webhook_url=webhook_url)

    if hook_id:
        hook_status = f"webhook #{hook_id} registered automatically"
    else:
        hook_status = "webhook NOT registered (token needs admin:repo_hook scope)"
    return _page(request, "quick_connect_done.html",
                 user=user,
                 slug=canonical_slug,
                 webhook_url=webhook_url,
                 hook_status=hook_status,
                 project_id=project_id)


@router.get("/review", response_class=HTMLResponse)
async def review_form(request: Request, user: User | None = _user_opt) -> HTMLResponse:
    return _page(request, "review.html", user=user, result=None, error=None, url="")


@router.post("/review", response_class=HTMLResponse)
async def review_submit(
    request: Request,
    repo_url: str = Form(...),
    token: str = Form(""),
    user: User | None = _user_opt,
) -> HTMLResponse:
    from aegis.api.extension import _persist_scan_result
    from aegis.pipeline.dispatch import run_scan

    url = repo_url.strip()
    if not url:
        return _page(request, "review.html", user=user, result=None,
                     error="Please enter a GitHub URL", url="")

    log.info("web.simple_scan", url=url)
    from aegis.config import get_config
    result = await run_scan(
        url,
        token=token.strip() or None,
        lang=get_config().policy.comment_language,
    )

    if result.error:
        return _page(request, "review.html", user=user, result=None,
                     error=result.error, url=url)

    result.scan_id = uuid.uuid4().hex
    await _persist_scan_result(
        scan_id=result.scan_id,
        provider="github",
        repo_slug=result.repo,
        pr_id=str(result.pr_number),
        head_sha=result.head_sha,
        files_scanned=result.files_scanned_paths,
        degraded=result.degraded_reasons,
        findings=result.findings,
        summary=result.summary,
        finding_labels=result.finding_labels,
    )

    return _page(request, "review.html", user=user, result=result, error=None, url=url)


# ----------------------------------------------------------------------------- #
# Chat
# ----------------------------------------------------------------------------- #
@router.get("/chat", response_class=HTMLResponse)
async def chat_page(
    request: Request,
    scan_id: str | None = None,
    fingerprint: str | None = None,
    prompt: str | None = None,
    user: User = _user_web,
) -> HTMLResponse:
    """Chat page — optionally pre-loaded with a finding context."""
    finding_data: dict[str, Any] | None = None
    scan_data: dict[str, Any] | None = None

    if scan_id:
        async with get_session() as s:
            if fingerprint:
                f_row = (
                    await s.execute(
                        select(FindingRow).where(
                            FindingRow.scan_id == scan_id,
                            FindingRow.fingerprint == fingerprint,
                        )
                    )
                ).scalar_one_or_none()
                if f_row:
                    finding_data = {
                        "fingerprint": f_row.fingerprint,
                        "file": f_row.file,
                        "line": f_row.line,
                        "cwe": f_row.cwe,
                        "severity": f_row.severity,
                        "title": f_row.title,
                        "rationale": f_row.rationale,
                        "exploit": f_row.exploit,
                        "fix": f_row.fix,
                    }
            sc = (
                await s.execute(select(Scan).where(Scan.id == scan_id))
            ).scalar_one_or_none()
            if sc:
                f_rows = (
                    await s.execute(select(FindingRow).where(FindingRow.scan_id == scan_id))
                ).scalars().all()
                scan_data = {
                    "id": sc.id,
                    "scan_id": sc.id,
                    "repo_slug": sc.repo_slug,
                    "repo": sc.repo_slug,
                    "pr_id": sc.pr_id,
                    "pr_number": int(sc.pr_id) if str(sc.pr_id).isdigit() else 0,
                    "pr_title": f"PR #{sc.pr_id}",
                    "pr_url": "",
                    "pr_author": "",
                    "summary": (sc.decision or {}).get("summary", ""),
                    "risk_score": sc.risk_score,
                    "risk_label": sc.risk_label,
                    "files_scanned": len(sc.files_scanned or []),
                    "degraded": bool(sc.degraded),
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
                        }
                        for f in f_rows
                    ],
                }

    finding_json = json.dumps(finding_data) if finding_data else "null"
    scan_json = json.dumps(scan_data) if scan_data else "null"
    return _page(
        request,
        "chat.html",
        user=user,
        finding=finding_data,
        scan=scan_data,
        finding_json=finding_json,
        scan_json=scan_json,
        initial_prompt=prompt or "",
    )


class _WebChatHistoryItem(BaseModel):
    role: str
    content: str


class _WebChatRequest(BaseModel):
    finding: dict[str, Any] | None = None
    scan: dict[str, Any] | None = None
    repo: str = ""
    message: str
    history: list[_WebChatHistoryItem] = []
    lang: str = "ru"


@router.post("/api/web/chat/stream")
async def web_chat_stream(
    req: _WebChatRequest, user: User = _user_web
) -> StreamingResponse:
    """SSE streaming chat endpoint for the web UI (session-cookie auth)."""
    from aegis.api.extension import ChatFinding, ChatHistoryItem, ChatRequest, ChatScan
    from aegis.llm.router import LLMRouter

    chat_finding: ChatFinding | None = None
    if req.finding:
        try:
            chat_finding = ChatFinding(**req.finding)
        except Exception:
            chat_finding = None
    chat_scan: ChatScan | None = None
    if req.scan:
        try:
            chat_scan = ChatScan(**req.scan)
        except Exception:
            chat_scan = None

    ext_req = ChatRequest(
        finding=chat_finding,
        scan=chat_scan,
        repo=req.repo,
        message=req.message,
        history=[ChatHistoryItem(role=h.role, content=h.content) for h in req.history],
        lang=req.lang if req.lang in ("ru", "en") else "ru",
    )

    from aegis.api.extension import _build_chat_messages
    messages = _build_chat_messages(ext_req)
    router_obj = LLMRouter()

    async def event_generator() -> AsyncIterator[str]:
        try:
            async for token in router_obj.stream_chat(
                role="judge", messages=messages, max_tokens=2048
            ):
                payload = json.dumps({"token": token}, ensure_ascii=False)
                yield f"data: {payload}\n\n"
        except Exception as exc:
            log.warning("web.chat_stream.failed", error=str(exc))
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        finally:
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    request: Request, scan_id: str, user: User = _user_web
) -> Any:
    async with get_session() as s:
        scan = (
            await s.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one_or_none()
        if scan is None:
            return RedirectResponse("/dashboard", status_code=303)
        # Ownership: the scan's repo must belong to a project owned by the user.
        repo = (await s.execute(
            select(Repository).where(Repository.slug == scan.repo_slug)
        )).scalars().first()
        owned = False
        if repo is not None and repo.project_id is not None:
            owned = await _owned(s, repo.project_id, user.id) is not None
        if not owned:
            return RedirectResponse("/dashboard", status_code=303)
        findings = (await s.execute(
            select(FindingRow).where(FindingRow.scan_id == scan_id)
            .order_by(FindingRow.severity.desc())
        )).scalars().all()
        labels = (scan.decision or {}).get("finding_labels", {})
        if not isinstance(labels, dict):
            labels = {}
        f_rows = [
            {"fingerprint": f.fingerprint, "file": f.file, "line": f.line, "cwe": f.cwe,
             "severity": f.severity, "title": f.title,
             "rationale": f.rationale, "fix": f.fix,
             "source": f.source, "confidence": f.confidence,
             "short_label": labels.get(f.fingerprint)}
            for f in findings
        ]
        scan_row = {
            "id": scan.id, "repo_slug": scan.repo_slug, "pr_id": scan.pr_id,
            "status": scan.status, "risk_score": scan.risk_score,
            "risk_label": scan.risk_label,
            "files_scanned": scan.files_scanned,
            "files_skipped": scan.files_skipped,
            "degraded": scan.degraded,
            "decision": scan.decision or {},
        }
    return _page(request, "scan.html", user=user, scan=scan_row, findings=f_rows)
