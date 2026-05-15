"""Web control plane routes: register → login → projects → scans.

Forms post to these routes; on success we set the httponly session cookie and
redirect (POST-redirect-GET). Every page except auth requires a logged-in user.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
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
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

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
        policy = repo.policy or RepoPolicy(repo_id=repo.id)
        policy.severity_gate = severity_gate
        policy.merge_block = merge_block
        s.add(policy)
    log.info("web.repo_added", project_id=project_id, slug=slug)
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


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
        f_rows = [
            {"file": f.file, "line": f.line, "cwe": f.cwe,
             "severity": f.severity, "title": f.title,
             "rationale": f.rationale, "fix": f.fix}
            for f in findings
        ]
        scan_row = {
            "id": scan.id, "repo_slug": scan.repo_slug, "pr_id": scan.pr_id,
            "status": scan.status, "risk_score": scan.risk_score,
            "risk_label": scan.risk_label,
            "files_scanned": scan.files_scanned,
            "files_skipped": scan.files_skipped,
            "degraded": scan.degraded,
        }
    return _page(request, "scan.html", user=user, scan=scan_row, findings=f_rows)
