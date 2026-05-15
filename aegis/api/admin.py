"""Backend REST API: user auth, projects, repos, scans (consumed by web + clients)."""

from __future__ import annotations

import hmac
import re
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from aegis.api.auth import issue_token, require_admin
from aegis.api.security import hash_password, require_user, verify_password
from aegis.config import get_settings
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
from aegis.schemas import Provider
from aegis.vault import encrypt

router = APIRouter(prefix="/api", tags=["api"])

# Module-level dependency singletons (avoids B008; mirrors aegis.api.auth style).
_user_dep = Depends(require_user)


class LoginRequest(BaseModel):
    username: str
    password: str


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=200)
    display_name: str = Field(default="", max_length=128)

    @field_validator("email")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("invalid email address")
        return v


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a password


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2000)


class ProjectOut(BaseModel):
    id: int
    name: str
    description: str
    repo_count: int
    created_at: str


class RepoCreate(BaseModel):
    provider: Provider
    external_id: str
    slug: str
    access_token: str = Field(min_length=1)
    webhook_secret: str = Field(min_length=1)
    severity_gate: str = "medium"
    merge_block: str = "critical"
    ignore_globs: list[str] = Field(default_factory=list)
    ensemble_profile: str = "det+don+judge"
    lang: str = "ru"


class RepoOut(BaseModel):
    id: int
    provider: str
    external_id: str
    slug: str
    status: str
    policy: dict[str, Any]


@router.post("/auth/register", response_model=LoginResponse, status_code=201)
async def register(req: RegisterRequest) -> LoginResponse:
    async with get_session() as session:
        dup = (
            await session.execute(select(User.id).where(User.email == req.email))
        ).scalar_one_or_none()
        if dup is not None:
            raise HTTPException(status_code=409, detail="email already registered")
        user = User(
            email=req.email,
            password_hash=hash_password(req.password),
            display_name=req.display_name or req.email.split("@")[0],
        )
        session.add(user)
        await session.flush()
    return LoginResponse(access_token=issue_token(req.email))


@router.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest) -> LoginResponse:
    """Authenticate a registered user by email; fall back to the bootstrap admin."""
    email = req.username.strip().lower()
    async with get_session() as session:
        user = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
    if user is not None and verify_password(req.password, user.password_hash):
        return LoginResponse(access_token=issue_token(user.email))

    # Bootstrap admin from env (control-plane access before any user exists).
    settings = get_settings()
    if (
        settings.admin_password
        and req.username == settings.admin_user
        and hmac.compare_digest(req.password, settings.admin_password)
    ):
        return LoginResponse(access_token=issue_token(req.username))
    raise HTTPException(status_code=401, detail="invalid credentials")


@router.post("/projects", response_model=ProjectOut, status_code=201)
async def create_project(
    req: ProjectCreate, user: User = _user_dep
) -> ProjectOut:
    async with get_session() as session:
        dup = (
            await session.execute(
                select(Project.id).where(
                    Project.owner_id == user.id, Project.name == req.name
                )
            )
        ).scalar_one_or_none()
        if dup is not None:
            raise HTTPException(status_code=409, detail="project name already exists")
        project = Project(
            owner_id=user.id, name=req.name, description=req.description
        )
        session.add(project)
        await session.flush()
        return ProjectOut(
            id=project.id, name=project.name, description=project.description,
            repo_count=0, created_at=project.created_at.isoformat(),
        )


@router.get("/projects", response_model=list[ProjectOut])
async def list_projects(user: User = _user_dep) -> list[ProjectOut]:
    async with get_session() as session:
        projects = (
            await session.execute(
                select(Project).where(Project.owner_id == user.id)
                .order_by(Project.created_at.desc())
            )
        ).scalars().all()
        out: list[ProjectOut] = []
        for p in projects:
            n = int(
                (
                    await session.execute(
                        select(func.count(Repository.id)).where(
                            Repository.project_id == p.id
                        )
                    )
                ).scalar_one()
            )
            out.append(ProjectOut(
                id=p.id, name=p.name, description=p.description,
                repo_count=n, created_at=p.created_at.isoformat(),
            ))
        return out


async def _owned_project(session: Any, project_id: int, user_id: int) -> Project:
    project = (
        await session.execute(select(Project).where(Project.id == project_id))
    ).scalar_one_or_none()
    if project is None or project.owner_id != user_id:
        raise HTTPException(status_code=404, detail="project not found")
    return cast(Project, project)


@router.get("/projects/{project_id}")
async def project_detail(
    project_id: int, user: User = _user_dep
) -> dict[str, Any]:
    async with get_session() as session:
        project = await _owned_project(session, project_id, user.id)
        repos = (
            await session.execute(
                select(Repository).where(Repository.project_id == project_id)
            )
        ).scalars().all()
        slugs = [r.slug for r in repos]
        scans = (
            (
                await session.execute(
                    select(Scan).where(Scan.repo_slug.in_(slugs))
                    .order_by(Scan.started_at.desc()).limit(50)
                )
            ).scalars().all()
            if slugs else []
        )
        return {
            "project": {
                "id": project.id,
                "name": project.name,
                "description": project.description,
            },
            "repos": [
                _repo_out(r, await _policy_for(session, r.id)).model_dump()
                for r in repos
            ],
            "scans": [
                {
                    "id": s.id, "repo_slug": s.repo_slug, "pr_id": s.pr_id,
                    "status": s.status, "risk_score": s.risk_score,
                    "risk_label": s.risk_label,
                    "started_at": s.started_at.isoformat(),
                }
                for s in scans
            ],
        }


@router.post("/projects/{project_id}/repos", response_model=RepoOut, status_code=201)
async def add_repo_to_project(
    project_id: int, req: RepoCreate, user: User = _user_dep
) -> RepoOut:
    async with get_session() as session:
        await _owned_project(session, project_id, user.id)
        existing = (
            await session.execute(
                select(Repository).where(
                    Repository.provider == req.provider.value,
                    Repository.external_id == req.external_id,
                )
            )
        ).scalar_one_or_none()
        repo = existing or Repository(
            provider=req.provider.value, external_id=req.external_id,
            slug=req.slug, status="active",
        )
        repo.slug = req.slug
        repo.project_id = project_id
        if existing is None:
            session.add(repo)
            await session.flush()
        session.add(RepoSecret(
            repo_id=repo.id, kind="access_token",
            ciphertext=encrypt(req.access_token),
        ))
        session.add(RepoSecret(
            repo_id=repo.id, kind="webhook_secret",
            ciphertext=encrypt(req.webhook_secret),
        ))
        policy = (
            await session.execute(
                select(RepoPolicy).where(RepoPolicy.repo_id == repo.id)
            )
        ).scalar_one_or_none() or RepoPolicy(repo_id=repo.id)
        policy.severity_gate = req.severity_gate
        policy.merge_block = req.merge_block
        policy.ignore_globs = req.ignore_globs
        policy.ensemble_profile = req.ensemble_profile
        policy.lang = req.lang
        session.add(policy)
        await session.flush()
        return _repo_out(repo, policy)


@router.get("/repos", response_model=list[RepoOut])
async def list_repos(_: str = Depends(require_admin)) -> list[RepoOut]:
    async with get_session() as session:
        repos = (await session.execute(select(Repository))).scalars().all()
        return [
            _repo_out(repo, await _policy_for(session, repo.id))
            for repo in repos
        ]


@router.post("/repos", response_model=RepoOut)
async def create_repo(req: RepoCreate, actor: str = Depends(require_admin)) -> RepoOut:
    async with get_session() as session:
        existing = (
            await session.execute(
                select(Repository).where(
                    Repository.provider == req.provider.value,
                    Repository.external_id == req.external_id,
                )
            )
        ).scalar_one_or_none()
        repo = existing or Repository(
            provider=req.provider.value,
            external_id=req.external_id,
            slug=req.slug,
            status="active",
        )
        repo.slug = req.slug
        if existing is None:
            session.add(repo)
            await session.flush()
        session.add(
            RepoSecret(
                repo_id=repo.id,
                kind="access_token",
                ciphertext=encrypt(req.access_token),
            )
        )
        session.add(
            RepoSecret(
                repo_id=repo.id,
                kind="webhook_secret",
                ciphertext=encrypt(req.webhook_secret),
            )
        )
        policy = (
            await session.execute(
                select(RepoPolicy).where(RepoPolicy.repo_id == repo.id)
            )
        ).scalar_one_or_none() or RepoPolicy(repo_id=repo.id)
        policy.severity_gate = req.severity_gate
        policy.merge_block = req.merge_block
        policy.ignore_globs = req.ignore_globs
        policy.ensemble_profile = req.ensemble_profile
        policy.lang = req.lang
        session.add(policy)
        await session.flush()
        _ = actor
        return _repo_out(repo, policy)


@router.get("/scans")
async def list_scans(_: str = Depends(require_admin)) -> list[dict[str, Any]]:
    async with get_session() as session:
        rows = (
            await session.execute(select(Scan).order_by(Scan.started_at.desc()).limit(100))
        ).scalars().all()
        return [
            {
                "id": s.id,
                "provider": s.provider,
                "repo_slug": s.repo_slug,
                "pr_id": s.pr_id,
                "status": s.status,
                "risk_score": s.risk_score,
                "risk_label": s.risk_label,
                "started_at": s.started_at.isoformat(),
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in rows
        ]


@router.get("/scans/{scan_id}")
async def scan_detail(scan_id: str, _: str = Depends(require_admin)) -> dict[str, Any]:
    async with get_session() as session:
        scan = (await session.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        findings = (
            await session.execute(select(FindingRow).where(FindingRow.scan_id == scan_id))
        ).scalars().all()
        return {
            "scan": {
                "id": scan.id,
                "status": scan.status,
                "risk_score": scan.risk_score,
                "risk_label": scan.risk_label,
                "decision": scan.decision,
                "files_scanned": scan.files_scanned,
                "files_skipped": scan.files_skipped,
                "degraded": scan.degraded,
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
                    "fix": f.fix,
                }
                for f in findings
            ],
        }


@router.get("/stats")
async def stats(_: str = Depends(require_admin)) -> dict[str, Any]:
    async with get_session() as session:
        scans = int((await session.execute(select(func.count(Scan.id)))).scalar_one())
        findings = int((await session.execute(select(func.count(FindingRow.id)))).scalar_one())
        blocked = int(
            (
                await session.execute(
                    select(func.count(Scan.id)).where(Scan.risk_label.in_(["high", "critical"]))
                )
            ).scalar_one()
        )
        return {"scans": scans, "findings": findings, "blocked_or_high_risk": blocked}


async def _policy_for(session: Any, repo_id: int) -> RepoPolicy | None:
    row = (
        await session.execute(
            select(RepoPolicy).where(RepoPolicy.repo_id == repo_id)
        )
    ).scalar_one_or_none()
    return cast("RepoPolicy | None", row)


def _repo_out(repo: Repository, policy: RepoPolicy | None = None) -> RepoOut:
    return RepoOut(
        id=repo.id,
        provider=repo.provider,
        external_id=repo.external_id,
        slug=repo.slug,
        status=repo.status,
        policy={
            "severity_gate": policy.severity_gate if policy else "medium",
            "merge_block": policy.merge_block if policy else "critical",
            "ignore_globs": policy.ignore_globs if policy else [],
            "ensemble_profile": policy.ensemble_profile if policy else "det+don+judge",
            "lang": policy.lang if policy else "ru",
        },
    )
