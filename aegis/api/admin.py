"""Backend REST API consumed by the Admin Portal frontend."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from aegis.api.auth import issue_token, require_admin
from aegis.config import get_settings
from aegis.db import get_session
from aegis.db.models import FindingRow, RepoPolicy, RepoSecret, Repository, Scan
from aegis.schemas import Provider
from aegis.vault import encrypt

router = APIRouter(prefix="/api", tags=["admin"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a password


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


@router.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest) -> LoginResponse:
    settings = get_settings()
    if not settings.admin_password:
        raise HTTPException(status_code=503, detail="admin password is not configured")
    if req.username != settings.admin_user or not hmac.compare_digest(
        req.password, settings.admin_password
    ):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return LoginResponse(access_token=issue_token(req.username))


@router.get("/repos", response_model=list[RepoOut])
async def list_repos(_: str = Depends(require_admin)) -> list[RepoOut]:
    async with get_session() as session:
        repos = (await session.execute(select(Repository))).scalars().all()
        return [_repo_out(repo) for repo in repos]


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
        policy = repo.policy or RepoPolicy(repo_id=repo.id)
        policy.severity_gate = req.severity_gate
        policy.merge_block = req.merge_block
        policy.ignore_globs = req.ignore_globs
        policy.ensemble_profile = req.ensemble_profile
        policy.lang = req.lang
        session.add(policy)
        await session.flush()
        _ = actor
        return _repo_out(repo)


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


def _repo_out(repo: Repository) -> RepoOut:
    policy = repo.policy
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
