<<<<<<< Updated upstream
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
=======
"""Admin REST API endpoints for repositories, scans, findings, and knowledge base."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.api.auth import get_current_user
from aegis.db.session import get_db
from aegis.observability.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api", tags=["admin"])

# Auth dependency shorthand
Auth = Annotated[dict, Depends(get_current_user)]


# ── Pydantic Models ───────────────────────────────────────────────────────────

class RegisterRepoRequest(BaseModel):
    provider: str  # "github" | "gitlab"
    full_name: str  # "org/repo"
    access_token: str
    webhook_secret: str | None = None
    settings: dict = {}


class RepoResponse(BaseModel):
    id: str
    provider: str
    full_name: str
    active: bool
    created_at: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    current_node: str | None
    risk_score: int | None
    findings: int | None
    created_at: str


class FindingResponse(BaseModel):
    id: str
    file_path: str
    line_number: int | None
    vuln_type: str
    severity: str
    cwe: str | None
    description: str
    source: str


class HumanReviewRequest(BaseModel):
    decision: str  # "approved" | "rejected" | "ignored"
    reason: str | None = None


class FalsePositiveRequest(BaseModel):
    pattern: str
    directory: str | None = None
    reason: str | None = None


# ── Repository Management ─────────────────────────────────────────────────────

@router.post("/repos", response_model=RepoResponse)
async def register_repo(request: RegisterRepoRequest, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """Register a repository for security scanning."""
    from aegis.db.models import Repository
    from sqlalchemy import select
    from cryptography.fernet import Fernet
    from aegis.config import get_settings

    settings = get_settings()
    f = Fernet(settings.fernet_key.encode())

    # Encrypt tokens
    encrypted_token = f.encrypt(request.access_token.encode()).decode()
    encrypted_secret = f.encrypt(request.webhook_secret.encode()).decode() if request.webhook_secret else None

    # Check if already registered
    existing = await db.execute(
        select(Repository).where(
            Repository.provider == request.provider,
            Repository.full_name == request.full_name,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Repository already registered")

    repo = Repository(
        id=uuid.uuid4(),
        provider=request.provider,
        full_name=request.full_name,
        access_token=encrypted_token,
        webhook_secret=encrypted_secret,
        settings_json=request.settings,
        active=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(repo)
    await db.commit()
    await db.refresh(repo)

    log.info("admin.repo_registered", repo=request.full_name)
    return RepoResponse(
        id=str(repo.id),
        provider=repo.provider,
        full_name=repo.full_name,
        active=repo.active,
        created_at=repo.created_at.isoformat(),
    )


@router.get("/repos", response_model=list[RepoResponse])
async def list_repos(user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """List all registered repositories."""
    from aegis.db.models import Repository
    from sqlalchemy import select

    result = await db.execute(select(Repository).order_by(Repository.created_at.desc()))
    repos = result.scalars().all()
    return [
        RepoResponse(
            id=str(r.id),
            provider=r.provider,
            full_name=r.full_name,
            active=r.active,
            created_at=r.created_at.isoformat(),
        )
        for r in repos
    ]


@router.delete("/repos/{repo_id}", status_code=204)
async def delete_repo(repo_id: str, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """Remove a registered repository."""
    from aegis.db.models import Repository
    from sqlalchemy import select

    result = await db.execute(select(Repository).where(Repository.id == uuid.UUID(repo_id)))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    await db.delete(repo)
    await db.commit()


# ── Scan Management ───────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """Get the status of a specific scan."""
    from aegis.db.models import GraphExecution, PullRequest
    from sqlalchemy import select

    result = await db.execute(
        select(GraphExecution).where(GraphExecution.scan_id == scan_id)
    )
    execution = result.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Scan not found")

    pr_result = await db.execute(select(PullRequest).where(PullRequest.id == execution.pr_id))
    pr = pr_result.scalar_one_or_none()

    return ScanStatusResponse(
        scan_id=execution.scan_id,
        status=execution.status,
        current_node=execution.current_node,
        risk_score=pr.risk_score if pr else None,
        findings=pr.finding_count if pr else None,
        created_at=execution.created_at.isoformat(),
    )


@router.post("/scans/{scan_id}/cancel", status_code=202)
async def cancel_scan(scan_id: str, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """Cancel a running scan."""
    from aegis.db.models import GraphExecution
    from sqlalchemy import update

    await db.execute(
        update(GraphExecution)
        .where(GraphExecution.scan_id == scan_id, GraphExecution.status == "running")
        .values(status="cancelled", updated_at=datetime.now(timezone.utc))
    )
    await db.commit()
    return {"status": "cancelled", "scan_id": scan_id}


# ── Human Review ──────────────────────────────────────────────────────────────

@router.post("/human-review/{scan_id}", status_code=202)
async def submit_human_review(
    scan_id: str,
    request: HumanReviewRequest,
    user: Auth,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Submit a human review decision to resume a paused graph."""
    from aegis.db.models import HumanReview, GraphExecution
    from aegis.graph.runtime import resume_graph
    from sqlalchemy import select

    if request.decision not in ("approved", "rejected", "ignored"):
        raise HTTPException(status_code=400, detail="Decision must be: approved, rejected, or ignored")

    # Find the execution
    result = await db.execute(
        select(GraphExecution).where(GraphExecution.scan_id == scan_id)
    )
    execution = result.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Save review
    review = HumanReview(
        id=uuid.uuid4(),
        scan_id=scan_id,
        pr_id=execution.pr_id,
        decision=request.decision,
        reviewer=user.get("sub", "unknown"),
        reason=request.reason or "",
        created_at=datetime.now(timezone.utc),
    )
    db.add(review)

    from sqlalchemy import update
    await db.execute(
        update(GraphExecution)
        .where(GraphExecution.scan_id == scan_id)
        .values(status="resuming")
    )
    await db.commit()

    # Resume graph
    try:
        await resume_graph(
            thread_id=scan_id,
            update={"human_decision": request.decision},
        )
    except Exception as exc:
        log.error("admin.resume_error", scan_id=scan_id, error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to resume graph: {exc}")

    return {"status": "resumed", "scan_id": scan_id, "decision": request.decision}


# ── Findings ──────────────────────────────────────────────────────────────────

@router.get("/prs/{pr_id}/findings", response_model=list[FindingResponse])
async def get_pr_findings(
    pr_id: str,
    user: Auth,
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
):
    """Get findings for a specific PR."""
    from aegis.db.models import Finding
    from sqlalchemy import select

    stmt = select(Finding).where(Finding.pr_id == uuid.UUID(pr_id))
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    stmt = stmt.order_by(Finding.severity.desc()).offset(offset).limit(limit)

    result = await db.execute(stmt)
    findings = result.scalars().all()

    return [
        FindingResponse(
            id=str(f.id),
            file_path=f.file_path,
            line_number=f.line_number,
            vuln_type=f.vuln_type,
            severity=f.severity,
            cwe=f.cwe,
            description=f.description,
            source=f.source or "unknown",
        )
        for f in findings
    ]


# ── False Positives ───────────────────────────────────────────────────────────

@router.post("/repos/{repo_id}/false-positives", status_code=201)
async def add_false_positive(
    repo_id: str,
    request: FalsePositiveRequest,
    user: Auth,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Add a false positive rule for a repository."""
    from aegis.db.models import FalsePositive

    fp = FalsePositive(
        id=uuid.uuid4(),
        repo_id=uuid.UUID(repo_id),
        pattern=request.pattern,
        directory=request.directory or "",
        reason=request.reason or "",
        created_at=datetime.now(timezone.utc),
    )
    db.add(fp)
    await db.commit()

    return {"status": "created", "id": str(fp.id)}


@router.get("/repos/{repo_id}/false-positives")
async def list_false_positives(
    repo_id: str,
    user: Auth,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all false positive rules for a repository."""
    from aegis.db.models import FalsePositive
    from sqlalchemy import select

    result = await db.execute(
        select(FalsePositive).where(FalsePositive.repo_id == uuid.UUID(repo_id))
    )
    fps = result.scalars().all()

    return [
        {"id": str(fp.id), "pattern": fp.pattern, "directory": fp.directory, "reason": fp.reason}
        for fp in fps
    ]


# ── Knowledge Base ────────────────────────────────────────────────────────────

@router.get("/kb/search")
async def search_knowledge_base(
    q: str = Query(..., min_length=3),
    top_k: int = Query(5, le=20),
    user: Auth = None,
):
    """Semantic search in the knowledge base."""
    from aegis.knowledge.retrieval import search_similar

    results = await search_similar(q, top_k=top_k)
    return {"query": q, "results": results}


@router.get("/kb")
async def list_kb_entries(
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    user: Auth = None,
):
    """List knowledge base entries."""
    from aegis.knowledge.kb import list_kb_entries as _list

    entries = await _list(limit=limit, offset=offset)
    return {"entries": entries, "count": len(entries)}


# ── Retro Scan ────────────────────────────────────────────────────────────────

@router.post("/repos/{repo_id}/retroscan", status_code=202)
async def trigger_retro_scan(
    repo_id: str,
    user: Auth,
    days_back: int = Query(30, le=365),
    limit: int = Query(50, le=200),
):
    """Trigger a retro scan of historical PRs."""
    from aegis.graph.subgraphs.retro_scan import run_retro_scan

    summary = await run_retro_scan(repo_id=repo_id, days_back=days_back, limit=limit)
    return {"status": "initiated", "repo_id": repo_id, **summary}


# ── Statistics ────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """Get aggregate scan statistics."""
    from aegis.db.models import Repository, PullRequest, Finding, GraphExecution
    from sqlalchemy import select, func

    repo_count = (await db.execute(select(func.count(Repository.id)))).scalar()
    pr_count = (await db.execute(select(func.count(PullRequest.id)))).scalar()
    finding_count = (await db.execute(select(func.count(Finding.id)))).scalar()
    active_scans = (
        await db.execute(
            select(func.count(GraphExecution.id)).where(GraphExecution.status == "running")
        )
    ).scalar()

    return {
        "repositories": repo_count,
        "pull_requests_scanned": pr_count,
        "total_findings": finding_count,
        "active_scans": active_scans,
    }
>>>>>>> Stashed changes
