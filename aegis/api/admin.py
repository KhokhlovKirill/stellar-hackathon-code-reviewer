"""Admin REST API endpoints for repositories, scans, findings, and knowledge base."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.api.auth import get_current_user
from aegis.config import get_settings
from aegis.db.models import (
    FalsePositive,
    Finding,
    GraphExecution,
    GraphStatusEnum,
    HumanDecisionEnum,
    HumanReview,
    ProviderEnum,
    PullRequest,
    Repository,
    SeverityEnum,
)
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
    settings: dict = Field(default_factory=dict)


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


_HUMAN_DECISION_API = {
    "approved": HumanDecisionEnum.approve,
    "rejected": HumanDecisionEnum.reject,
    "ignored": HumanDecisionEnum.suppress,
}


# ── Repository Management ─────────────────────────────────────────────────────

@router.post("/repos", response_model=RepoResponse)
async def register_repo(
    request: RegisterRepoRequest,
    user: Auth,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RepoResponse:
    """Register a repository for security scanning."""
    try:
        prov = ProviderEnum(request.provider.lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid provider") from exc

    settings = get_settings()
    f = Fernet(settings.fernet_key.encode())

    encrypted_token = f.encrypt(request.access_token.encode()).decode()
    encrypted_secret = (
        f.encrypt(request.webhook_secret.encode()).decode() if request.webhook_secret else None
    )

    result = await db.execute(
        select(Repository).where(
            Repository.provider == prov,
            Repository.slug == request.full_name,
        )
    )
    if result.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Repository already registered")

    repo_url = (
        f"https://github.com/{request.full_name}"
        if prov == ProviderEnum.github
        else f"https://gitlab.com/{request.full_name}"
    )

    repo = Repository(
        provider=prov,
        slug=request.full_name,
        url=repo_url,
        token_encrypted=encrypted_token,
        webhook_secret_encrypted=encrypted_secret,
        settings_json=request.settings,
        is_active=True,
    )
    db.add(repo)
    await db.commit()
    await db.refresh(repo)

    log.info("admin.repo_registered", repo=request.full_name)
    return RepoResponse(
        id=str(repo.id),
        provider=repo.provider.value if hasattr(repo.provider, "value") else str(repo.provider),
        full_name=repo.slug,
        active=repo.is_active,
        created_at=repo.created_at.isoformat(),
    )


@router.get("/repos", response_model=list[RepoResponse])
async def list_repos(user: Auth, db: Annotated[AsyncSession, Depends(get_db)]) -> list[RepoResponse]:
    """List all registered repositories."""
    result = await db.execute(select(Repository).order_by(Repository.created_at.desc()))
    repos = result.scalars().all()
    return [
        RepoResponse(
            id=str(r.id),
            provider=r.provider.value if hasattr(r.provider, "value") else str(r.provider),
            full_name=r.slug,
            active=r.is_active,
            created_at=r.created_at.isoformat(),
        )
        for r in repos
    ]


@router.delete("/repos/{repo_id}", status_code=204)
async def delete_repo(repo_id: str, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]) -> None:
    """Remove a registered repository."""
    try:
        rid = int(repo_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid repository id") from exc

    result = await db.execute(select(Repository).where(Repository.id == rid))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    db.delete(repo)
    await db.commit()


# ── Scan Management ───────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]
) -> ScanStatusResponse:
    """Get the status of a specific scan."""
    result = await db.execute(select(GraphExecution).where(GraphExecution.scan_id == scan_id))
    execution = result.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Scan not found")

    pr_result = await db.execute(select(PullRequest).where(PullRequest.id == execution.pr_id))
    pr = pr_result.scalar_one_or_none()

    return ScanStatusResponse(
        scan_id=execution.scan_id,
        status=(
            execution.status.value
            if hasattr(execution.status, "value")
            else str(execution.status)
        ),
        current_node=execution.current_node,
        risk_score=pr.risk_score if pr else None,
        findings=pr.findings_count if pr else None,
        created_at=execution.started_at.isoformat(),
    )


@router.post("/scans/{scan_id}/cancel", status_code=202)
async def cancel_scan(scan_id: str, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]) -> dict:
    """Cancel a running scan."""
    await db.execute(
        update(GraphExecution)
        .where(
            GraphExecution.scan_id == scan_id,
            GraphExecution.status == GraphStatusEnum.running,
        )
        .values(
            status=GraphStatusEnum.interrupted,
            finished_at=datetime.now(timezone.utc),
        )
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
) -> dict:
    """Submit a human review decision to resume a paused graph."""
    from aegis.graph.runtime import resume_graph

    if request.decision not in _HUMAN_DECISION_API:
        raise HTTPException(
            status_code=400,
            detail="Decision must be: approved, rejected, or ignored",
        )

    result = await db.execute(select(GraphExecution).where(GraphExecution.scan_id == scan_id))
    execution = result.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Scan not found")

    review = HumanReview(
        scan_id=scan_id,
        decision=_HUMAN_DECISION_API[request.decision],
        reviewer=user.get("sub", "unknown"),
        rationale=request.reason or "",
    )
    db.add(review)

    await db.execute(
        update(GraphExecution)
        .where(GraphExecution.scan_id == scan_id)
        .values(status=GraphStatusEnum.running)
    )
    await db.commit()

    try:
        await resume_graph(
            thread_id=scan_id,
            update={"human_decision": request.decision},
        )
    except Exception as exc:
        log.error("admin.resume_error", scan_id=scan_id, error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to resume graph: {exc}") from exc

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
) -> list[FindingResponse]:
    """Get findings for a specific PR."""
    try:
        pr_pk = int(pr_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid pr id") from exc

    stmt = select(Finding).where(Finding.pr_id == pr_pk)
    if severity:
        try:
            sev = SeverityEnum(severity.lower())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid severity") from exc
        stmt = stmt.where(Finding.severity == sev)
    stmt = stmt.order_by(Finding.severity.desc()).offset(offset).limit(limit)

    result = await db.execute(stmt)
    findings = result.scalars().all()

    return [
        FindingResponse(
            id=str(f.id),
            file_path=f.file_path,
            line_number=f.line_number,
            vuln_type=f.vuln_type or "",
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            cwe=f.cwe,
            description=f.description or "",
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
) -> dict:
    """Add a false positive rule for a repository."""
    try:
        rid = int(repo_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid repository id") from exc

    pattern = request.pattern
    if request.reason:
        pattern = f"{pattern} # {request.reason}"

    fp = FalsePositive(
        repo_id=rid,
        pattern=pattern,
        directory=request.directory or "",
    )
    db.add(fp)
    await db.commit()

    return {"status": "created", "id": str(fp.id)}


@router.get("/repos/{repo_id}/false-positives")
async def list_false_positives(
    repo_id: str,
    user: Auth,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[dict]:
    """List all false positive rules for a repository."""
    try:
        rid = int(repo_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid repository id") from exc

    result = await db.execute(select(FalsePositive).where(FalsePositive.repo_id == rid))
    fps = result.scalars().all()

    return [
        {"id": str(fp.id), "pattern": fp.pattern, "directory": fp.directory, "reason": ""}
        for fp in fps
    ]


# ── Knowledge Base ────────────────────────────────────────────────────────────

@router.get("/kb/search")
async def search_knowledge_base(
    user: Auth,
    q: str = Query(..., min_length=3),
    top_k: int = Query(5, le=20),
) -> dict:
    """Semantic search in the knowledge base."""
    from aegis.knowledge.retrieval import search_similar

    _ = user
    results = await search_similar(q, top_k=top_k)
    return {"query": q, "results": results}


@router.get("/kb")
async def list_kb_entries(
    user: Auth,
    limit: int = Query(50, le=200),
    offset: int = Query(0),
) -> dict:
    """List knowledge base entries."""
    from aegis.knowledge.kb import list_kb_entries as _list

    _ = user
    entries = await _list(limit=limit, offset=offset)
    return {"entries": entries, "count": len(entries)}


# ── Retro Scan ────────────────────────────────────────────────────────────────

@router.post("/repos/{repo_id}/retroscan", status_code=202)
async def trigger_retro_scan(
    repo_id: str,
    user: Auth,
    days_back: int = Query(30, le=365),
    limit: int = Query(50, le=200),
) -> dict:
    """Trigger a retro scan of historical PRs."""
    from aegis.graph.subgraphs.retro_scan import run_retro_scan

    _ = user
    summary = await run_retro_scan(repo_id=repo_id, days_back=days_back, limit=limit)
    return {"status": "initiated", "repo_id": repo_id, **summary}


# ── Statistics ────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(user: Auth, db: Annotated[AsyncSession, Depends(get_db)]) -> dict:
    """Get aggregate scan statistics."""
    _ = user
    repo_count = (await db.execute(select(func.count(Repository.id)))).scalar()
    pr_count = (await db.execute(select(func.count(PullRequest.id)))).scalar()
    finding_count = (await db.execute(select(func.count(Finding.id)))).scalar()
    active_scans = (
        await db.execute(
            select(func.count(GraphExecution.id)).where(
                GraphExecution.status == GraphStatusEnum.running
            )
        )
    ).scalar()

    return {
        "repositories": repo_count,
        "pull_requests_scanned": pr_count,
        "total_findings": finding_count,
        "active_scans": active_scans,
    }
