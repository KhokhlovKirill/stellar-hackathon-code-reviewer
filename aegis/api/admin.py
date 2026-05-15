"""Admin REST API endpoints for repositories, scans, findings, and knowledge base."""

from __future__ import annotations

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
    decision: str  # approve | reject | suppress | escalate | rerun
    rationale: str | None = None
    finding_fingerprint: str | None = None


class FalsePositiveRequest(BaseModel):
    pattern: str
    directory: str | None = None
    cwe: str | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_int_id(raw: str, name: str = "id") -> int:
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: must be a numeric id") from exc


# ── Repository Management ─────────────────────────────────────────────────────

@router.post("/repos", response_model=RepoResponse)
async def register_repo(request: RegisterRepoRequest, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """Register a repository for security scanning."""
    from aegis.db.models import ProviderEnum, Repository, repository_url
    from sqlalchemy import select
    from cryptography.fernet import Fernet
    from aegis.config import get_settings

    try:
        provider = ProviderEnum(request.provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {request.provider}") from exc

    settings = get_settings()
    f = Fernet(settings.fernet_key.encode())

    # Encrypt tokens
    encrypted_token = f.encrypt(request.access_token.encode()).decode()
    encrypted_secret = f.encrypt(request.webhook_secret.encode()).decode() if request.webhook_secret else None

    # Check if already registered
    existing = await db.execute(
        select(Repository).where(
            Repository.provider == provider,
            Repository.slug == request.full_name,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Repository already registered")

    repo = Repository(
        provider=provider,
        slug=request.full_name,
        url=repository_url(request.provider, request.full_name),
        token_encrypted=encrypted_token,
        webhook_secret_encrypted=encrypted_secret,
        settings_json=request.settings or {},
        is_active=True,
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

    repo_pk = _parse_int_id(repo_id, "repo_id")

    result = await db.execute(select(Repository).where(Repository.id == repo_pk))
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
        findings=pr.findings_count if pr else None,
        created_at=execution.started_at.isoformat() if execution.started_at else "",
    )


@router.post("/scans/{scan_id}/cancel", status_code=202)
async def cancel_scan(scan_id: str, user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """Cancel a running scan (marks it as failed with a cancellation reason)."""
    from aegis.db.models import GraphExecution, GraphStatusEnum
    from sqlalchemy import select, update

    result = await db.execute(
        select(GraphExecution).where(GraphExecution.scan_id == scan_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    meta = dict(row.metadata_json or {})
    meta["cancellation_reason"] = "manual_cancel"
    meta["cancelled_at"] = datetime.now(timezone.utc).isoformat()

    await db.execute(
        update(GraphExecution)
        .where(GraphExecution.scan_id == scan_id)
        .values(
            status=GraphStatusEnum.failed,
            finished_at=datetime.now(timezone.utc),
            metadata_json=meta,
        )
    )
    await db.commit()
    return {"status": "cancelled", "scan_id": scan_id}


# ── Human Review ──────────────────────────────────────────────────────────────

_VALID_HUMAN_DECISIONS = {"approve", "reject", "suppress", "escalate", "rerun"}


@router.post("/human-review/{scan_id}", status_code=202)
async def submit_human_review(
    scan_id: str,
    request: HumanReviewRequest,
    user: Auth,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Submit a human review decision to resume a paused graph."""
    from aegis.db.models import GraphExecution, GraphStatusEnum, HumanDecisionEnum, HumanReview
    from aegis.graph.runtime import resume_graph
    from sqlalchemy import select, update

    if request.decision not in _VALID_HUMAN_DECISIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Decision must be one of: {sorted(_VALID_HUMAN_DECISIONS)}",
        )

    # Find the execution
    result = await db.execute(
        select(GraphExecution).where(GraphExecution.scan_id == scan_id)
    )
    execution = result.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Save review (id is BigInteger autoincrement — let DB assign it)
    review = HumanReview(
        scan_id=scan_id,
        finding_fingerprint=request.finding_fingerprint,
        decision=HumanDecisionEnum(request.decision),
        reviewer=user.get("sub", "unknown"),
        rationale=request.rationale or "",
        created_at=datetime.now(timezone.utc),
    )
    db.add(review)

    await db.execute(
        update(GraphExecution)
        .where(GraphExecution.scan_id == scan_id)
        .values(status=GraphStatusEnum.resumed, resumed_count=GraphExecution.resumed_count + 1)
    )
    await db.commit()

    # Resume graph
    try:
        await resume_graph(
            scan_id=scan_id,
            update={"human_decision": request.decision},
        )
    except Exception as exc:
        log.error("admin.resume_error", scan_id=scan_id, error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to resume graph: {exc}") from exc

    return {"status": "resumed", "scan_id": scan_id, "decision": request.decision}


# ── Findings ──────────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


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

    pr_pk = _parse_int_id(pr_id, "pr_id")

    stmt = select(Finding).where(Finding.pr_id == pr_pk)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    stmt = stmt.order_by(Finding.created_at.desc()).offset(offset).limit(limit)

    result = await db.execute(stmt)
    findings = result.scalars().all()
    # Order in Python by severity weight so 'critical' shows first.
    findings = sorted(findings, key=lambda f: -_SEVERITY_ORDER.get(f.severity, 0))

    return [
        FindingResponse(
            id=str(f.id),
            file_path=f.file_path,
            line_number=f.line_number,
            vuln_type=f.vuln_type or "",
            severity=f.severity,
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
):
    """Add a false positive rule for a repository."""
    from aegis.db.models import FalsePositive

    repo_pk = _parse_int_id(repo_id, "repo_id")

    fp = FalsePositive(
        repo_id=repo_pk,
        pattern=request.pattern,
        directory=request.directory or None,
        cwe=request.cwe,
        created_at=datetime.now(timezone.utc),
    )
    db.add(fp)
    await db.commit()
    await db.refresh(fp)

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

    repo_pk = _parse_int_id(repo_id, "repo_id")

    result = await db.execute(
        select(FalsePositive).where(FalsePositive.repo_id == repo_pk)
    )
    fps = result.scalars().all()

    return [
        {
            "id": str(fp.id),
            "pattern": fp.pattern,
            "directory": fp.directory,
            "cwe": fp.cwe,
            "count": fp.count,
            "auto_suppressed": fp.auto_suppressed,
        }
        for fp in fps
    ]


# ── Knowledge Base ────────────────────────────────────────────────────────────

@router.get("/kb/search")
async def search_knowledge_base(
    user: Auth,
    q: str = Query(..., min_length=3),
    top_k: int = Query(5, le=20),
):
    """Semantic search in the knowledge base."""
    from aegis.knowledge.retrieval import search_similar

    results = await search_similar(q, top_k=top_k)
    return {"query": q, "results": results}


@router.get("/kb")
async def list_kb_entries(
    user: Auth,
    limit: int = Query(50, le=200),
    offset: int = Query(0),
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

    # Validate id format up front (runner also validates, but produce 400 here).
    _parse_int_id(repo_id, "repo_id")

    summary = await run_retro_scan(repo_id=repo_id, days_back=days_back, limit=limit)
    return {"status": "initiated", "repo_id": repo_id, **summary}


# ── Statistics ────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(user: Auth, db: Annotated[AsyncSession, Depends(get_db)]):
    """Get aggregate scan statistics."""
    from aegis.db.models import Finding, GraphExecution, GraphStatusEnum, PullRequest, Repository
    from sqlalchemy import select, func

    repo_count = (await db.execute(select(func.count(Repository.id)))).scalar() or 0
    pr_count = (await db.execute(select(func.count(PullRequest.id)))).scalar() or 0
    finding_count = (await db.execute(select(func.count(Finding.id)))).scalar() or 0
    active_scans = (
        await db.execute(
            select(func.count(GraphExecution.id)).where(
                GraphExecution.status == GraphStatusEnum.running.value
            )
        )
    ).scalar() or 0

    return {
        "repositories": repo_count,
        "pull_requests_scanned": pr_count,
        "total_findings": finding_count,
        "active_scans": active_scans,
    }
