"""Persist agent — saves findings, graph execution, and embeddings to PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from aegis.graph.state import SecurityGraphState
from aegis.db.session import get_session_factory
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def persist_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Persist scan results to the database.

    Updates:
        - state["persisted"]: bool
        - state["persist_error"]: str | None
    """
    final_findings = state.get("filtered_final_findings") or state.get("final_findings", [])
    pr_id = state.get("pr_id")
    scan_id = state.get("scan_id")
    risk_score = state.get("risk_score", 0)
    risk_label = state.get("risk_label", "green")
    policy_decision = state.get("policy_decision", "pass")
    autofix_suggestions = state.get("autofix_suggestions", [])
    llm_a_tokens = state.get("llm_a_tokens", 0)
    llm_b_tokens = state.get("llm_b_tokens", 0)
    judge_tokens = state.get("judge_tokens", 0)

    log.info("persist.start", pr_id=pr_id, scan_id=scan_id, findings=len(final_findings))

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            async with session.begin():
                await _upsert_pr(
                    session,
                    pr_id=pr_id,
                    risk_score=risk_score,
                    risk_label=risk_label,
                    policy_decision=policy_decision,
                    finding_count=len(final_findings),
                )

                await _save_findings(session, pr_id=pr_id, findings=final_findings)

                await _save_llm_log(
                    session,
                    pr_id=pr_id,
                    scan_id=scan_id,
                    tokens_used=llm_a_tokens + llm_b_tokens + judge_tokens,
                    summary=state.get("llm_a_summary", ""),
                )

                await _update_graph_execution(
                    session,
                    scan_id=scan_id,
                    status="completed",
                )

        # Update embeddings in knowledge base (fire and forget)
        if final_findings:
            try:
                from aegis.knowledge.kb import upsert_findings_to_kb
                await upsert_findings_to_kb(final_findings, pr_id=pr_id)
            except Exception as kb_exc:
                log.warning("persist.kb_error", error=str(kb_exc))

        log.info("persist.complete")
        return {**state, "persisted": True, "persist_error": None}

    except Exception as exc:
        log.error("persist.error", error=str(exc))
        return {**state, "persisted": False, "persist_error": str(exc)}


async def _upsert_pr(session, pr_id, risk_score, risk_label, policy_decision, finding_count):
    from sqlalchemy import update
    from aegis.db.models import PullRequest

    if pr_id:
        await session.execute(
            update(PullRequest)
            .where(PullRequest.id == pr_id)
            .values(
                risk_score=risk_score,
                risk_label=risk_label,
                status="reviewed",
                finding_count=finding_count,
                policy_decision=policy_decision,
                updated_at=datetime.now(timezone.utc),
            )
        )


async def _save_findings(session, pr_id, findings: list[dict]):
    from aegis.db.models import Finding

    if not pr_id or not findings:
        return

    for f in findings:
        finding = Finding(
            id=uuid.uuid4(),
            pr_id=pr_id,
            file_path=f.get("file_path", ""),
            line_number=f.get("line_number"),
            vuln_type=f.get("vuln_type", ""),
            cwe=f.get("cwe"),
            severity=f.get("severity", "info"),
            confidence=f.get("confidence", 0.75),
            description=f.get("description", ""),
            fix_snippet=f.get("fix_snippet") or f.get("fix"),
            source=f.get("source", "unknown"),
            fingerprint=f.get("fingerprint"),
            created_at=datetime.now(timezone.utc),
        )
        session.add(finding)


async def _save_llm_log(session, pr_id, scan_id, tokens_used, summary):
    from aegis.db.models import LLMLog

    if not pr_id:
        return

    log_entry = LLMLog(
        id=uuid.uuid4(),
        pr_id=pr_id,
        scan_id=str(scan_id) if scan_id else None,
        tokens_used=tokens_used,
        summary=summary[:2000] if summary else "",
        created_at=datetime.now(timezone.utc),
    )
    session.add(log_entry)


async def _update_graph_execution(session, scan_id, status: str):
    from sqlalchemy import update
    from aegis.db.models import GraphExecution

    if not scan_id:
        return

    await session.execute(
        update(GraphExecution)
        .where(GraphExecution.scan_id == str(scan_id))
        .values(status=status, completed_at=datetime.now(timezone.utc))
    )
