"""Human review agent — pauses execution for human decision on critical PRs."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def human_review_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Gate execution pending human review.

    This node is an INTERRUPT point in the LangGraph. When the graph reaches this
    node for a critical finding, it will:
    1. Record the interrupt in the database
    2. Post a "Pending Human Review" comment to the PR
    3. Suspend execution (the graph checkpointer saves state)

    The graph is resumed via the /api/human-review/{scan_id} endpoint.

    Updates:
        - state["human_review_pending"]: True when waiting
        - state["human_decision"]: "approved" | "rejected" | "ignored" after resume
    """
    final_findings = state.get("final_findings", [])
    risk_label = state.get("risk_label", "")
    pr_metadata = state.get("pr_metadata", {})
    human_decision = state.get("human_decision")

    log.info(
        "human_review.reached",
        pr=pr_metadata.get("number"),
        risk=risk_label,
        decision=human_decision,
    )

    # If already decided (resumed), pass through
    if human_decision in ("approved", "rejected", "ignored"):
        log.info("human_review.already_decided", decision=human_decision)
        return {**state, "human_review_pending": False}

    # Mark as pending — this triggers graph interrupt
    critical_findings = [
        f for f in final_findings if f.get("severity") in ("critical", "high")
    ]

    log.info(
        "human_review.pending",
        critical_findings=len(critical_findings),
        risk=risk_label,
    )

    return {
        **state,
        "human_review_pending": True,
        "human_review_findings": critical_findings,
        "interrupt": True,  # Signal to runtime to interrupt here
    }
