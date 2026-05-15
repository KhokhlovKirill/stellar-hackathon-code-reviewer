"""Judge agent — arbitrates between Agent A and B findings."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.llm.router import call_llm
from aegis.llm.prompts.security_review import SYSTEM_PROMPT_JUDGE, build_judge_prompt
from aegis.llm.parsers.findings import parse_judge_findings
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def judge_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Merge A and B findings into a final list with risk score.

    Updates:
        - state["final_findings"]: deduplicated, judge-validated findings
        - state["risk_score"]: 0-100 integer
        - state["risk_label"]: "critical" | "high" | "medium" | "low" | "green"
        - state["requires_human_review"]: bool
    """
    llm_a_findings = state.get("llm_a_findings", [])
    llm_b_findings = state.get("llm_b_findings", [])
    deterministic_findings = state.get("deterministic_findings", [])
    pr_metadata = state.get("pr_metadata", {})

    log.info(
        "judge.start",
        pr=pr_metadata.get("number"),
        a=len(llm_a_findings),
        b=len(llm_b_findings),
        det=len(deterministic_findings),
    )

    # Build combined findings for judge
    all_findings = deterministic_findings + llm_a_findings + llm_b_findings

    diff_text = state.get("full_diff", "")

    prompt = build_judge_prompt(
        diff=diff_text,
        llm_a_findings=llm_a_findings,
        llm_b_findings=llm_b_findings,
        det_findings=deterministic_findings,
    )

    result = await call_llm(
        system_prompt=SYSTEM_PROMPT_JUDGE,
        user_prompt=prompt,
        agent_name="judge",
    )
    response_text = result["content"]
    tokens = result.get("prompt_tokens", 0) + result.get("completion_tokens", 0)

    final_findings, risk_score, risk_label, requires_human = parse_judge_findings(response_text)

    # Fallback: if LLM failed, use deterministic findings
    if not final_findings and all_findings:
        final_findings = all_findings[:20]  # cap to avoid overwhelming
        # Calculate risk score from severity
        risk_score = _calc_risk_score(all_findings)
        risk_label = _score_to_label(risk_score)

    log.info(
        "judge.complete",
        final=len(final_findings),
        risk_score=risk_score,
        risk_label=risk_label,
        tokens=tokens,
    )

    return {
        **state,
        "final_findings": final_findings,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "requires_human_review": requires_human,
        "judge_tokens": tokens,
    }


def _calc_risk_score(findings: list[dict]) -> int:
    weights = {"critical": 25, "high": 15, "medium": 5, "low": 1, "info": 0}
    total = sum(weights.get(f.get("severity", "info"), 0) for f in findings)
    return min(100, total)


def _score_to_label(score: int) -> str:
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    elif score > 0:
        return "low"
    return "green"
