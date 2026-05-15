"""LLM Agent B — validation pass, sees Agent A findings for adversarial review."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.llm.router import call_llm
from aegis.llm.prompts.security_review import (
    SYSTEM_PROMPT_LLM_B,
    build_security_review_prompt,
)
from aegis.llm.parsers.findings import parse_llm_b_findings
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_MAX_DIFF_CHARS = 80_000


async def llm_agent_b(state: SecurityGraphState) -> SecurityGraphState:
    """Validate Agent A's findings and add any missed vulnerabilities.

    Updates:
        - state["llm_b_findings"]: validated + new findings
        - state["llm_b_requires_human"]: bool
        - state["llm_b_tokens"]: token usage
    """
    filtered_files = state.get("filtered_files", [])
    pr_metadata = state.get("pr_metadata", {})
    ast_context = state.get("ast_context", {})
    rag_context = state.get("rag_context", [])
    llm_a_findings = state.get("llm_a_findings", [])
    deterministic_findings = state.get("deterministic_findings", [])

    log.info("llm_b.start", pr=pr_metadata.get("number"), a_findings=len(llm_a_findings))

    diff_text = _build_diff(filtered_files)

    # Combine det + LLM A findings for context
    all_prior = deterministic_findings + llm_a_findings

    prompt = build_security_review_prompt(
        diff=diff_text,
        context_map={},
        ast_context=ast_context,
        det_findings=all_prior,
        similar_findings=rag_context,
        repo_context=pr_metadata,
    )

    result = await call_llm(
        system_prompt=SYSTEM_PROMPT_LLM_B,
        user_prompt=prompt,
        agent_name="llm_b",
    )
    response_text = result["content"]
    tokens = result.get("prompt_tokens", 0) + result.get("completion_tokens", 0)

    findings, requires_human = parse_llm_b_findings(response_text)

    log.info("llm_b.complete", findings=len(findings), tokens=tokens)

    return {
        **state,
        "llm_b_findings": findings,
        "llm_b_requires_human": requires_human,
        "llm_b_tokens": tokens,
    }


def _build_diff(filtered_files: list[dict]) -> str:
    parts = []
    total_chars = 0
    for f in filtered_files:
        filename = f.get("filename", "")
        patch = f.get("patch", "")
        chunk = f"--- {filename}\n{patch}\n"
        if total_chars + len(chunk) > _MAX_DIFF_CHARS:
            parts.append(f"--- {filename}\n[ОБРЕЗАНО]\n")
            break
        parts.append(chunk)
        total_chars += len(chunk)
    return "\n".join(parts)
