"""LLM Agent A — first-pass security review by Claude."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.llm.router import call_llm
from aegis.llm.prompts.security_review import (
    SYSTEM_PROMPT_LLM_A,
    build_security_review_prompt,
)
from aegis.llm.parsers.findings import parse_llm_a_findings
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_MAX_DIFF_CHARS = 80_000  # truncate very large diffs


async def llm_agent_a(state: SecurityGraphState) -> SecurityGraphState:
    """Run the first LLM pass — independent analysis without seeing existing findings.

    Updates:
        - state["llm_a_findings"]: list of findings from Agent A
        - state["llm_a_summary"]: overall summary string
        - state["llm_a_requires_human"]: bool
    """
    filtered_files = state.get("filtered_files", [])
    pr_metadata = state.get("pr_metadata", {})
    ast_context = state.get("ast_context", {})
    rag_context = state.get("rag_context", [])
    deterministic_findings = state.get("deterministic_findings", [])

    log.info("llm_a.start", pr=pr_metadata.get("number"), files=len(filtered_files))

    # Build the diff text
    diff_text = _build_diff(filtered_files)

    prompt = build_security_review_prompt(
        diff=diff_text,
        context_map={},
        ast_context=ast_context,
        det_findings=deterministic_findings,
        similar_findings=rag_context,
        repo_context=pr_metadata,
    )

    result = await call_llm(
        system_prompt=SYSTEM_PROMPT_LLM_A,
        user_prompt=prompt,
        agent_name="llm_a",
    )
    response_text = result["content"]
    tokens = result.get("prompt_tokens", 0) + result.get("completion_tokens", 0)

    findings = parse_llm_a_findings(response_text)
    summary = _extract_summary(response_text)
    requires_human = any(
        f.get("severity") in ("critical", "high") for f in findings
    )

    log.info("llm_a.complete", findings=len(findings), tokens=tokens)

    return {
        **state,
        "llm_a_findings": findings,
        "llm_a_summary": summary,
        "llm_a_requires_human": requires_human,
        "llm_a_tokens": tokens,
    }


def _build_diff(filtered_files: list[dict]) -> str:
    parts = []
    total_chars = 0
    for f in filtered_files:
        filename = f.get("filename", "")
        patch = f.get("patch", "")
        chunk = f"--- {filename}\n{patch}\n"
        if total_chars + len(chunk) > _MAX_DIFF_CHARS:
            parts.append(f"--- {filename}\n[TRUNCATED — diff too large]\n")
            break
        parts.append(chunk)
        total_chars += len(chunk)
    return "\n".join(parts)


def _extract_summary(response_text: str) -> str:
    import json, re
    try:
        # Try to get summary from JSON
        m = re.search(r'"summary"\s*:\s*"([^"]*)"', response_text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""
