"""LangGraph state model for the Aegis security analysis pipeline."""

from __future__ import annotations

from typing import Annotated, Any

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class SecurityGraphState(TypedDict):
    """Full shared state threaded through every graph node."""

    # ── Identifiers ───────────────────────────────────────────────────────────
    scan_id: str
    provider: str          # github | gitlab | bitbucket
    repo_slug: str
    pr_number: int
    repo_db_id: int        # Repository.id in PostgreSQL

    # ── PR context ────────────────────────────────────────────────────────────
    pr: dict[str, Any]                 # normalised PRMetadata dict
    repo_context: dict[str, Any]       # {language, framework, settings}
    diff: str                          # full raw diff string

    # ── File classifications ──────────────────────────────────────────────────
    all_files: list[dict[str, Any]]    # DiffFile dicts (raw)
    code_files: list[dict[str, Any]]   # security-relevant files
    manifest_files: list[dict[str, Any]]  # package.json, requirements.txt …
    skipped_files: list[dict[str, Any]]   # .md, .lock, images …

    # ── Context enrichment ────────────────────────────────────────────────────
    context_map: dict[str, str]        # path → ±50-line context window
    ast_context: dict[str, dict]       # path → AST node info
    code_rag: dict[str, list[str]]     # path → related function bodies

    # ── Findings ─────────────────────────────────────────────────────────────
    deterministic_findings: list[dict[str, Any]]
    llm_findings_a: list[dict[str, Any]]
    llm_findings_b: list[dict[str, Any]]
    judge_findings: list[dict[str, Any]]
    merged_findings: list[dict[str, Any]]

    # ── Risk ──────────────────────────────────────────────────────────────────
    risk_score: int        # 0–100
    risk_label: str        # green | yellow | red
    risk_breakdown: dict[str, int]

    # ── Graph control ─────────────────────────────────────────────────────────
    next_action: str       # analyze | skip | retro
    current_stage: str
    retries: int
    degraded: list[str]    # which services failed gracefully
    requires_llm: bool
    requires_sca: bool
    requires_ast: bool
    estimated_tokens: int

    # ── Execution metadata ────────────────────────────────────────────────────
    started_at: str
    token_usage: dict[str, int]
    execution_trace: list[dict[str, Any]]  # [{node, duration_ms, status}]

    # ── Human review (HITL) ──────────────────────────────────────────────────
    requires_human_review: bool
    human_decision: str | None  # approve | reject | suppress | escalate | rerun

    # ── Blast radius ─────────────────────────────────────────────────────────
    blast_radius_mermaid: str | None

    # ── Autofix ───────────────────────────────────────────────────────────────
    autofix_created: bool
    autofix_pr_url: str | None

    # ── ChatOps / dialog ─────────────────────────────────────────────────────
    messages: Annotated[list[BaseMessage], add_messages]

    # ── Knowledge base ────────────────────────────────────────────────────────
    similar_findings: list[dict[str, Any]]

    # ── Final status ─────────────────────────────────────────────────────────
    status: str            # passed | blocked | error | skipped
    publish_result: dict[str, Any]
    error_message: str | None


class ChatState(TypedDict):
    """State for the ChatOps subgraph."""

    scan_id: str
    pr_number: int
    repo_slug: str
    provider: str
    command: str                      # raw @secbot command string
    intent: str | None                # explain | false_positive | ignore | scan_full | replay
    context: dict[str, Any]           # retrieved finding context
    response: str | None
    messages: Annotated[list[BaseMessage], add_messages]


class RetroScanState(TypedDict):
    """State for the retro full-repo scan subgraph."""

    scan_id: str
    repo_slug: str
    provider: str
    repo_db_id: int
    all_files: list[str]
    batches: list[list[str]]
    current_batch: int
    batch_findings: list[dict[str, Any]]
    aggregated_findings: list[dict[str, Any]]
    report_markdown: str | None
    status: str
