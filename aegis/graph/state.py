"""LangGraph state model for the Aegis security analysis pipeline."""

from __future__ import annotations

from typing import Annotated, Any

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class SecurityGraphState(TypedDict, total=False):
    """Full shared state threaded through every graph node.

    ``total=False`` means all keys are optional at any point in time —
    agents add/update keys incrementally as the graph progresses.

    Field names must match what ``graph_worker.py`` puts into the
    initial_state dict and what every agent reads via ``state.get()``.
    """

    # ── Identifiers ───────────────────────────────────────────────────────────
    scan_id: str
    pr_id: str           # DB PullRequest.id serialised to str (arq JSON transport)
    repo_id: str         # DB Repository.id serialised to str
    provider: str        # github | gitlab | bitbucket
    repo_full_name: str  # e.g. "org/repo"
    access_token: str    # decrypted VCS token

    # ── PR context ────────────────────────────────────────────────────────────
    pr_metadata: dict[str, Any]    # {number, title, head_sha, base_branch, …}
    repo_settings: dict[str, Any]  # {block_threshold, ignored_dirs, …}
    diff_files: list[dict[str, Any]]  # DiffFile dicts from VCS provider
    full_diff: str                    # concatenated raw patch text

    # ── Filter / classification ───────────────────────────────────────────────
    filtered_files: list[dict[str, Any]]   # security-relevant DiffFile dicts
    file_classifications: dict[str, Any]   # filename → {type, language, …}
    false_positive_rules: list[dict[str, Any]]  # suppression rules from DB

    # ── Context enrichment ────────────────────────────────────────────────────
    ast_context: dict[str, Any]    # filename → AST node info
    import_graph: dict[str, Any]   # filename → list of imports
    rag_context: list[Any]         # similar historical findings (list[str] from context_agent)

    # ── Scanner outputs ───────────────────────────────────────────────────────
    deterministic_findings: list[dict[str, Any]]  # semgrep/bandit/gitleaks/sca
    has_secret: bool                               # set by gitleaks/entropy scanner
    scanner_errors: dict[str, str]                 # tool → error message

    # ── LLM agent outputs ─────────────────────────────────────────────────────
    llm_a_findings: list[dict[str, Any]]
    llm_a_summary: str
    llm_a_requires_human: bool
    llm_a_tokens: int

    llm_b_findings: list[dict[str, Any]]
    llm_b_requires_human: bool
    llm_b_tokens: int

    judge_tokens: int

    # ── Merged / final findings ───────────────────────────────────────────────
    final_findings: list[dict[str, Any]]       # merged by judge agent
    filtered_final_findings: list[dict[str, Any]]  # after policy filtering

    # ── Risk ──────────────────────────────────────────────────────────────────
    risk_score: int                 # 0–100
    risk_label: str                 # green | yellow | red
    risk_breakdown: dict[str, int]  # {critical: N, high: N, …}
    block_pr: bool

    # ── Policy ────────────────────────────────────────────────────────────────
    policy_decision: str        # pass | block | warn
    policy_reasons: list[str]

    # ── Planner outputs ───────────────────────────────────────────────────────
    action: str | None          # analyze | skip  (set by planner)
    pr_number: int              # convenience alias also set by planner
    pr_size: dict[str, int]     # {additions, deletions, files}

    # ── Filter outputs ────────────────────────────────────────────────────────
    suppressed_count: int
    test_files: list[str]

    # ── Human-in-the-loop ─────────────────────────────────────────────────────
    requires_human_review: bool
    human_review_pending: bool
    human_decision: str | None   # approve | reject | suppress | escalate | rerun

    # ── Blast radius ─────────────────────────────────────────────────────────
    blast_radius: dict[str, Any]      # {affected_files, call_paths, …}
    blast_radius_mermaid: str | None   # Mermaid diagram string

    # ── Autofix ───────────────────────────────────────────────────────────────
    autofix_suggestions: list[dict[str, Any]]
    autofix_pr_possible: bool
    autofix_pr_url: str | None

    # ── Render outputs ────────────────────────────────────────────────────────
    pr_comment_body: str
    inline_comments: list[dict[str, Any]]
    status_check: dict[str, Any]

    # ── Publish ───────────────────────────────────────────────────────────────
    published: bool
    publish_error: str | None
    comment_ids: list[str]

    # ── Persistence ───────────────────────────────────────────────────────────
    persisted: bool
    persist_error: str | None

    # ── Final status ─────────────────────────────────────────────────────────
    status: str              # passed | blocked | error | skipped
    error_message: str | None

    # ── ChatOps / dialog ─────────────────────────────────────────────────────
    messages: Annotated[list[BaseMessage], add_messages]


class ChatState(TypedDict, total=False):
    """State for the ChatOps subgraph."""

    scan_id: str
    pr_number: int
    repo_full_name: str
    provider: str
    command: str                       # raw @secbot command string
    intent: str | None                 # explain | false_positive | ignore | scan_full | replay
    context: dict[str, Any]            # retrieved finding context
    response: str | None
    messages: Annotated[list[BaseMessage], add_messages]


class RetroScanState(TypedDict, total=False):
    """State for re-scanning historical PR rows already stored in PostgreSQL."""

    repo_db_id: int
    days_back: int
    limit: int
    pr_list: list[dict[str, Any]]
    total: int
    queued_jobs: list[str]
    queued_count: int
    summary: dict[str, Any]
    error: str | None
