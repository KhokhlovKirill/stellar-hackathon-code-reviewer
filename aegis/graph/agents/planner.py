"""Planner agent — decides whether to analyze or skip a PR."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger

log = get_logger(__name__)

# Extensions to skip (docs-only, lock files, generated files)
_SKIP_EXTENSIONS = frozenset(
    [".md", ".rst", ".txt", ".lock", ".sum", ".toml.lock", ".png", ".jpg",
     ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
     ".min.js", ".min.css", ".map"]
)

# Files that, if present, warrant a full scan regardless
_ALWAYS_SCAN_PATTERNS = [
    "Dockerfile", ".github/workflows/", ".gitlab-ci", "requirements", "package.json",
    "setup.py", "setup.cfg", "pyproject.toml", "pom.xml", "build.gradle",
    "Gemfile", "go.mod", "Cargo.toml",
]


async def planner_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Classify the PR as 'analyze' or 'skip'.

    Updates:
        - state["action"]: "analyze" | "skip"
        - state["file_classifications"]: dict[filename, list[str]] of relevant categories
    """
    diff_files = state.get("diff_files", [])
    pr_metadata = state.get("pr_metadata", {})

    log.info("planner.start", pr=pr_metadata.get("number"), files=len(diff_files))

    # Classify files
    classifications: dict[str, list[str]] = {}
    has_code_files = False
    always_scan_triggered = False

    for f in diff_files:
        filename: str = f.get("filename", "")
        cats: list[str] = []

        # Check for always-scan patterns
        for pattern in _ALWAYS_SCAN_PATTERNS:
            if pattern.lower() in filename.lower():
                always_scan_triggered = True
                cats.append("config")

        # Check extension
        ext = _get_extension(filename)
        if ext in _SKIP_EXTENSIONS:
            cats.append("docs_or_generated")
        else:
            has_code_files = True

            if ext in {".py", ".pyw"}:
                cats.append("python")
            elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
                cats.append("javascript")
            elif ext in {".go"}:
                cats.append("golang")
            elif ext in {".java", ".kt"}:
                cats.append("jvm")
            elif ext in {".c", ".cpp", ".h", ".hpp", ".cc"}:
                cats.append("c_cpp")
            elif ext in {".rb"}:
                cats.append("ruby")
            elif ext in {".php"}:
                cats.append("php")
            elif ext in {".rs"}:
                cats.append("rust")
            elif ext in {".sh", ".bash", ".zsh"}:
                cats.append("shell")
            elif ext in {".tf", ".tfvars"}:
                cats.append("terraform")
            elif ext in {".yaml", ".yml"}:
                cats.append("yaml")
            elif ext in {".json"}:
                cats.append("json")
            else:
                cats.append("other")

        classifications[filename] = cats

    # Determine action
    action = "skip"
    if has_code_files or always_scan_triggered:
        action = "analyze"

    # Check PR size — very large PRs get a special flag
    total_additions = sum(f.get("additions", 0) for f in diff_files)
    total_deletions = sum(f.get("deletions", 0) for f in diff_files)

    log.info(
        "planner.decision",
        action=action,
        files=len(diff_files),
        code_files=has_code_files,
        always_scan=always_scan_triggered,
        additions=total_additions,
        deletions=total_deletions,
    )

    return {
        **state,
        "action": action,
        "file_classifications": classifications,
        "pr_size": {"additions": total_additions, "deletions": total_deletions, "files": len(diff_files)},
    }


def _get_extension(filename: str) -> str:
    lower = filename.lower()
    # Handle compound extensions first
    if lower.endswith(".min.js"):
        return ".min.js"
    if lower.endswith(".min.css"):
        return ".min.css"
    parts = lower.rsplit(".", 1)
    return f".{parts[1]}" if len(parts) > 1 else ""
