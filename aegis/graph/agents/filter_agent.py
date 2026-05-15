"""Filter agent — removes false positives and applies suppression rules."""

from __future__ import annotations

import re

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger

log = get_logger(__name__)

# Patterns that are almost always false positives
_FP_PATTERNS = [
    re.compile(r"TODO|FIXME|HACK|XXX|NOTE", re.IGNORECASE),
    re.compile(r"#\s*nosec", re.IGNORECASE),       # Bandit suppression
    re.compile(r"//\s*NOSONAR", re.IGNORECASE),    # SonarQube suppression
    re.compile(r"^\s*#.*$", re.MULTILINE),           # Comment-only lines
]

_TEST_FILE_PATTERNS = [
    re.compile(r"test_.*\.py$"),
    re.compile(r".*_test\.py$"),
    re.compile(r".*\.spec\.(js|ts)x?$"),
    re.compile(r".*\.test\.(js|ts)x?$"),
    re.compile(r"tests?/"),
    re.compile(r"__mocks__/"),
]


async def filter_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Filter out irrelevant files and apply known suppression rules.

    Updates:
        - state["filtered_files"]: list of DiffFile dicts after suppression
        - state["suppressed_count"]: number of files/findings suppressed
    """
    diff_files = state.get("diff_files", [])
    file_classifications = state.get("file_classifications", {})
    repo_id = state.get("repo_id")

    log.info("filter.start", total_files=len(diff_files), repo_id=repo_id)

    # Load repo-level false positive rules from state (populated by context agent later,
    # but may have pre-existing rules from the database)
    fp_rules = state.get("false_positive_rules", [])

    filtered: list[dict] = []
    suppressed = 0
    test_files: list[str] = []

    for file in diff_files:
        filename: str = file.get("filename", "")
        cats = file_classifications.get(filename, [])

        # Skip docs/generated files
        if "docs_or_generated" in cats:
            suppressed += 1
            continue

        # Track test files (still scan, but lower severity threshold)
        is_test = any(p.search(filename) for p in _TEST_FILE_PATTERNS)
        if is_test:
            test_files.append(filename)

        # Check repo-level suppression rules
        suppressed_by_rule = False
        for rule in fp_rules:
            pattern = rule.get("pattern", "")
            directory = rule.get("directory", "")
            if directory and filename.startswith(directory):
                suppressed_by_rule = True
                break
            if pattern and re.search(pattern, filename):
                suppressed_by_rule = True
                break

        if suppressed_by_rule:
            suppressed += 1
            log.debug("filter.suppressed_by_rule", filename=filename)
            continue

        # Keep file, but annotate it
        filtered.append({**file, "_is_test": is_test})

    log.info(
        "filter.complete",
        kept=len(filtered),
        suppressed=suppressed,
        test_files=len(test_files),
    )

    return {
        **state,
        "filtered_files": filtered,
        "suppressed_count": suppressed,
        "test_files": test_files,
    }
