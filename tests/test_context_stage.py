"""Smart Context Window unit tests."""

from __future__ import annotations

from aegis.pipeline.context import extract_context
from aegis.schemas import DiffLine, FileChange, Hunk, LineKind


def _file() -> FileChange:
    return FileChange(
        path="app/service.py",
        status="modified",
        language="python",
        hunks=[
            Hunk(
                old_start=5,
                old_count=1,
                new_start=5,
                new_count=2,
                header="@@ -5,1 +5,2 @@",
                lines=[
                    DiffLine(kind=LineKind.ADD, content="danger(user)", new_lineno=5),
                    DiffLine(kind=LineKind.ADD, content="return ok", new_lineno=6),
                ],
            )
        ],
    )


def test_extract_context_uses_bounded_numbered_window() -> None:
    text = "\n".join(f"line {i}" for i in range(1, 11))
    context = extract_context(_file(), text, context_lines=2)
    assert "@@ context app/service.py:3-8 @@" in context
    assert "3: line 3" in context
    assert "8: line 8" in context
    assert "2: line 2" not in context
    assert "9: line 9" not in context
