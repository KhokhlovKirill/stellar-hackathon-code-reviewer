"""Unified-diff → normalized FileChange/Hunk/DiffLine with right-side line numbers
and GitHub-style per-file diff positions.

Shared by all providers so line mapping (criterion C4) behaves identically regardless
of VCS. `diff_position` is the 1-based offset of a line within a single file's patch
(what the GitHub review API calls `position`).
"""

from __future__ import annotations

from unidiff import PatchSet

from aegis.schemas import DiffLine, FileChange, Hunk, LineKind

# Minimal, dependency-free language map (extension -> language tag).
_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".go": "go", ".java": "java", ".rb": "ruby", ".php": "php",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp", ".rs": "rust",
    ".kt": "kotlin", ".scala": "scala", ".sh": "bash", ".sql": "sql", ".yaml": "yaml",
    ".yml": "yaml", ".tf": "hcl", ".dockerfile": "dockerfile",
}


def language_of(path: str) -> str | None:
    low = path.lower()
    if low.endswith("dockerfile") or "/dockerfile" in low:
        return "dockerfile"
    for ext, lang in _LANG.items():
        if low.endswith(ext):
            return lang
    return None


def _status(pf) -> str:  # type: ignore[no-untyped-def]
    if pf.is_added_file:
        return "added"
    if pf.is_removed_file:
        return "deleted"
    if pf.is_rename:
        return "renamed"
    return "modified"


def parse_unified_diff(diff_text: str) -> list[FileChange]:
    """Parse a raw unified diff into normalized FileChange objects."""
    if not diff_text.strip():
        return []
    patch = PatchSet(diff_text)
    changes: list[FileChange] = []

    for pf in patch:
        path = pf.path
        position = 0  # resets per file; counts every hunk header + context/+/- line
        hunks: list[Hunk] = []
        for h in pf:
            position += 1  # the @@ hunk header occupies a position slot
            lines: list[DiffLine] = []
            for ln in h:
                position += 1
                if ln.is_added:
                    kind = LineKind.ADD
                elif ln.is_removed:
                    kind = LineKind.DEL
                else:
                    kind = LineKind.CTX
                lines.append(
                    DiffLine(
                        kind=kind,
                        content=ln.value.rstrip("\n"),
                        new_lineno=ln.target_line_no,
                        old_lineno=ln.source_line_no,
                        diff_position=position,
                    )
                )
            hunks.append(
                Hunk(
                    old_start=h.source_start,
                    old_count=h.source_length,
                    new_start=h.target_start,
                    new_count=h.target_length,
                    header=str(h).splitlines()[0] if str(h) else "",
                    lines=lines,
                )
            )
        changes.append(
            FileChange(
                path=path,
                old_path=pf.source_file if pf.is_rename else None,
                status=_status(pf),
                is_binary=pf.is_binary_file,
                language=language_of(path),
                hunks=hunks,
            )
        )
    return changes
