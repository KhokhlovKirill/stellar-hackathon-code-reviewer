"""Golden-set regression harness.

The first gate is deterministic and offline: it validates changed-line mapping
and high-confidence secret detection. Later phases can add Semgrep/Bandit/LLM
profiles to the same Case/Result contract without changing CI output.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

os.environ.setdefault("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")

from aegis.pipeline.deterministic.secrets import scan_secrets
from aegis.schemas import DiffLine, FileChange, Hunk, LineKind

ROOT = Path(__file__).resolve().parent
# Prefer the full golden-set if it has been built; fall back to the seed.
_FULL = ROOT / "golden" / "full.jsonl"
_SEED = ROOT / "golden" / "seed.jsonl"
DEFAULT_GOLDEN = _FULL if _FULL.exists() else _SEED


@dataclass(frozen=True, slots=True)
class Metrics:
    tp: int
    fp: int
    fn: int
    line_hits: int
    expected: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def line_accuracy(self) -> float:
        return self.line_hits / self.expected if self.expected else 1.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", default=str(DEFAULT_GOLDEN))
    parser.add_argument("--gate", action="store_true")
    args = parser.parse_args()

    metrics = run(Path(args.golden))
    result = {
        "precision": round(metrics.precision, 4),
        "recall": round(metrics.recall, 4),
        "line_accuracy": round(metrics.line_accuracy, 4),
        "tp": metrics.tp,
        "fp": metrics.fp,
        "fn": metrics.fn,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.gate and (
        metrics.precision < 0.95 or metrics.recall < 0.95 or metrics.line_accuracy < 0.95
    ):
        raise SystemExit(1)


# CWEs testable by the offline secrets scanner only
_OFFLINE_CWES = {"CWE-798", "CWE-321", "CWE-259", "CWE-312"}


def run(path: Path) -> Metrics:
    """Evaluate the offline (no tools required) secret detection on the golden set.

    Cases whose expected CWEs are entirely outside _OFFLINE_CWES are skipped —
    they require Semgrep/Bandit/SCA and are evaluated separately by score_criteria.
    Clean negatives are always included to measure FP rate.
    """
    tp = fp = fn = line_hits = expected_total = 0
    for case in _cases(path):
        all_expected = {(item["cwe"], int(item["line"])) for item in case["expected"]}
        secret_expected = {(cwe, ln) for cwe, ln in all_expected if cwe in _OFFLINE_CWES}

        # Skip non-secret vulnerable cases — can't be tested without external tools.
        if all_expected and not secret_expected:
            continue

        fc = _file_change(case)
        findings = scan_secrets([fc])
        got = {(finding.cwe, finding.line) for finding in findings if finding.cwe in _OFFLINE_CWES}

        tp += len(secret_expected & got)
        fp += len(got - secret_expected)
        fn += len(secret_expected - got)
        line_hits += len(secret_expected & got)
        expected_total += len(secret_expected)
    return Metrics(tp=tp, fp=fp, fn=fn, line_hits=line_hits, expected=expected_total)


def _cases(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _file_change(case: dict[str, Any]) -> FileChange:
    lines = [
        DiffLine(kind=LineKind.ADD, content=text, new_lineno=i, diff_position=i)
        for i, text in enumerate(case["added_lines"], start=1)
    ]
    return FileChange(
        path=case["path"],
        status="modified",
        language=case.get("language"),
        hunks=[
            Hunk(
                old_start=1,
                old_count=0,
                new_start=1,
                new_count=len(lines),
                header=f"@@ -0,0 +1,{len(lines)} @@",
                lines=lines,
            )
        ],
    )


if __name__ == "__main__":
    main()
