"""Map eval results onto the C1-C8 hackathon criteria and compute a weighted score.

Usage:
    python -m eval.score_criteria                      # auto-run full.jsonl if present
    python -m eval.score_criteria --golden eval/golden/full.jsonl
    python -m eval.score_criteria --json               # machine-readable output

Criteria weights (from task brief, total = 96 points max for tech criteria):
    C1  Webhook reception from 3 providers          w=6
    C2  Diff-only analysis (no full clone)           w=6
    C3  Detect SQLi / secrets / XSS / bad deps       w=6
    C4  Inline comment with rationale                w=6
    C5  Fix snippet                                  w=3
    C6  Non-code file filtering                      w=3
    C7  Dialog (@secbot commands)                    w=1
    C8  Merge block on critical                      w=1

C3 is the only criterion directly measurable by the golden-set eval harness.
Other criteria are marked as "verified" based on code presence checks below.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path

os.environ.setdefault("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")

ROOT = Path(__file__).resolve().parent.parent
EVAL_ROOT = ROOT / "eval"

_WEIGHTS = {
    "C1": 6,  # webhook
    "C2": 6,  # diff-only
    "C3": 6,  # detection
    "C4": 6,  # inline comment
    "C5": 3,  # fix snippet
    "C6": 3,  # non-code filter
    "C7": 1,  # dialog
    "C8": 1,  # merge block
}
_MAX_SCORE = sum(_WEIGHTS.values())  # 32 for these 8; task brief has more bonus criteria


def _module_exists(mod: str) -> bool:
    try:
        importlib.import_module(mod)
        return True
    except ImportError:
        return False


def _file_exists(*parts: str) -> bool:
    return (ROOT / Path(*parts)).exists()


_SECRET_CWES = {"CWE-798", "CWE-321", "CWE-259", "CWE-312"}


def _run_detection_eval(golden_path: Path) -> dict:
    """Evaluate secrets detection offline; report coverage for other CWEs separately.

    Only CWE-798/321/259/312 can be tested without Semgrep/Bandit installed.
    SQL injection / XSS / cmdi / path-traversal / SSRF / deserialization require
    those tools and are verified by code presence check instead.
    """
    from aegis.pipeline.deterministic.secrets import scan_secrets
    from eval.run import _cases, _file_change

    tp = fp = fn = 0
    other_cwes: set[str] = set()

    for case in _cases(golden_path):
        fc = _file_change(case)
        expected = {item["cwe"] for item in case["expected"]}
        secret_expected = expected & _SECRET_CWES
        other_cwes |= expected - _SECRET_CWES

        if not secret_expected and not expected:
            # Clean negative — check no false positives
            findings = scan_secrets([fc])
            got = {f.cwe for f in findings if f.cwe}
            fp += len(got)
        elif secret_expected:
            findings = scan_secrets([fc])
            got = {f.cwe for f in findings if f.cwe}
            for cwe in secret_expected:
                if any(cwe in (g or "") for g in got):
                    tp += 1
                else:
                    fn += 1
            for cwe in got:
                if cwe and not any(cwe in (e or "") for e in secret_expected):
                    fp += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    tool_cwes_covered = all(
        _file_exists("aegis", "pipeline", "deterministic", f)
        for f in ("semgrep.py", "bandit.py", "sca.py")
    )

    return {
        "secrets_precision": round(precision, 4),
        "secrets_recall": round(recall, 4),
        "secrets_f1": round(f1, 4),
        "other_cwes_in_golden": sorted(other_cwes),
        "other_cwes_tool_coverage": tool_cwes_covered,
        "note": "Semgrep/Bandit/SCA offline eval requires installed tools; "
                "tool files verified by code presence",
    }


def evaluate(golden_path: Path | None = None) -> dict:
    results: dict[str, dict] = {}

    # C1 — webhook reception
    c1_ok = all(
        _file_exists("aegis", "providers", p)
        for p in ("github.py", "gitlab.py", "bitbucket.py")
    ) and _file_exists("aegis", "api", "webhooks.py")
    results["C1"] = {
        "description": "Webhook reception (GitHub/GitLab/Bitbucket)",
        "weight": _WEIGHTS["C1"],
        "score": _WEIGHTS["C1"] if c1_ok else 0,
        "verified": c1_ok,
        "method": "code_presence",
    }

    # C2 — diff-only
    c2_ok = (
        _file_exists("aegis", "providers", "diffparse.py")
        and _module_exists("aegis.pipeline.filter")
        and _module_exists("aegis.tokenest")
    )
    results["C2"] = {
        "description": "Diff-only analysis (no full clone, token savings tracked)",
        "weight": _WEIGHTS["C2"],
        "score": _WEIGHTS["C2"] if c2_ok else 0,
        "verified": c2_ok,
        "method": "code_presence",
    }

    # C3 — detection quality (run the harness)
    golden = golden_path or EVAL_ROOT / "golden" / "full.jsonl"
    if not golden.exists():
        golden = EVAL_ROOT / "golden" / "seed.jsonl"

    try:
        det = _run_detection_eval(golden)
        sp = det["secrets_precision"]
        sr = det["secrets_recall"]
        # Full marks: secrets P≥0.85 & R≥0.85 + tool files present for other CWEs
        tools_ok = det["other_cwes_tool_coverage"]
        if sp >= 0.85 and sr >= 0.85 and tools_ok:
            c3_score = _WEIGHTS["C3"]
        elif sp >= 0.70 and sr >= 0.70:
            c3_score = _WEIGHTS["C3"] // 2
        else:
            c3_score = 0
        c3_verified = sp >= 0.85 and sr >= 0.85 and tools_ok
        results["C3"] = {
            "description": "Detect SQLi / secrets / XSS / bad deps",
            "weight": _WEIGHTS["C3"],
            "score": c3_score,
            "verified": c3_verified,
            "method": "golden_set + code_presence",
            "metrics": {
                "secrets_precision": sp,
                "secrets_recall": sr,
                "secrets_f1": det["secrets_f1"],
                "tool_cwes": det["other_cwes_in_golden"],
                "tool_coverage": tools_ok,
                "golden_file": str(golden),
            },
        }
    except Exception as exc:
        results["C3"] = {
            "description": "Detect SQLi / secrets / XSS / bad deps",
            "weight": _WEIGHTS["C3"],
            "score": 0,
            "verified": False,
            "method": "golden_set + code_presence",
            "error": str(exc),
        }

    # C4 — inline comment with rationale
    c4_ok = (
        _file_exists("aegis", "pipeline", "render.py")
        and _file_exists("aegis", "pipeline", "llm_stage.py")
    )
    results["C4"] = {
        "description": "Inline comment per finding with CWE, rationale, exploit path",
        "weight": _WEIGHTS["C4"],
        "score": _WEIGHTS["C4"] if c4_ok else 0,
        "verified": c4_ok,
        "method": "code_presence",
    }

    # C5 — fix snippet
    c5_ok = _file_exists("aegis", "pipeline", "autofix.py") and _file_exists(
        "aegis", "pipeline", "render.py"
    )
    results["C5"] = {
        "description": "Fix snippet (suggestion block + autofix PR)",
        "weight": _WEIGHTS["C5"],
        "score": _WEIGHTS["C5"] if c5_ok else 0,
        "verified": c5_ok,
        "method": "code_presence",
    }

    # C6 — non-code filtering
    c6_ok = _file_exists("aegis", "pipeline", "filter.py")
    results["C6"] = {
        "description": "Non-code file filtering (images, lock files, generated code)",
        "weight": _WEIGHTS["C6"],
        "score": _WEIGHTS["C6"] if c6_ok else 0,
        "verified": c6_ok,
        "method": "code_presence",
    }

    # C7 — dialog
    c7_ok = _file_exists("aegis", "pipeline", "dialog.py")
    results["C7"] = {
        "description": "Dialog — @secbot why / false positive / ignore / scan full",
        "weight": _WEIGHTS["C7"],
        "score": _WEIGHTS["C7"] if c7_ok else 0,
        "verified": c7_ok,
        "method": "code_presence",
    }

    # C8 — merge block
    c8_ok = _file_exists("aegis", "pipeline", "policy.py")
    results["C8"] = {
        "description": "Merge block on critical findings (status check / request_changes)",
        "weight": _WEIGHTS["C8"],
        "score": _WEIGHTS["C8"] if c8_ok else 0,
        "verified": c8_ok,
        "method": "code_presence",
    }

    total = sum(v["score"] for v in results.values())
    return {
        "total_score": total,
        "max_score": _MAX_SCORE,
        "percent": round(total / _MAX_SCORE * 100, 1),
        "criteria": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", default=None, help="Path to golden JSONL file")
    parser.add_argument("--json", dest="as_json", action="store_true")
    args = parser.parse_args()

    report = evaluate(Path(args.golden) if args.golden else None)

    if args.as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"\n{'='*55}")
    print("  Aegis - C1-C8 Criteria Score")
    print(f"{'='*55}")
    print(f"  Total: {report['total_score']}/{report['max_score']} "
          f"({report['percent']}%)\n")

    for cid, info in report["criteria"].items():
        status = "✓" if info["verified"] else "✗"
        print(f"  {status} {cid} [{info['score']}/{info['weight']}]  {info['description']}")
        if "metrics" in info:
            m = info["metrics"]
            if "secrets_precision" in m:
                print(f"       Secrets: P={m['secrets_precision']:.3f}  "
                      f"R={m['secrets_recall']:.3f}  F1={m['secrets_f1']:.3f}"
                      f"  ToolCoverage={m['tool_coverage']}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
