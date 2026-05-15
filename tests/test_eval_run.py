"""Eval harness smoke test."""

from __future__ import annotations

from pathlib import Path

from eval.run import run


def test_seed_eval_gate_is_green() -> None:
    metrics = run(Path("eval/golden/seed.jsonl"))
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.line_accuracy == 1.0
