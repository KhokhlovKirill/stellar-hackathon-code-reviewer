"""Cheap, dependency-free token estimator (~4 chars/token).

Used only for analytics/budgeting (criterion C2 evidence and per-scan caps), never
for correctness — so an approximation is fine and avoids a tokenizer dependency.
"""

from __future__ import annotations


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, round(len(text) / 4))
