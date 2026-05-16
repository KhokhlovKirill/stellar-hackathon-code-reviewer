"""Tests for the LangGraph orchestration layer.

These cover the wiring (graph topology, error short-circuit, trace shape) and
the dispatcher (engine knob routing). The full scan path is exercised by the
existing `test_llm_units.py` against `run_simple_scan` — by construction, the
graph nodes call the same helpers, so duplicating that here would be churn.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from aegis.graph.builder import build_security_graph
from aegis.graph.runner import run_graph_scan
from aegis.pipeline.dispatch import run_scan
from aegis.pipeline.simple_scan import SimpleScanResult


def test_graph_compiles_with_all_expected_nodes() -> None:
    g = build_security_graph()
    # __start__ is LangGraph's synthetic entry node; everything else is ours.
    expected = {
        "__start__",
        "parse",
        "fetch_pr",
        "fetch_diff",
        "filter",
        "deterministic",
        "llm",
        "review",
        "finalize",
    }
    assert expected.issubset(set(g.nodes))


def test_graph_short_circuits_on_url_parse_error() -> None:
    """An unparseable URL must skip fetch/llm/review and still produce a valid result."""
    result = asyncio.run(run_graph_scan("not-a-github-url"))
    assert isinstance(result, SimpleScanResult)
    assert result.error is not None
    assert "Cannot parse" in result.error
    # No network/LLM stages were executed.
    assert result.findings == []
    assert result.files_scanned == 0


def test_run_graph_scan_returns_simple_scan_result_shape() -> None:
    """The graph path must be a drop-in for `run_simple_scan` (same dataclass)."""
    result = asyncio.run(run_graph_scan("not-a-github-url"))
    # All the fields the API/DB layer reads must be present.
    for field in (
        "repo",
        "pr_number",
        "pr_title",
        "pr_url",
        "pr_author",
        "findings",
        "files_scanned",
        "degraded",
        "degraded_reasons",
        "files_scanned_paths",
        "head_sha",
        "summary",
        "finding_labels",
        "error",
    ):
        assert hasattr(result, field), f"missing field {field!r}"


def test_dispatch_prefers_graph_when_forced() -> None:
    """`prefer_graph=True` must route through `run_graph_scan`, not the direct path."""
    called: dict[str, int] = {"graph": 0, "direct": 0}

    async def fake_graph(url: str, token: str | None = None, lang: str = "ru") -> SimpleScanResult:
        called["graph"] += 1
        return SimpleScanResult(repo="g", pr_number=0, pr_title="", pr_url=url, pr_author="")

    async def fake_direct(url: str, token: str | None = None, lang: str = "ru") -> SimpleScanResult:
        called["direct"] += 1
        return SimpleScanResult(repo="d", pr_number=0, pr_title="", pr_url=url, pr_author="")

    with (
        patch("aegis.graph.runner.run_graph_scan", new=fake_graph),
        patch("aegis.pipeline.dispatch.run_simple_scan", new=fake_direct),
    ):
        out = asyncio.run(run_scan("https://example", prefer_graph=True))
        assert out.repo == "g"
        assert called == {"graph": 1, "direct": 0}

        out = asyncio.run(run_scan("https://example", prefer_graph=False))
        assert out.repo == "d"
        assert called == {"graph": 1, "direct": 1}


@pytest.mark.parametrize(
    ("engine", "expected"),
    [("auto", None), ("graph", True), ("direct", False), ("nonsense", None), (None, None)],
)
def test_engine_knob_maps_to_dispatch_arg(engine: str | None, expected: bool | None) -> None:
    from aegis.api.extension import _engine_to_pref

    assert _engine_to_pref(engine) is expected
