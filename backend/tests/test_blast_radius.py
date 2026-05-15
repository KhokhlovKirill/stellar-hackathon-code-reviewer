"""Blast radius Mermaid generation."""

from __future__ import annotations

from aegis.pipeline.blast_radius import build_blast_radius


def test_build_blast_radius_for_imported_vulnerable_package() -> None:
    mermaid = build_blast_radius(
        {"app/main.py": "1: import flask\n2: from requests import get"},
        {"requests"},
    )
    assert mermaid is not None
    assert "graph TD" in mermaid
    assert "app/main.py" in mermaid
    assert "requests" in mermaid


def test_build_blast_radius_returns_none_without_edges() -> None:
    assert build_blast_radius({"app/main.py": "1: import os"}, {"requests"}) is None
