"""GitHub provider write-operation payload tests; no network."""

from __future__ import annotations

from typing import Any

import pytest

from aegis.providers.github import GitHubProvider
from aegis.schemas import (
    MergePolicyDecision,
    Provider,
    PullRequest,
    ReviewComment,
)


class _Resp:
    status_code = 201

    def json(self) -> dict[str, Any]:
        return {"id": 123}


def _pr() -> PullRequest:
    return PullRequest(
        provider=Provider.GITHUB,
        repo_slug="acme/api",
        repo_external_id="42",
        pr_id="7",
        pr_number=7,
        base_sha="base",
        head_sha="head",
    )


@pytest.mark.asyncio
async def test_post_inline_comment_uses_diff_position(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    gh = GitHubProvider()
    calls: list[dict[str, Any]] = []

    async def _request(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append({"args": args, "kwargs": kwargs})
        return _Resp()

    monkeypatch.setattr(gh, "_request", _request)
    ref = await gh.post_inline_comment(
        _pr(),
        "tok",
        ReviewComment(
            file="app/db.py",
            line=42,
            diff_position=9,
            body="SQLi",
            finding_fingerprint="fp",
        ),
    )

    payload = calls[0]["kwargs"]["json"]
    assert ref == "123"
    assert calls[0]["args"][1] == "/repos/acme/api/pulls/7/comments"
    assert payload["commit_id"] == "head"
    assert payload["position"] == 9
    assert "line" not in payload


@pytest.mark.asyncio
async def test_status_and_request_changes_payloads(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    gh = GitHubProvider()
    calls: list[dict[str, Any]] = []

    async def _request(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append({"args": args, "kwargs": kwargs})
        return _Resp()

    monkeypatch.setattr(gh, "_request", _request)
    decision = MergePolicyDecision(
        block=True,
        state="failure",
        reason="critical security finding",
    )
    await gh.set_status_check(_pr(), "tok", decision, "https://aegis/scan/1")
    await gh.request_changes(_pr(), "tok", "Fix critical findings")

    assert calls[0]["args"][1] == "/repos/acme/api/statuses/head"
    assert calls[0]["kwargs"]["json"]["state"] == "failure"
    assert calls[1]["args"][1] == "/repos/acme/api/pulls/7/reviews"
    assert calls[1]["kwargs"]["json"]["event"] == "REQUEST_CHANGES"
