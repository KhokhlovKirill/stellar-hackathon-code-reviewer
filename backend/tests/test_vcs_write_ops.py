"""GitLab and Bitbucket write-operation payload tests."""

from __future__ import annotations

from typing import Any

import pytest

from aegis.providers.bitbucket import BitbucketProvider
from aegis.providers.gitlab import GitLabProvider
from aegis.schemas import MergePolicyDecision, Provider, PullRequest, ReviewComment


class _Resp:
    status_code = 201

    def json(self) -> dict[str, Any]:
        return {"id": 123, "notes": [{"body": "ok"}]}


def _pr(provider: Provider) -> PullRequest:
    return PullRequest(
        provider=provider,
        repo_slug="group/api" if provider is Provider.GITLAB else "team/api",
        repo_external_id="42",
        pr_id="7",
        pr_number=7,
        base_sha="base",
        head_sha="head",
    )


@pytest.mark.asyncio
async def test_gitlab_inline_comment_and_status_payload(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    gl = GitLabProvider()
    calls: list[dict[str, Any]] = []

    async def _request(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append({"args": args, "kwargs": kwargs})
        return _Resp()

    monkeypatch.setattr(gl, "_request", _request)
    await gl.post_inline_comment(
        _pr(Provider.GITLAB),
        "tok",
        ReviewComment(
            file="app/db.py",
            line=42,
            body="SQLi",
            finding_fingerprint="fp",
        ),
    )
    await gl.set_status_check(
        _pr(Provider.GITLAB),
        "tok",
        MergePolicyDecision(block=True, state="failure", reason="critical"),
        "https://aegis/scan/1",
    )

    # URLs are now absolute (per-call host resolution): a PR with no carried
    # instance_api_base resolves to the default gitlab.com API root.
    assert calls[0]["args"][1] == (
        "https://gitlab.com/api/v4/projects/group%2Fapi/merge_requests/7/discussions"
    )
    pos = calls[0]["kwargs"]["json"]["position"]
    assert pos["new_path"] == "app/db.py"
    assert pos["new_line"] == 42
    assert calls[1]["args"][1] == (
        "https://gitlab.com/api/v4/projects/group%2Fapi/statuses/head"
    )
    assert calls[1]["kwargs"]["json"]["state"] == "failed"


@pytest.mark.asyncio
async def test_bitbucket_inline_comment_and_status_payload(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    bb = BitbucketProvider()
    calls: list[dict[str, Any]] = []

    async def _request(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append({"args": args, "kwargs": kwargs})
        return _Resp()

    monkeypatch.setattr(bb, "_request", _request)
    await bb.post_inline_comment(
        _pr(Provider.BITBUCKET),
        "tok",
        ReviewComment(
            file="app/db.py",
            line=42,
            body="SQLi",
            finding_fingerprint="fp",
        ),
    )
    await bb.set_status_check(
        _pr(Provider.BITBUCKET),
        "tok",
        MergePolicyDecision(block=True, state="failure", reason="critical"),
        "https://aegis/scan/1",
    )

    assert calls[0]["args"][1] == "/repositories/team/api/pullrequests/7/comments"
    assert calls[0]["kwargs"]["json"]["inline"] == {"path": "app/db.py", "to": 42}
    assert calls[1]["args"][1] == "/repositories/team/api/commit/head/statuses/build"
    assert calls[1]["kwargs"]["json"]["state"] == "FAILED"
