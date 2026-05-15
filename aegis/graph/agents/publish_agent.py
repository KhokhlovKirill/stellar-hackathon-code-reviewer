"""Publish agent — posts review comments and sets status checks on GitHub/GitLab."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.providers import get_provider
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def publish_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Post PR comments and update status checks via the VCS provider.

    Updates:
        - state["published"]: bool
        - state["publish_error"]: str | None
        - state["comment_ids"]: list of created comment IDs
    """
    pr_comment_body = state.get("pr_comment_body", "")
    inline_comments = state.get("inline_comments", [])
    status_check = state.get("status_check", {})
    pr_metadata = state.get("pr_metadata", {})
    provider_name = state.get("provider", "github")
    repo_full_name = state.get("repo_full_name", "")
    access_token = state.get("access_token", "")

    pr_number = pr_metadata.get("number")
    pr_node_id = pr_metadata.get("node_id") or pr_metadata.get("id")
    head_sha = pr_metadata.get("head_sha", "")

    log.info("publish.start", pr=pr_number, provider=provider_name)

    if not repo_full_name or not access_token:
        log.warning("publish.missing_credentials")
        return {**state, "published": False, "publish_error": "Missing credentials"}

    try:
        provider = get_provider(provider_name, access_token, repo_full_name)

        comment_ids: list[str] = []

        # Post main comment
        if pr_comment_body:
            comment_id = await provider.post_comment(
                repo=repo_full_name,
                pr_number=pr_number,
                body=pr_comment_body,
            )
            if comment_id:
                comment_ids.append(comment_id)

        # Post inline comments (limit to avoid API rate limits)
        for ic in inline_comments[:10]:
            try:
                cid = await provider.post_inline_comment(
                    repo=repo_full_name,
                    pr_number=pr_number,
                    path=ic.get("path"),
                    line=ic.get("line"),
                    body=ic.get("body"),
                    commit_sha=head_sha,
                )
                if cid:
                    comment_ids.append(cid)
            except Exception as e:
                log.warning("publish.inline_comment_failed", error=str(e))

        # Set status check
        if status_check and head_sha:
            await provider.set_status_check(
                repo=repo_full_name,
                sha=head_sha,
                state=status_check.get("state", "success"),
                description=status_check.get("description", ""),
                context=status_check.get("context", "aegis/security-review"),
            )

        log.info("publish.complete", comment_ids=len(comment_ids))
        return {**state, "published": True, "publish_error": None, "comment_ids": comment_ids}

    except Exception as exc:
        log.error("publish.error", error=str(exc))
        return {**state, "published": False, "publish_error": str(exc), "comment_ids": []}
