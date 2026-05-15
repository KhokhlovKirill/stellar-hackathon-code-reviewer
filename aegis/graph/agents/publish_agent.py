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
    head_sha = pr_metadata.get("head_sha", "")

    log.info("publish.start", pr=pr_number, provider=provider_name)

    if not repo_full_name or not access_token:
        log.warning("publish.missing_credentials")
        return {**state, "published": False, "publish_error": "Missing credentials"}
    if pr_number is None:
        log.warning("publish.missing_pr_number")
        return {**state, "published": False, "publish_error": "Missing pr_number"}

    try:
        provider = get_provider(provider_name, access_token, repo_full_name)

        comment_ids: list[str] = []

        async with provider:
            # Post main summary comment
            if pr_comment_body:
                try:
                    comment_id = await provider.publish_pr_comment(
                        pr_number=int(pr_number),
                        body=pr_comment_body,
                    )
                    if comment_id:
                        comment_ids.append(str(comment_id))
                except Exception as exc:
                    log.warning("publish.summary_comment_failed", error=str(exc))

            # Post inline comments (require head_sha; limit to avoid rate limits)
            if head_sha:
                for ic in inline_comments[:10]:
                    try:
                        cid = await provider.publish_inline_comment(
                            pr_number=int(pr_number),
                            commit_sha=head_sha,
                            path=ic.get("path", ""),
                            line=int(ic.get("line") or 1),
                            body=ic.get("body", ""),
                        )
                        if cid:
                            comment_ids.append(str(cid))
                    except Exception as exc:
                        log.warning("publish.inline_comment_failed", error=str(exc))
            elif inline_comments:
                log.warning(
                    "publish.inline_comments_skipped",
                    reason="missing head_sha",
                    count=len(inline_comments),
                )

            # Set status check (requires head SHA)
            if status_check and head_sha:
                try:
                    await provider.set_status_check(
                        commit_sha=head_sha,
                        state=status_check.get("state", "success"),
                        description=status_check.get("description", ""),
                        context=status_check.get("context", "aegis/security-review"),
                    )
                except Exception as exc:
                    log.warning("publish.status_check_failed", error=str(exc))

        log.info("publish.complete", comment_ids=len(comment_ids))
        return {**state, "published": True, "publish_error": None, "comment_ids": comment_ids}

    except Exception as exc:
        log.error("publish.error", error=str(exc))
        return {**state, "published": False, "publish_error": str(exc), "comment_ids": []}
