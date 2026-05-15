"""ChatOps parser and thread helpers."""

from __future__ import annotations

from aegis.pipeline.dialog import (
    _extract_answer,
    _fingerprint,
    parse_command,
    should_answer,
)
from aegis.schemas import DiscussionThread, EventKind, Provider, WebhookEvent


def _event(body: str, in_reply_to_id: str | None = None) -> WebhookEvent:
    return WebhookEvent(
        provider=Provider.GITHUB,
        kind=EventKind.COMMENT,
        delivery_id="d",
        repo_slug="acme/api",
        repo_external_id="42",
        pr_id="7",
        comment_body=body,
        in_reply_to_id=in_reply_to_id,
        thread_id=in_reply_to_id,
    )


def test_should_answer_mentions_or_direct_replies() -> None:
    assert should_answer("@secbot why?", _event("@secbot why?")) is True
    assert should_answer("why?", _event("why?", in_reply_to_id="123")) is True
    assert should_answer("why?", _event("why?")) is False


def test_parse_dialog_commands() -> None:
    assert parse_command("@secbot false positive, this is test data").kind == "false_positive"
    cmd = parse_command("@secbot ignore, /tests/**")
    assert cmd.kind == "ignore"
    assert cmd.argument == "/tests/**"
    assert parse_command("@secbot scan full").kind == "scan_full"
    assert parse_command("@secbot why is this SQLi?").kind == "explain"


def test_extract_fingerprint_from_thread() -> None:
    thread = DiscussionThread(
        thread_id="t",
        pr_id="7",
        comments=[
            {
                "body": (
                    "Finding fingerprint: "
                    "`0123456789abcdef0123456789abcdef01234567`"
                )
            }
        ],
    )
    assert _fingerprint(thread) == "0123456789abcdef0123456789abcdef01234567"


def test_extract_answer_from_json_or_text() -> None:
    assert _extract_answer('{"answer":"Use parameters."}') == "Use parameters."
    assert _extract_answer("Plain explanation") == "Plain explanation"
    assert _extract_answer("{bad-json") == ""
