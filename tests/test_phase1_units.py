"""Phase 1 unit gate: signature verification (C1) + diff parsing (C2 line mapping).

Pure units, no DB/Redis. Full webhook e2e runs on compose in Phase 11.
"""

from __future__ import annotations

import hashlib
import hmac
import os

import pytest

os.environ.setdefault("AEGIS_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("AEGIS_VAULT_KEY", "xEOF8a4KNVGyGBbrcF9ItOdw-YaEM1jaNmh4trOPW70=")

from aegis.errors import WebhookVerificationError
from aegis.providers.diffparse import parse_unified_diff
from aegis.providers.gitlab import _parse_gitlab_diff
from aegis.providers.signatures import (
    verify_bitbucket,
    verify_github,
    verify_gitlab,
)
from aegis.schemas import LineKind


def test_github_signature_ok_and_fail() -> None:
    body = b'{"x":1}'
    secret = "s3cr3t"
    good = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    verify_github(body, {"x-hub-signature-256": good}, secret)  # no raise
    with pytest.raises(WebhookVerificationError):
        verify_github(body, {"x-hub-signature-256": "sha256=deadbeef"}, secret)
    with pytest.raises(WebhookVerificationError):
        verify_github(body, {}, secret)
    with pytest.raises(WebhookVerificationError):
        verify_github(body, {"x-hub-signature-256": good}, "")  # empty secret = fail-closed


def test_gitlab_token() -> None:
    verify_gitlab(b"{}", {"x-gitlab-token": "tok"}, "tok")
    with pytest.raises(WebhookVerificationError):
        verify_gitlab(b"{}", {"x-gitlab-token": "nope"}, "tok")


def test_bitbucket_hmac_and_shared() -> None:
    body = b"{}"
    secret = "bb"
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    verify_bitbucket(body, {"x-hub-signature": sig}, secret)
    verify_bitbucket(body, {"x-aegis-secret": "bb"}, secret)
    with pytest.raises(WebhookVerificationError):
        verify_bitbucket(body, {"x-aegis-secret": "bad"}, secret)


_DIFF = """diff --git a/app/db.py b/app/db.py
index 111..222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,4 +10,5 @@ def get_user(uid):
 def get_user(uid):
     safe = True
-    return db.query("SELECT * FROM u WHERE id=%s", uid)
+    q = "SELECT * FROM u WHERE id=" + uid
+    return db.query(q)
     return None
"""


def test_unified_diff_line_mapping() -> None:
    files = parse_unified_diff(_DIFF)
    assert len(files) == 1
    fc = files[0]
    assert fc.path == "app/db.py" and fc.language == "python" and fc.status == "modified"
    added = fc.added_lines()
    assert [a.content for a in added] == [
        '    q = "SELECT * FROM u WHERE id=" + uid',
        "    return db.query(q)",
    ]
    # right-side line numbers present and monotonic; positions assigned
    assert added[0].new_lineno == 12
    assert added[0].kind is LineKind.ADD
    assert all(a.diff_position is not None for a in added)


def test_gitlab_structured_diff_parser() -> None:
    body = (
        "@@ -1,2 +1,3 @@\n"
        " import os\n"
        "-x = 1\n"
        '+x = os.system(cmd)\n'
        "+y = 2\n"
    )
    hunks = _parse_gitlab_diff(body)
    assert len(hunks) == 1
    adds = [ln for ln in hunks[0].lines if ln.kind is LineKind.ADD]
    assert adds[0].content == "x = os.system(cmd)"
    assert adds[0].new_lineno == 2
    assert adds[1].new_lineno == 3
