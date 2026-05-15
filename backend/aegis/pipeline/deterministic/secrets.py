"""Hardcoded-secret detection on ADDED lines only (criterion C3).

High-confidence named patterns + a Shannon-entropy fallback for opaque blobs.
Values are masked in the finding (type + first/last chars) so we never echo the
secret itself (docs/10). Scans only `+` lines so unchanged code is not re-flagged.
"""

from __future__ import annotations

import math
import re

from aegis.config import get_config
from aegis.schemas import FileChange, Finding, FindingSource, Severity

# (name, compiled regex, CWE). Patterns mirror the log redaction set.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # AWS — access key ID (AKIA…) and secret access key (40-char base64-ish)
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), "CWE-798"),
    ("AWS secret access key",
     re.compile(r"""(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['"]?[A-Za-z0-9/+]{40}['"]?"""),
     "CWE-798"),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "CWE-798"),
    ("GitLab PAT", re.compile(r"glpat-[A-Za-z0-9_\-]{15,}"), "CWE-798"),
    # Slack webhooks and bot tokens
    ("Slack webhook",
     re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
     "CWE-798"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "CWE-798"),
    ("Stripe secret key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}"), "CWE-798"),
    ("OpenAI-style key", re.compile(r"sk-[A-Za-z0-9]{20,}"), "CWE-798"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "CWE-798"),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "CWE-321"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
     "CWE-798"),
    # DB URLs with embedded credentials: scheme://user:pass@host
    ("DB connection string with creds",
     re.compile(r"(?i)(postgres(?:ql)?|mysql|mongodb|redis|amqp)://[^:\s@/]+:[^@\s]{3,}@"),
     "CWE-798"),
    # Generic: password/secret/api_key = "value" (must come after specific patterns)
    ("Generic assigned secret",
     re.compile(r"""(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"""
                r"""auth[_-]?token|client[_-]?secret)\s*[=:]\s*['"][^'"\s]{6,}['"]"""),
     "CWE-798"),
]
_SECRETISH_FILE = re.compile(r"(^|/)(\.env|\.npmrc|\.pypirc|id_rsa|.*\.pem|.*\.p12)$")
_PLACEHOLDER = re.compile(
    r"(?i)(example|changeme|placeholder|your[_-]?|xxx+|\.\.\.|<[^>]+>|dummy|test[_-]?key|fake)"
)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _mask(value: str) -> str:
    v = value.strip("'\"")
    if len(v) <= 8:
        return "****"
    return f"{v[:3]}…{v[-2:]} (len={len(v)})"


def _high_entropy_tokens(line: str, threshold: float) -> list[str]:
    out = []
    for tok in re.findall(r"['\"]?([A-Za-z0-9+/=_\-]{20,})['\"]?", line):
        if _PLACEHOLDER.search(tok):
            continue
        if _shannon(tok) >= threshold and re.search(r"[0-9]", tok) and re.search(r"[A-Za-z]", tok):
            out.append(tok)
    return out


def scan_secrets(files: list[FileChange]) -> list[Finding]:
    threshold = get_config().deterministic.secrets_min_entropy
    findings: list[Finding] = []
    for fc in files:
        env_file = bool(_SECRETISH_FILE.search(fc.path))
        for ln in fc.added_lines():
            text = ln.content
            if not text.strip() or ln.new_lineno is None:
                continue
            matched = False
            for name, pat, cwe in _PATTERNS:
                m = pat.search(text)
                if not m:
                    continue
                val = m.group(0)
                if _PLACEHOLDER.search(val) and name == "Generic assigned secret":
                    continue
                matched = True
                findings.append(Finding(
                    file=fc.path, line=ln.new_lineno, diff_position=ln.diff_position,
                    cwe=cwe, rule_id=f"secret:{name}",
                    severity=Severity.CRITICAL,
                    confidence=0.98, source=FindingSource.DETERMINISTIC,
                    title=f"Hardcoded secret: {name}",
                    rationale=(
                        f"A {name} appears on an added line"
                        + (f" in a secrets-bearing file ({fc.path})" if env_file else "")
                        + f". Masked value: {_mask(val)}. Committed credentials are "
                        "retrievable from history even if later removed."
                    ),
                    exploit="Anyone with repo/history access obtains the live credential.",
                    fix="Remove the literal; load from env/secret manager and rotate the "
                        "exposed credential immediately.",
                ))
                break
            if matched:
                continue
            for tok in _high_entropy_tokens(text, threshold):
                findings.append(Finding(
                    file=fc.path, line=ln.new_lineno, diff_position=ln.diff_position,
                    cwe="CWE-798", rule_id="secret:high-entropy",
                    severity=Severity.HIGH, confidence=0.85,
                    source=FindingSource.DETERMINISTIC,
                    title="Possible hardcoded credential (high entropy)",
                    rationale=f"High-entropy token on an added line ({_mask(tok)}); "
                              "likely a key/token committed to source.",
                    exploit="If this is a live secret, it is exposed in history.",
                    fix="Move to a secret store; rotate if real.",
                ))
    return findings
