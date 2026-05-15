"""High-entropy string detector for catching hardcoded secrets."""

from __future__ import annotations

import math
import re
from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)

# Minimum length before running entropy check
_MIN_STRING_LEN = 20
# Entropy threshold (bits per character) — typical passwords/tokens are > 3.5
_ENTROPY_THRESHOLD = 3.5
# Max strings to check per line (avoid DoS on minified files)
_MAX_PER_LINE = 5

_STRING_RE = re.compile(r'["\']([A-Za-z0-9+/=!@#$%^&*_\-]{20,})["\']')

# Common false-positive patterns (hashes, UUIDs, example values)
_FP_PATTERNS = [
    re.compile(r'^[0]{8,}$'),  # all zeros
    re.compile(r'^example|^test|^placeholder|^dummy|^sample', re.IGNORECASE),
    re.compile(r'^[a-f0-9]{32}$'),  # MD5 hash (constant)
    re.compile(r'^[a-f0-9]{64}$'),  # SHA256 hash (constant)
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (bits per character)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_false_positive(s: str) -> bool:
    for pat in _FP_PATTERNS:
        if pat.match(s):
            return True
    return False


async def run_entropy_scan(
    files: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Scan added lines in diff for high-entropy strings."""
    findings: list[dict[str, Any]] = []

    for f in files:
        filename = f.get("filename", "")
        # Skip known binary/asset types
        if any(filename.endswith(ext) for ext in (".png", ".jpg", ".pdf", ".zip", ".gz", ".woff")):
            continue

        patch = f.get("patch", "")
        for line_offset, line in enumerate(patch.splitlines()):
            if not line.startswith("+") or line.startswith("+++"):
                continue

            matches = _STRING_RE.findall(line)[:_MAX_PER_LINE]
            for s in matches:
                if len(s) < _MIN_STRING_LEN:
                    continue
                if _is_false_positive(s):
                    continue
                entropy = _shannon_entropy(s)
                if entropy >= _ENTROPY_THRESHOLD:
                    findings.append(
                        {
                            "file_path": filename,
                            "line_number": line_offset,
                            "vuln_type": "high-entropy-string",
                            "severity": "high",
                            "description": (
                                f"High-entropy string detected (entropy={entropy:.2f}): "
                                f"possible hardcoded secret"
                            ),
                            "cwe": "CWE-798",
                            "source": "entropy",
                            "confidence": 0.7,
                            "fingerprint": f"entropy:{filename}:{line_offset}:{s[:16]}",
                        }
                    )

    log.info("entropy.done", findings=len(findings))
    return findings
