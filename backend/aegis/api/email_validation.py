"""Email validation shared by API and legacy web forms."""

from __future__ import annotations

import re

_LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def normalize_email(value: str) -> str:
    return value.strip().lower()


def is_plausible_email(value: str) -> bool:
    """Validate structural deliverability, not live mailbox existence."""
    email = normalize_email(value)
    if not (3 <= len(email) <= 254) or email.count("@") != 1:
        return False
    local, domain = email.rsplit("@", 1)
    if not local or not domain or len(local) > 64:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    if not _LOCAL_RE.fullmatch(local):
        return False
    if domain.startswith("[") or domain.endswith("]") or ".." in domain:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    if not all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return False
    tld = labels[-1]
    return len(tld) >= 2 and tld.isalpha()
