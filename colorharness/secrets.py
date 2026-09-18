"""Secret scanning: sk-, ghp_, AKIA, and private-key headers -> SECRET_EXPOSURE."""

from __future__ import annotations

import re
from typing import Any


class SecretExposureError(Exception):
    pass


# Fingerprints only, never values. Each entry maps a detector to the kind name.
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "sk_token": re.compile(r"\bsk[-_](?:live|test)?[A-Za-z0-9_-]{16,}"),
    "ghp_token": re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
}


def scan_for_secrets(value: Any) -> list[str]:
    """Return the sorted list of secret kinds detected in *value*.

    Detection runs over strings recursively (dict values, list items); it
    never logs or returns the secret itself, only detector names.
    """
    found: set[str] = set()
    if isinstance(value, str):
        for kind, pattern in SECRET_PATTERNS.items():
            if pattern.search(value):
                found.add(kind)
    elif isinstance(value, dict):
        for v in value.values():
            found.update(scan_for_secrets(v))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for v in value:
            found.update(scan_for_secrets(v))
    return sorted(found)


def raise_if_secret(value: Any) -> None:
    kinds = scan_for_secrets(value)
    if kinds:
        raise SecretExposureError(f"secret material detected: {', '.join(kinds)}")