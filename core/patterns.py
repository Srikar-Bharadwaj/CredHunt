"""
Shared regex patterns for credential / secret detection.
Used by both the original file scanner and the new network plugins so
detection logic lives in exactly one place.
"""

import re

PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"),
    "password_string": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "private_key_header": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
}


def find_patterns(text: str):
    """
    Return list of (pattern_name, matched_string) tuples found in text.
    Where a pattern captures the secret value separately from its keyword
    (e.g. `password=` vs the password itself), the captured value is
    returned so entropy scoring reflects the secret, not the surrounding
    keyword text.
    """
    results = []
    if not text:
        return results
    for name, rx in PATTERNS.items():
        for m in rx.finditer(text):
            groups = [g for g in m.groups() if g]
            matched = groups[-1] if groups else m.group(0)
            results.append((name, matched))
    return results
