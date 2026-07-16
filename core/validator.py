"""
Contextual validation layer.

Raw pattern matches are noisy: the string "password" in a comment, or a
documentation example (AKIAIOSFODNN7EXAMPLE), will match the regexes just
as well as a real leaked secret. This module scores matches by entropy and
filters known-safe/example strings so only credible findings reach the
evidence store.
"""

import math
from collections import Counter

# Strings that are commonly matched by pattern rules but are NOT real secrets
# (documentation examples, placeholder values, well-known test fixtures).
WHITELIST = {
    "AKIAIOSFODNN7EXAMPLE",          # AWS's own official documentation example key
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "your_api_key_here",
    "changeme",
    "example",
    "placeholder",
    "xxxxxxxxxxxx",
}

# Minimum Shannon entropy (bits per character) for a string to be treated as
# a plausible real secret rather than natural-language / low-randomness text.
ENTROPY_THRESHOLD = 3.0


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char -- high for random-looking strings
    (real keys/tokens), low for natural language or repeated characters."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_whitelisted(value: str) -> bool:
    lowered = value.lower()
    return any(w.lower() in lowered for w in WHITELIST)


def validate(pattern_name: str, matched_value: str) -> tuple[bool, str]:
    """
    Returns (is_credible, reason). Called on every raw pattern match before
    it's allowed into the evidence store.
    """
    if is_whitelisted(matched_value):
        return False, "whitelisted (known example/placeholder value)"

    # Password-string and generic-key matches benefit from an entropy check;
    # structural patterns (JWT format, PEM header, AKIA prefix) are already
    # high-confidence by shape and don't need it.
    if pattern_name in ("password_string", "generic_api_key"):
        entropy = shannon_entropy(matched_value)
        if entropy < ENTROPY_THRESHOLD:
            return False, f"low entropy ({entropy:.2f}) -- likely not a real secret"

    return True, "passed validation"
