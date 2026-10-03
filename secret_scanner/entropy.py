"""
entropy.py
Shannon-entropy based detection for high-randomness tokens (catches secrets
that don't match a known vendor pattern, e.g. custom API keys).
"""

import math
import re

# Candidate token shapes worth entropy-checking
TOKEN_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,}")

# Assignment context so we don't flag random hashes/minified JS everywhere
ASSIGNMENT_CONTEXT_RE = re.compile(
    r"(?i)(key|token|secret|password|pwd|auth|credential|api)[A-Za-z0-9_]*\s*[:=]\s*['\"]([A-Za-z0-9+/_\-]{20,})['\"]"
)


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def find_high_entropy_strings(line: str, min_len: int = 20, threshold: float = 4.3):
    """
    Scan a line of text for high-entropy tokens that appear in an
    assignment context suggestive of a secret (key/token/password/etc).
    Returns list of (matched_string, entropy_value).
    """
    results = []
    for m in ASSIGNMENT_CONTEXT_RE.finditer(line):
        token = m.group(2)
        if len(token) < min_len:
            continue
        ent = shannon_entropy(token)
        # hex strings max out at 4.0 bits/char, so they need a lower bar
        limit = 3.0 if re.fullmatch(r"[0-9a-fA-F]+", token) else threshold
        if ent >= limit:
            results.append((token, round(ent, 2)))
    return results
