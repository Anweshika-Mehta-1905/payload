"""
Mock static "Antivirus / IDS" scanner.

This is a deliberately naive, purely static signature matcher. It checks the
plaintext of an input against a list of mock "bad words." It has no decoding,
emulation, or behavioral analysis, which is exactly why it is easy to bypass.
It is not connected to any real security product.
"""

from typing import Dict, List, Optional

DEFAULT_BLACKLIST: List[str] = [
    "mock_malware",
    "unauthorized_command",
    "drop_table",
]


def scan(
    text: str,
    blacklist: Optional[List[str]] = None,
    case_sensitive: bool = False,
) -> Dict:
    """
    Scan text for blacklisted substrings.

    Returns a dictionary:
        {
            "status":   "Detected" | "Bypassed",
            "detected": bool,
            "matches":  list of blacklist terms found,
            "length":   length of the scanned text,
        }
    """
    terms = DEFAULT_BLACKLIST if blacklist is None else blacklist
    haystack = text if case_sensitive else text.lower()

    matches: List[str] = []
    for term in terms:
        needle = term if case_sensitive else term.lower()
        if needle and needle in haystack:
            matches.append(term)

    detected = bool(matches)
    return {
        "status": "Detected" if detected else "Bypassed",
        "detected": detected,
        "matches": matches,
        "length": len(text),
    }
