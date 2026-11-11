"""Deterministic content filters for secret/PII detection, injection matching, and normalization."""

from __future__ import annotations

import base64
import binascii
import re

_CANARY_AND_PII_PATTERNS = [
    re.compile(r"CANARY_[A-Z0-9_-]+"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"(?i)sk-[A-Za-z0-9]{16,}"),
    re.compile(r"(?i)(?:SERVICE_API_KEY|INTERNAL_DB_TOKEN)\s*="),
]

_LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalize_leetspeak(text: str) -> str:
    """Normalize common leetspeak substitutions for downstream regex screening."""
    return text.translate(_LEET_MAP)


def decode_embedded_base64(text: str) -> str:
    """Extract and decode plausible base64 substrings to catch encoded injections/paths."""
    decoded_parts: list[str] = []
    for token in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", text):
        try:
            raw = base64.b64decode(token, validate=True)
            txt = raw.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            txt = ""
        if txt and sum(ch.isprintable() for ch in txt) / len(txt) > 0.85:
            decoded_parts.append(txt)
    return text + ("\n[DECODED_B64] " + " ".join(decoded_parts) if decoded_parts else "")


def screen_patterns(
    text: str,
    patterns: list[str],
    decode_b64: bool = False,
    norm_leet: bool = False,
) -> str | None:
    """Return the first matching regex pattern string or None."""
    variants = [text]
    if decode_b64:
        variants.append(decode_embedded_base64(text))
    if norm_leet:
        variants.extend(normalize_leetspeak(v) for v in list(variants))

    for pat in patterns:
        rx = re.compile(pat)
        for v in variants:
            if rx.search(v):
                return pat
    return None


def contains_canary_or_pii(text: str) -> str | None:
    """Return matched secret/PII indicator if present."""
    for rx in _CANARY_AND_PII_PATTERNS:
        m = rx.search(text)
        if m:
            return m.group(0)
    return None

