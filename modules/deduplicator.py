"""
Deduplicates findings across scanning tools.

Two findings are treated as the same real issue when their *normalized*
title, host, and port match. Normalization (lowercasing, stripping URL
schemes and paths, collapsing whitespace, and mapping web ports to a
single value) lets different tools describe the same issue in their own
dialect and still be deduplicated into one record.

The fingerprint is a deterministic SHA-1 over the normalized fields, NOT
Python's built-in hash(). Built-in hash() is salted per process via
PYTHONHASHSEED, which made dedup results non-reproducible between runs.
"""

import hashlib
import re
from urllib.parse import urlparse

WEB_PORTS = {"80", "443", "web", "http", "https"}

_SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_WHITESPACE_RE = re.compile(r"\s+")


def get_severity_weight(severity) -> int:
    """Assigns a numerical weight to a severity for dedup preference."""
    if severity is None:
        return 0
    return _SEVERITY_WEIGHTS.get(str(severity).strip().lower(), 0)


def _normalize_title(title) -> str:
    """Lowercases, trims, and collapses whitespace in a finding title."""
    if not title:
        return "unknown"
    text = _WHITESPACE_RE.sub(" ", str(title).strip().lower())
    return text or "unknown"


def _normalize_host(host) -> str:
    """
    Reduces a target/host to a bare, lowercase hostname.

    Strips the URL scheme so 'https://Example.COM/admin' and 'example.com'
    hash identically, drops userinfo (user@host), and removes any explicit
    port (the port is fingerprinted separately via _normalize_port).
    """
    if not host:
        return "unknown"
    text = str(host).strip().lower()
    if text.startswith(("http://", "https://")):
        try:
            parsed = urlparse(text)
            text = parsed.netloc or text
        except ValueError:
            pass
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    if ":" in text:
        text = text.rsplit(":", 1)[0]
    return text or "unknown"


def _normalize_port(port) -> str:
    """Maps any representation of an HTTP(S) port to a single 'web' value."""
    if port is None:
        return "web"
    text = str(port).strip().lower()
    if text.startswith(":"):
        text = text[1:]
    return "web" if text in WEB_PORTS else (text or "web")


def _fingerprint(finding: dict) -> str:
    """Deterministic SHA-1 over the normalized title/host/port."""
    title = _normalize_title(finding.get("title"))
    host = _normalize_host(finding.get("target") or finding.get("host"))
    port = _normalize_port(finding.get("port"))
    canonical = f"{title}|{host}|{port}".encode("utf-8")
    return hashlib.sha1(canonical).hexdigest()


def deduplicate(findings: list) -> list:
    """
    Removes duplicates detected by different tools.

    An issue is identified by a deterministic fingerprint over the
    normalized title/host/port. When two records fingerprint the same,
    the one with the higher severity is retained.
    """
    print(f"    [>] Running deduplication on {len(findings)} raw findings...")

    seen = {}
    for finding in findings:
        fp = _fingerprint(finding)
        current_weight = get_severity_weight(finding.get("severity"))

        existing = seen.get(fp)
        if existing is None or current_weight > get_severity_weight(existing.get("severity")):
            seen[fp] = finding

    deduplicated_list = list(seen.values())
    print(f"        -> Deduplication complete. {len(deduplicated_list)} unique findings retained.")

    return deduplicated_list