"""
Basic validation for user-supplied scan targets before they're passed
into subprocess calls (nmap, nuclei, ssh_audit) or used to build URLs.

This is not a full RFC-compliant hostname/URL parser — it's a defensive
sanity check to reject obviously malformed or suspicious input before
it reaches external tools.
"""
import re
from urllib.parse import urlparse

# Allows: hostnames, FQDNs, IPv4, IPv6 (bracketed), with optional port.
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$"
)
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Characters that have no business being in a hostname/IP and could be
# used to smuggle extra flags/arguments into a downstream tool.
_SUSPICIOUS_CHARS = set(" \t\n;|&$`<>(){}\\\"'")


def is_safe_target(raw_target: str) -> bool:
    """
    Returns True if raw_target looks like a plain hostname, IP, or URL
    with no shell-metacharacters or embedded flags.
    """
    if not raw_target or len(raw_target) > 253:
        return False

    if any(c in _SUSPICIOUS_CHARS for c in raw_target):
        return False

    # Reject anything that looks like a CLI flag (e.g. "--script=...")
    if raw_target.startswith("-"):
        return False

    candidate = raw_target
    if raw_target.startswith(("http://", "https://")):
        parsed = urlparse(raw_target)
        if not parsed.netloc:
            return False
        candidate = parsed.netloc.split(":")[0].strip("[]")

    if _IPV4_RE.match(candidate):
        return True

    if _HOSTNAME_RE.match(candidate):
        return True

    # Basic IPv6 sanity check (not exhaustive)
    if ":" in candidate and all(
        part == "" or re.match(r"^[0-9a-fA-F]{1,4}$", part)
        for part in candidate.split(":")
    ):
        return True

    return False
