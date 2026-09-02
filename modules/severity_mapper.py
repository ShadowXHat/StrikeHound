"""
Normalizes tool-specific severity ratings into a standard scale
(Critical, High, Medium, Low, Info).

NOTE: This module no longer loads config.yaml itself. The severity_map
must be passed in explicitly (loaded once by strikehound.py) to avoid
re-reading and re-parsing the config file for every single finding.
"""


def normalize(tool_name: str, raw_severity, severity_map: dict) -> str:
    """
    Normalizes a tool-specific severity into a standard string.

    Args:
        tool_name: e.g. "nuclei", "zap", "ssh_audit"
        raw_severity: the tool's native severity value (str or int)
        severity_map: the 'severity_map' section of config.yaml,
                       loaded once and passed in by the caller.
    """
    if tool_name not in severity_map:
        return "Info"

    tool_map = severity_map[tool_name]

    # Handle integer-based severities (ZAP) vs string-based (Nuclei, ssh_audit)
    if isinstance(raw_severity, str):
        raw_severity = raw_severity.lower()

    return tool_map.get(raw_severity, "Info")
