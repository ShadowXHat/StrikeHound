"""
Tests for modules/deduplicator.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.deduplicator import (
    deduplicate,
    get_severity_weight,
    _fingerprint,
    _normalize_title,
    _normalize_host,
    _normalize_port,
)


# --- Severity weight ordering ---

def test_severity_weight_ordering():
    assert get_severity_weight("Critical") > get_severity_weight("High")
    assert get_severity_weight("High") > get_severity_weight("Medium")
    assert get_severity_weight("Medium") > get_severity_weight("Low")
    assert get_severity_weight("Low") > get_severity_weight("Info")


def test_severity_weight_unknown_defaults_to_zero():
    assert get_severity_weight("NotARealSeverity") == 0


def test_severity_weight_case_insensitive():
    assert get_severity_weight("critical") == get_severity_weight("Critical")
    assert get_severity_weight("HIGH") == get_severity_weight("High")


def test_severity_weight_none_returns_zero():
    assert get_severity_weight(None) == 0


# --- Deterministic fingerprinting ---

def test_fingerprint_is_deterministic():
    finding = {"title": "XSS", "target": "example.com", "port": 80}
    assert _fingerprint(finding) == _fingerprint(finding)


def test_fingerprint_differs_on_different_title():
    a = _fingerprint({"title": "XSS", "target": "example.com"})
    b = _fingerprint({"title": "SQLi", "target": "example.com"})
    assert a != b


# --- Normalization helpers ---

def test_normalize_title_collapses_whitespace():
    assert _normalize_title("  SQL  Injection  ") == "sql injection"


def test_normalize_host_strips_scheme_and_port():
    assert _normalize_host("https://Example.com:8443/path") == "example.com"


def test_normalize_port_maps_http_to_web():
    assert _normalize_port(80) == "web"
    assert _normalize_port(443) == "web"
    assert _normalize_port("80") == "web"


def test_normalize_port_preserves_non_http():
    assert _normalize_port(22) == "22"
    assert _normalize_port(8080) == "8080"


def test_normalize_port_none_defaults_to_web():
    assert _normalize_port(None) == "web"


# --- Cross-tool deduplication (key regression) ---

def test_deduplicate_cross_tool_port_mismatch():
    """
    Core regression: Nuclei has no 'port' key (defaults to 'web'), ZAP
    hardcodes port 80. Before the fix these were two distinct findings
    that never merged. Both must now deduplicate to one record.
    """
    nuclei_finding = {
        "tool": "nuclei",
        "title": "Cross-Site Scripting",
        "target": "http://example.com",
        "severity": "Medium",
    }
    zap_finding = {
        "tool": "zap",
        "title": "Cross-Site Scripting",
        "target": "http://example.com",
        "port": 80,
        "severity": "High",
    }
    result = deduplicate([nuclei_finding, zap_finding])
    assert len(result) == 1
    assert result[0]["tool"] == "zap"          # higher severity wins
    assert result[0]["severity"] == "High"


def test_deduplicate_title_case_insensitive():
    findings = [
        {"title": "SQL Injection", "target": "example.com", "port": 80, "severity": "High"},
        {"title": "SQL INJECTION", "target": "Example.COM", "port": 80, "severity": "Critical"},
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0]["severity"] == "Critical"


# --- Original suite (preserved) ---

def test_deduplicate_removes_exact_duplicates():
    findings = [
        {"title": "XSS", "target": "example.com", "port": 80, "severity": "High"},
        {"title": "XSS", "target": "example.com", "port": 80, "severity": "High"},
    ]
    result = deduplicate(findings)
    assert len(result) == 1


def test_deduplicate_keeps_distinct_findings():
    findings = [
        {"title": "XSS", "target": "example.com", "port": 80, "severity": "High"},
        {"title": "SQLi", "target": "example.com", "port": 80, "severity": "Critical"},
    ]
    result = deduplicate(findings)
    assert len(result) == 2


def test_deduplicate_prefers_higher_severity_on_conflict():
    findings = [
        {"title": "XSS", "target": "example.com", "port": 80, "severity": "Low"},
        {"title": "XSS", "target": "example.com", "port": 80, "severity": "Critical"},
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0]["severity"] == "Critical"


def test_deduplicate_empty_list():
    assert deduplicate([]) == []


def test_deduplicate_missing_fields_does_not_crash():
    findings = [{}, {"title": "Something"}]
    result = deduplicate(findings)
    # Neither entry crashes the function; both fall back to defaults, and
    # since their titles differ they're correctly treated as two findings.
    assert len(result) == 2


def test_deduplicate_two_fully_empty_findings_merge():
    findings = [{}, {}]
    result = deduplicate(findings)
    assert len(result) == 1
