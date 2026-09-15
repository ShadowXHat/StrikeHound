"""
Tests for strikehound.py CLI helpers.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from strikehound import worst_finding_severity, clean_target_for_nmap, FAIL_SEVERITY_WEIGHTS


def test_clean_target_for_nmap_strips_scheme():
    assert clean_target_for_nmap("http://example.com") == "example.com"
    assert clean_target_for_nmap("https://example.com:8080/path") == "example.com:8080"


def test_clean_target_for_nmap_keeps_bare_host():
    assert clean_target_for_nmap("192.168.1.1") == "192.168.1.1"


def test_worst_finding_severity_empty():
    assert worst_finding_severity([]) == "info"


def test_worst_finding_severity_returns_worst():
    findings = [
        {"severity": "Low"},
        {"severity": "critical"},
        {"severity": "MediUm"},
    ]
    assert worst_finding_severity(findings) == "critical"


def test_worst_finding_severity_ignores_unknown():
    findings = [{"severity": "apocalyptic"}, {"severity": "high"}]
    assert worst_finding_severity(findings) == "high"


def test_fail_severity_thresholds_ordered():
    assert FAIL_SEVERITY_WEIGHTS["critical"] > FAIL_SEVERITY_WEIGHTS["high"]
    assert FAIL_SEVERITY_WEIGHTS["high"] > FAIL_SEVERITY_WEIGHTS["medium"]
    assert FAIL_SEVERITY_WEIGHTS["medium"] > FAIL_SEVERITY_WEIGHTS["low"]
    assert FAIL_SEVERITY_WEIGHTS["low"] > FAIL_SEVERITY_WEIGHTS["info"]