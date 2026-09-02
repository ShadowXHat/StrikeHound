"""
Tests for modules/deduplicator.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.deduplicator import deduplicate, get_severity_weight


def test_severity_weight_ordering():
    assert get_severity_weight("Critical") > get_severity_weight("High")
    assert get_severity_weight("High") > get_severity_weight("Medium")
    assert get_severity_weight("Medium") > get_severity_weight("Low")
    assert get_severity_weight("Low") > get_severity_weight("Info")


def test_severity_weight_unknown_defaults_to_zero():
    assert get_severity_weight("NotARealSeverity") == 0


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
    # Neither entry crashes the function; both fall back to "Unknown"
    # defaults for missing fields, and since their titles differ they're
    # correctly treated as two distinct findings.
    assert len(result) == 2


def test_deduplicate_two_fully_empty_findings_merge():
    findings = [{}, {}]
    result = deduplicate(findings)
    # Both have identical (Unknown/Unknown/web) fallback keys, so they merge.
    assert len(result) == 1
