"""
Tests for modules/report_generator.py
"""
import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.report_generator import safe_filename_from_target, generate_report, generate_sarif, generate_json


def test_safe_filename_strips_scheme():
    assert safe_filename_from_target("http://example.com") == "example.com"
    assert safe_filename_from_target("https://example.com") == "example.com"


def test_safe_filename_replaces_slashes_and_colons():
    result = safe_filename_from_target("http://example.com:8080/path")
    assert "/" not in result
    assert ":" not in result


def test_generate_report_creates_pdf(tmp_path):
    findings = [
        {"title": "Test Finding", "severity": "High", "target": "http://example.com",
         "description": "desc", "remediation": "fix it"},
    ]
    output_dir = str(tmp_path)
    report_path = generate_report(findings, "http://example.com", output_dir, [80, 443])

    assert os.path.exists(report_path)
    assert report_path.endswith(".pdf")
    assert os.path.getsize(report_path) > 0


def test_generate_report_handles_no_findings(tmp_path):
    output_dir = str(tmp_path)
    report_path = generate_report([], "http://example.com", output_dir, [])
    assert os.path.exists(report_path)


def test_generate_report_handles_malformed_finding(tmp_path):
    """A finding missing expected keys shouldn't crash report generation."""
    findings = [{}, {"unexpected_key": "value"}]
    output_dir = str(tmp_path)
    report_path = generate_report(findings, "http://example.com", output_dir, [80])
    assert os.path.exists(report_path)


# --- SARIF tests ---

def test_generate_sarif_writes_valid_json(tmp_path):
    findings = [
        {"title": "XSS", "severity": "High", "description": "reflected", "target": "http://example.com"},
        {"title": "Info Leak", "severity": "Info", "target": "http://example.com"},
    ]
    sarif_path = str(tmp_path / "out.sarif")
    generate_sarif(findings, "http://example.com", sarif_path)
    with open(sarif_path) as f:
        data = json.load(f)
    assert data["version"] == "2.1.0"
    results = data["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "note"


def test_generate_sarif_empty_findings(tmp_path):
    sarif_path = str(tmp_path / "empty.sarif")
    generate_sarif([], "http://example.com", sarif_path)
    with open(sarif_path) as f:
        data = json.load(f)
    assert len(data["runs"][0]["results"]) == 0


# --- JSON export tests ---

def test_generate_json_writes_valid_json(tmp_path):
    findings = [
        {"title": "XSS", "severity": "High", "target": "http://example.com"},
    ]
    json_path = str(tmp_path / "out.json")
    generate_json(findings, "http://example.com", json_path)
    with open(json_path) as f:
        data = json.load(f)
    assert data["target"] == "http://example.com"
    assert data["total_findings"] == 1
    assert data["severity_counts"]["High"] == 1
    assert data["findings"][0]["title"] == "XSS"
