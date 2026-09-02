"""
Tests for modules/report_generator.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.report_generator import safe_filename_from_target, generate_report


def test_safe_filename_strips_scheme():
    assert safe_filename_from_target("http://example.com") == "example.com"
    assert safe_filename_from_target("https://example.com") == "example.com"


def test_safe_filename_replaces_slashes_and_colons():
    result = safe_filename_from_target("http://example.com:8080/path")
    assert "/" not in result
    assert ":" not in result


def test_generate_report_creates_pdf(tmp_path):
    findings = [
        {"title": "Test Finding", "severity": "High", "target": "http://example.com"},
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
