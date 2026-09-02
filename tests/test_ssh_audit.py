"""
Tests for modules/ssh_audit.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import patch, MagicMock

from modules import ssh_audit


def test_run_scan_reports_finding_on_successful_script():
    fake_result = MagicMock()
    fake_result.stdout = "PORT   STATE SERVICE\n22/tcp open  ssh\n| ssh2-enum-algos:\n"
    with patch("modules.ssh_audit.subprocess.run", return_value=fake_result):
        results = ssh_audit.run_scan("example.com", port=22)
    assert len(results) == 1
    assert results[0]["tool"] == "ssh_audit"
    assert results[0]["port"] == 22


def test_run_scan_no_output_returns_no_findings():
    fake_result = MagicMock()
    fake_result.stdout = ""
    with patch("modules.ssh_audit.subprocess.run", return_value=fake_result):
        results = ssh_audit.run_scan("example.com", port=22)
    assert results == []


def test_run_scan_handles_execution_error_gracefully():
    with patch("modules.ssh_audit.subprocess.run", side_effect=Exception("nmap crashed")):
        results = ssh_audit.run_scan("example.com", port=22)
    assert results == []
