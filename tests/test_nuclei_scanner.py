"""
Tests for modules/nuclei_scanner.py
"""
import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import patch, MagicMock
import tempfile

from modules import nuclei_scanner


def test_run_scan_parses_jsonl_output(tmp_path, monkeypatch):
    # Run inside a temp dir so nuclei_scanner's hardcoded "output/" path
    # doesn't touch the real project directory.
    monkeypatch.chdir(tmp_path)
    os.makedirs("output", exist_ok=True)

    sample_line = json.dumps({
        "info": {"name": "Exposed .git directory", "severity": "medium", "description": "desc"},
        "host": "http://example.com",
    })
    with open("output/nuclei_result.jsonl", "w") as f:
        f.write(sample_line + "\n")

    with patch("modules.nuclei_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        results = nuclei_scanner.run_scan("http://example.com", nuclei_path="nuclei")

    assert len(results) == 1
    assert results[0]["title"] == "Exposed .git directory"
    assert results[0]["severity"] == "medium"
    assert results[0]["tool"] == "nuclei"


def test_run_scan_missing_binary_returns_empty(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("modules.nuclei_scanner.subprocess.run", side_effect=FileNotFoundError):
        results = nuclei_scanner.run_scan("http://example.com", nuclei_path="/nonexistent/nuclei")
    assert results == []


def test_run_scan_no_output_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("modules.nuclei_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        results = nuclei_scanner.run_scan("http://example.com", nuclei_path="nuclei")
    assert results == []
