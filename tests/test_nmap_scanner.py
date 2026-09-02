"""
Tests for modules/nmap_scanner.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import nmap_scanner


def test_run_scan_rejects_unsafe_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    results = nmap_scanner.run_scan("example.com; rm -rf /", "-F -T4")
    assert results == {}
