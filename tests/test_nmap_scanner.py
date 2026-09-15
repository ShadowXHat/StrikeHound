"""
Tests for modules/nmap_scanner.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import patch

from modules import nmap_scanner


def test_run_scan_rejects_unsafe_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    results = nmap_scanner.run_scan("example.com; rm -rf /", "-F -T4")
    assert results == {}


def test_run_scan_missing_nmap_binary_degrades_gracefully(tmp_path, monkeypatch):
    """
    Regression: nmap.PortScanner() raises PortScannerError at construction
    when the nmap binary is not installed. It used to be instantiated
    outside the try/except, so a machine without nmap crashed the whole
    pipeline instead of returning no ports.
    """
    import nmap as nmap_lib
    monkeypatch.chdir(tmp_path)
    with patch.object(nmap_lib, "PortScanner", side_effect=nmap_lib.PortScannerError("not found")):
        results = nmap_scanner.run_scan("example.com", "-F -T4")
    assert results == {}


def test_run_scan_parses_open_ports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    class FakeProto:
        def __init__(self, ports):
            self.ports = ports

        def keys(self):
            return self.ports.keys()

        def __getitem__(self, port):
            return self.ports[port]

    class FakeHost:
        def __init__(self):
            self.tcp = {22: {"state": "open", "name": "ssh", "version": "OpenSSH 8.9"},
                        80: {"state": "closed", "name": "http", "version": ""}}

        def all_protocols(self):
            return ["tcp"]

        def __getitem__(self, proto):
            return FakeProto(self.tcp)

    class FakePortScanner:
        def __init__(self):
            pass

        def scan(self, hosts, arguments):
            pass

        def all_hosts(self):
            return ["1.2.3.4"]

        def __getitem__(self, host):
            return FakeHost()

        def get_nmap_last_output(self):
            return b"<xml/>"

    with patch.object(nmap_scanner.nmap, "PortScanner", FakePortScanner):
        results = nmap_scanner.run_scan("1.2.3.4", "-F -T4")

    assert results == {22: {"state": "open", "service": "ssh", "version": "OpenSSH 8.9"}}
    assert 80 not in results  # only open ports are reported
    assert os.path.exists(os.path.join("output", "nmap_result.xml"))