"""
Additional tests for modules/ssh_audit.py covering the weak-algorithm
detection added in this session (previously it only confirmed the
script ran, with no real analysis of the results).
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import patch, MagicMock

from modules import ssh_audit


SAMPLE_WEAK_OUTPUT = """
22/tcp open  ssh
| ssh2-enum-algos:
|   kex_algorithms: (2)
|       curve25519-sha256
|       diffie-hellman-group1-sha1
|   server_host_key_algorithms: (2)
|       ssh-ed25519
|       ssh-rsa
|   encryption_algorithms: (2)
|       aes256-ctr
|       arcfour
|   mac_algorithms: (2)
|       hmac-sha2-256
|       hmac-md5
"""

SAMPLE_STRONG_OUTPUT = """
22/tcp open  ssh
| ssh2-enum-algos:
|   kex_algorithms: (1)
|       curve25519-sha256
|   server_host_key_algorithms: (1)
|       ssh-ed25519
|   encryption_algorithms: (1)
|       chacha20-poly1305@openssh.com
|   mac_algorithms: (1)
|       hmac-sha2-256
"""


def _mock_nmap_result(stdout: str):
    result = MagicMock()
    result.stdout = stdout
    return result


def test_parses_weak_kex_algorithm():
    categories = ssh_audit._parse_algorithms_by_category(SAMPLE_WEAK_OUTPUT)
    assert "diffie-hellman-group1-sha1" in categories["kex_algorithms"]


def test_parses_weak_encryption_algorithm():
    categories = ssh_audit._parse_algorithms_by_category(SAMPLE_WEAK_OUTPUT)
    assert "arcfour" in categories["encryption_algorithms"]


def test_run_scan_flags_weak_algorithms():
    with patch("modules.ssh_audit.subprocess.run", return_value=_mock_nmap_result(SAMPLE_WEAK_OUTPUT)):
        results = ssh_audit.run_scan("example.com", port=22)

    titles = [r["title"] for r in results]
    assert any("diffie-hellman-group1-sha1" in t for t in titles)
    assert any("ssh-rsa" in t for t in titles)
    assert any("arcfour" in t for t in titles)
    assert any("hmac-md5" in t for t in titles)
    # All findings should carry raw lowercase severity codes for
    # severity_mapper.normalize() to translate downstream.
    assert all(r["severity"] in ("low", "medium", "info") for r in results)


def test_run_scan_reports_info_when_no_weak_algorithms():
    with patch("modules.ssh_audit.subprocess.run", return_value=_mock_nmap_result(SAMPLE_STRONG_OUTPUT)):
        results = ssh_audit.run_scan("example.com", port=22)

    assert len(results) == 1
    assert results[0]["severity"] == "info"


def test_run_scan_rejects_unsafe_target():
    results = ssh_audit.run_scan("example.com; rm -rf /", port=22)
    assert results == []


def test_run_scan_handles_timeout():
    import subprocess as sp
    with patch("modules.ssh_audit.subprocess.run", side_effect=sp.TimeoutExpired(cmd="nmap", timeout=120)):
        results = ssh_audit.run_scan("example.com", port=22)
    assert results == []
