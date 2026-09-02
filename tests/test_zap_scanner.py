"""
Tests for modules/zap_scanner.py

These use unittest.mock to simulate ZAP's API responses, so the tests
run without a real ZAP instance. This lets us test failure paths (bad
scan IDs, error responses, timeouts) that are hard to reliably trigger
against a real ZAP daemon.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import patch, MagicMock
import pytest

from modules.zap_scanner import run_scan, is_zap_ready, ZapScanError, _poll_scan_status


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


def test_is_zap_ready_true_on_200():
    with patch("modules.zap_scanner.requests.get") as mock_get:
        mock_get.return_value = _mock_response({"version": "2.14"})
        assert is_zap_ready("http://localhost:8080") is True


def test_is_zap_ready_false_on_connection_error():
    import requests
    with patch("modules.zap_scanner.requests.get", side_effect=requests.exceptions.ConnectionError):
        assert is_zap_ready("http://localhost:8080") is False


def test_run_scan_skips_when_zap_unreachable():
    with patch("modules.zap_scanner.is_zap_ready", return_value=False):
        result = run_scan("http://example.com")
        assert result == []


def test_poll_scan_status_raises_on_none_scan_id():
    """A scan that never got a real ID should never be treated as valid."""
    with pytest.raises(ZapScanError):
        _poll_scan_status(
            "http://localhost:8080/JSON/spider/view/status/",
            scan_id=None,
            params={},
            headers={},
            label="ZAP Spider",
            poll_interval=0,
            max_wait=1,
        )


def test_poll_scan_status_raises_on_error_response_not_silently_succeeds():
    """
    Regression test for the real bug found in this session: ZAP returning
    an API error (e.g. {"code": "does_not_exist", ...}) with no 'status'
    key was previously defaulted to '100' (done), silently treating a
    failed scan as successful. This must now raise instead.
    """
    error_response = _mock_response({"code": "does_not_exist", "message": "Does Not Exist"})
    with patch("modules.zap_scanner.requests.get", return_value=error_response):
        with pytest.raises(ZapScanError):
            _poll_scan_status(
                "http://localhost:8080/JSON/spider/view/status/",
                scan_id="1",
                params={},
                headers={},
                label="ZAP Spider",
                poll_interval=0,
                max_wait=5,
            )


def test_poll_scan_status_succeeds_on_real_100():
    ok_response = _mock_response({"status": "100"})
    with patch("modules.zap_scanner.requests.get", return_value=ok_response):
        # Should return without raising
        _poll_scan_status(
            "http://localhost:8080/JSON/spider/view/status/",
            scan_id="1",
            params={},
            headers={},
            label="ZAP Spider",
            poll_interval=0,
            max_wait=5,
        )


def test_poll_scan_status_times_out_if_never_completes():
    stuck_response = _mock_response({"status": "42"})
    with patch("modules.zap_scanner.requests.get", return_value=stuck_response):
        with pytest.raises(ZapScanError):
            _poll_scan_status(
                "http://localhost:8080/JSON/spider/view/status/",
                scan_id="1",
                params={},
                headers={},
                label="ZAP Spider",
                poll_interval=0,
                max_wait=0,  # instantly exceeded
            )


def test_run_scan_handles_spider_never_starting():
    """If the spider-start call itself returns no scan ID, run_scan should
    fail gracefully and return an empty list rather than crashing."""
    with patch("modules.zap_scanner.is_zap_ready", return_value=True), \
         patch("modules.zap_scanner.requests.get") as mock_get:
        # spider/action/scan/ returns a body with no 'scan' key
        mock_get.return_value = _mock_response({"code": "some_error"})
        result = run_scan("http://example.com", api_url="http://localhost:8080")
        assert result == []


def test_run_scan_full_happy_path():
    """End-to-end run_scan with every step mocked to succeed."""
    responses_by_call = {
        "/JSON/spider/action/scan/": {"scan": "1"},
        "/JSON/spider/view/status/": {"status": "100"},
        "/JSON/ascan/action/scan/": {"scan": "2"},
        "/JSON/ascan/view/status/": {"status": "100"},
        "/JSON/core/view/alerts/": {"alerts": [
            {"name": "Missing Header", "riskCode": "1", "description": "desc", "solution": "fix it"}
        ]},
    }

    def fake_get(url, params=None, headers=None, timeout=None):
        for path, body in responses_by_call.items():
            if url.endswith(path):
                return _mock_response(body)
        raise AssertionError(f"Unexpected URL called: {url}")

    with patch("modules.zap_scanner.is_zap_ready", return_value=True), \
         patch("modules.zap_scanner.requests.get", side_effect=fake_get):
        result = run_scan("http://example.com", api_url="http://localhost:8080")

    assert len(result) == 1
    assert result[0]["title"] == "Missing Header"
    assert result[0]["severity"] == 1
