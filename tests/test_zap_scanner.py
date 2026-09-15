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

from modules.zap_scanner import (
    run_scan, is_zap_ready, wait_for_zap, ZapScanError,
    _poll_scan_status, _poll_run_status, _new_context,
)


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


def test_wait_for_zap_bounds_wall_clock_not_sleep_time():
    """
    Regression: wait_for_zap previously summed `interval` sleep time, so
    when each poll call itself blocked for several seconds (slow
    connection failure on localhost), the total wait overran max_wait
    badly. It must now respect the wall-clock deadline.
    """
    import time

    def slow_poll(*args, **kwargs):
        time.sleep(0.2)  # blocking poll longer than the 0.05s interval
        return False

    with patch("modules.zap_scanner.is_zap_ready", side_effect=slow_poll):
        start = time.monotonic()
        ok = wait_for_zap("http://localhost:8080", max_wait=0.5, interval=0.05)
        elapsed = time.monotonic() - start

    assert ok is False
    # Polls block for 0.2s each; if we only counted sleep the loop would
    # run several more cycles and take far longer. Wall-clock timing bounds it.
    assert elapsed < 1.2


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


# --- Authenticated + scoped scanning -------------------------------------


def test_run_scan_with_form_auth_configures_context_and_user():
    """Form auth must create a context, wire up the login, and pass the
    context user into the active scan."""
    responses_by_call = {
        "/JSON/context/action/newContext/": {"contextId": "5"},
        "/JSON/context/action/includeInContext/": {},
        "/JSON/sessionManagement/action/setSessionManagementMethod/": {},
        "/JSON/authentication/action/setAuthenticationMethod/": {},
        "/JSON/authentication/action/addUser/": {"userId": "12"},
        "/JSON/authentication/action/setUserCredentials/": {},
        "/JSON/spider/action/scanAsUser/": {"scan": "1"},
        "/JSON/spider/view/status/": {"status": "100"},
        "/JSON/ascan/action/scanAsUser/": {"scan": "2"},
        "/JSON/ascan/view/status/": {"status": "100"},
        "/JSON/core/view/alerts/": {"alerts": [
            {"name": "SQLi", "riskCode": "2", "description": "d", "solution": "use params"}
        ]},
    }
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        for path, body in responses_by_call.items():
            if url.endswith(path):
                return _mock_response(body)
        raise AssertionError(f"Unexpected URL called: {url}")

    auth = {
        "method": "form",
        "login_url": "http://example.com/login",
        "username_field": "user",
        "password_field": "pass",
        "username": "alice",
        "password": "s3cret",
    }
    with patch("modules.zap_scanner.is_zap_ready", return_value=True), \
         patch("modules.zap_scanner.requests.get", side_effect=fake_get), \
         patch("modules.zap_scanner.SPIDER_POLL_INTERVAL", 0), \
         patch("modules.zap_scanner.ASCAN_POLL_INTERVAL", 0):
        result = run_scan("http://example.com", api_url="http://localhost:8080", auth=auth)

    assert len(result) == 1

    ascan_calls = [p for u, p in calls if u.endswith("/JSON/ascan/action/scanAsUser/")]
    assert len(ascan_calls) == 1
    assert ascan_calls[0]["contextId"] == 5
    # ZAP 2.17's ascan/scanAsUser takes the numeric userId, not a username.
    assert ascan_calls[0]["userId"] == 12
    # The plain scan must NOT be used when authenticating - it has no user param.
    assert not any(u.endswith("/JSON/ascan/action/scan/") for u, _ in calls)

    # Authenticated crawling must go through spider/action/scanAsUser, and the
    # plain spider must NOT run (it cannot authenticate).
    spider_as_user = [p for u, p in calls if u.endswith("/JSON/spider/action/scanAsUser/")]
    assert len(spider_as_user) == 1
    assert spider_as_user[0]["contextId"] == 5
    assert spider_as_user[0]["userId"] == 12
    assert not any(u.endswith("/JSON/spider/action/scan/") for u, _ in calls)

    cred_calls = [p for u, p in calls if u.endswith("/JSON/authentication/action/setUserCredentials/")]
    assert len(cred_calls) == 1
    assert "username=alice" in cred_calls[0]["credentials"]
    assert "password=s3cret" in cred_calls[0]["credentials"]


def test_run_scan_header_auth_uses_context_without_user():
    """Header auth needs no ZAP user; it still scopes the scan to a context."""
    responses_by_call = {
        "/JSON/context/action/newContext/": {"contextId": "3"},
        "/JSON/context/action/includeInContext/": {},
        "/JSON/authentication/action/setAuthenticationMethod/": {},
        "/JSON/spider/action/scan/": {"scan": "1"},
        "/JSON/spider/view/status/": {"status": "100"},
        "/JSON/ascan/action/scan/": {"scan": "2"},
        "/JSON/ascan/view/status/": {"status": "100"},
        "/JSON/core/view/alerts/": {"alerts": []},
    }
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        for path, body in responses_by_call.items():
            if url.endswith(path):
                return _mock_response(body)
        raise AssertionError(f"Unexpected URL called: {url}")

    auth = {"method": "header", "header_name": "Authorization", "header_value": "Bearer tok"}
    with patch("modules.zap_scanner.is_zap_ready", return_value=True), \
         patch("modules.zap_scanner.requests.get", side_effect=fake_get), \
         patch("modules.zap_scanner.SPIDER_POLL_INTERVAL", 0), \
         patch("modules.zap_scanner.ASCAN_POLL_INTERVAL", 0):
        result = run_scan("http://example.com", api_url="http://localhost:8080", auth=auth)

    assert result == []

    ascan_calls = [p for u, p in calls if u.endswith("/JSON/ascan/action/scan/")]
    assert len(ascan_calls) == 1
    assert ascan_calls[0]["contextId"] == 3
    assert "user" not in ascan_calls[0]
    assert not any(u.endswith("/JSON/ascan/action/scanAsUser/") for u, _ in calls)

    # Header auth has no user: the plain (context-scoped) spider runs.
    spider_calls = [(u, p) for u, p in calls if u.endswith("/JSON/spider/action/scan/")]
    assert len(spider_calls) == 1
    assert "contextName" in spider_calls[0][1]
    assert not any(u.endswith("/JSON/spider/action/scanAsUser/") for u, _ in calls)

    am_calls = [p for u, p in calls if u.endswith("/JSON/authentication/action/setAuthenticationMethod/")]
    assert len(am_calls) == 1
    assert am_calls[0]["authMethodName"] == "httpHeaderAuthentication"


def test_run_scan_form_auth_degrades_when_context_api_fails():
    """If ZAP refuses to create a context, the scan must still run
    unauthenticated rather than dying - just without authed findings."""
    responses_by_call = {
        "/JSON/spider/action/scan/": {"scan": "1"},
        "/JSON/spider/view/status/": {"status": "100"},
        "/JSON/ascan/action/scan/": {"scan": "2"},
        "/JSON/ascan/view/status/": {"status": "100"},
        "/JSON/core/view/alerts/": {"alerts": [
            {"name": "Old Finding", "riskCode": "1", "description": "d", "solution": "s"}
        ]},
    }
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        for path, body in responses_by_call.items():
            if url.endswith(path):
                return _mock_response(body)
        raise AssertionError(f"Unexpected URL called: {url}")

    auth = {"method": "form", "login_url": "http://example.com/login",
            "username": "alice", "password": "s3cret"}
    with patch("modules.zap_scanner.is_zap_ready", return_value=True), \
         patch("modules.zap_scanner.requests.get", side_effect=fake_get), \
         patch("modules.zap_scanner.SPIDER_POLL_INTERVAL", 0), \
         patch("modules.zap_scanner.ASCAN_POLL_INTERVAL", 0):
        result = run_scan("http://example.com", api_url="http://localhost:8080", auth=auth)

    # newContext gets no contextId -> ZapScanError -> authenticated parts skipped.
    urls_hit = [u for u, _ in calls]
    assert any(u.endswith("/JSON/context/action/newContext/") for u in urls_hit)
    assert not any("/JSON/authentication" in u for u in urls_hit)
    assert not any("/JSON/sessionManagement" in u for u in urls_hit)
    # The unauthenticated scan still completes and finds the old issue.
    assert len(result) == 1
    assert result[0]["title"] == "Old Finding"


def test_run_scan_with_ajax_spider_runs_ajax_phase():
    """ajax_spider=True must add an ajaxSpider crawl between spider and ascan."""
    responses_by_call = {
        "/JSON/spider/action/scan/": {"scan": "1"},
        "/JSON/spider/view/status/": {"status": "100"},
        "/JSON/ajaxSpider/action/scan/": {},
        "/JSON/ajaxSpider/view/status/": {"status": "100"},
        "/JSON/ascan/action/scan/": {"scan": "2"},
        "/JSON/ascan/view/status/": {"status": "100"},
        "/JSON/core/view/alerts/": {"alerts": []},
    }
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        for path, body in responses_by_call.items():
            if url.endswith(path):
                return _mock_response(body)
        raise AssertionError(f"Unexpected URL called: {url}")

    with patch("modules.zap_scanner.is_zap_ready", return_value=True), \
         patch("modules.zap_scanner.requests.get", side_effect=fake_get), \
         patch("modules.zap_scanner.SPIDER_POLL_INTERVAL", 0), \
         patch("modules.zap_scanner.ASCAN_POLL_INTERVAL", 0), \
         patch("modules.zap_scanner.AJAX_POLL_INTERVAL", 0):
        result = run_scan("http://example.com", api_url="http://localhost:8080", ajax_spider=True)

    assert result == []
    urls_hit = [u for u, _ in calls]
    assert any(u.endswith("/JSON/ajaxSpider/action/scan/") for u in urls_hit)
    assert any(u.endswith("/JSON/ajaxSpider/view/status/") for u in urls_hit)


def test_poll_run_status_raises_on_error_response():
    """The ajaxSpider poller must not treat API errors as completion."""
    with patch("modules.zap_scanner.requests.get",
               return_value=_mock_response({"code": "does_not_exist"})):
        with pytest.raises(ZapScanError):
            _poll_run_status(
                "http://localhost:8080/JSON/ajaxSpider/view/status/",
                {}, {}, label="ZAP Ajax Spider", poll_interval=0, max_wait=5,
            )


def test_new_context_raises_when_no_context_id():
    with patch("modules.zap_scanner.requests.get",
               return_value=_mock_response({"code": "some_error"})):
        with pytest.raises(ZapScanError):
            _new_context("http://localhost:8080", {}, {}, "ctx-name")
