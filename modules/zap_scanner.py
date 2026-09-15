import os
import re
import requests
import time


class ZapScanError(Exception):
    """Raised when a ZAP scan step can't proceed (bad scan ID, error response, etc.)."""
    pass


# Poll cadence for each phase. Module-level so tests can patch them to 0
# and avoid real sleeps while still exercising the full request flow.
SPIDER_POLL_INTERVAL = 2
ASCAN_POLL_INTERVAL = 5
AJAX_POLL_INTERVAL = 5


def is_zap_ready(zap_url: str = "http://localhost:8080", timeout: float = 2.0) -> bool:
    """Quick health check to confirm the ZAP daemon is up and responding."""
    try:
        res = requests.get(f"{zap_url}/JSON/core/view/version/", timeout=timeout)
        return res.status_code == 200
    except requests.exceptions.RequestException:
        return False


def wait_for_zap(zap_url: str = "http://localhost:8080", max_wait: int = 30, interval: float = 1.0) -> bool:
    """
    Polls the ZAP daemon until it responds or max_wait seconds elapse.

    Bounds the total wall-clock time, not just the sleep time: each poll
    call is itself blocking for up to `timeout` seconds (and a failed
    connection to localhost can take several seconds on some platforms),
    so counting only `interval` would let the wait overrun max_wait badly.
    Returns True if ZAP became ready, False if it timed out.
    """
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        if is_zap_ready(zap_url):
            return True
        time.sleep(interval)
    return False


def _poll_scan_status(status_url: str, scan_id, params: dict, headers: dict,
                       label: str, poll_interval: float, max_wait: int) -> None:
    """
    Polls a ZAP scan-status endpoint until it reports 100%, or raises
    ZapScanError if the scan ID is invalid, ZAP returns an API error,
    or max_wait is exceeded without reaching completion.
    """
    if scan_id is None:
        raise ZapScanError(f"{label} did not return a scan ID - the scan likely failed to start.")

    waited = 0.0
    status = "0"
    while int(status) < 100:
        if waited >= max_wait:
            raise ZapScanError(f"{label} did not finish within {max_wait}s.")

        time.sleep(poll_interval)
        waited += poll_interval

        r_status = requests.get(status_url, params={**params, 'scanId': scan_id}, headers=headers, timeout=10)
        body = r_status.json()

        # A ZAP API error comes back as {"code": "...", "message": "..."} with
        # no 'status' key. Treat that as a real failure, not "100% done" -
        # silently defaulting to complete here previously masked scans that
        # never actually started.
        if 'status' not in body:
            raise ZapScanError(f"{label} returned an unexpected response: {body}")

        status = body['status']


def _poll_run_status(status_url: str, params: dict, headers: dict,
                     label: str, poll_interval: float, max_wait: int) -> None:
    """
    Polls a ZAP run-status endpoint (ajaxSpider) until it reports 100%.
    Uses the same error handling as _poll_scan_status, but the param is
    called `runId` rather than `scanId`.
    """
    waited = 0.0
    while True:
        if waited >= max_wait:
            raise ZapScanError(f"{label} did not finish within {max_wait}s.")

        time.sleep(poll_interval)
        waited += poll_interval

        r_status = requests.get(status_url, params=params, headers=headers, timeout=10)
        body = r_status.json()

        if 'status' not in body:
            raise ZapScanError(f"{label} returned an unexpected response: {body}")

        try:
            if int(body['status']) >= 100:
                return
        except (TypeError, ValueError):
            raise ZapScanError(f"{label} returned a non-numeric status: {body}")


# --- Context & authentication setup (used when the scan needs to be
# --- authenticated and/or scoped to a specific host). These helpers are
# --- defensive: any failure here is caught by run_scan and degrades the
# --- scan to the unauthenticated, unscoped path with a clear warning.


def _new_context(api_url: str, base_params: dict, headers: dict, context_name: str) -> int:
    """Creates a fresh ZAP context and returns its contextId."""
    url = f"{api_url}/JSON/context/action/newContext/"
    r = requests.get(url, params={**base_params, 'contextName': context_name}, headers=headers, timeout=10)
    r.raise_for_status()
    body = r.json()
    context_id = body.get('contextId')
    if context_id is None:
        raise ZapScanError(f"Could not create ZAP context '{context_name}': {body}")
    return int(context_id)


def _include_target_in_context(target: str, api_url: str, base_params: dict,
                               headers: dict, context_name: str) -> None:
    """Scopes a context to the target host subtree so ZAP stays in scope."""
    match = re.match(r"^(https?://[^/]+)", target)
    host = match.group(1) if match else target
    regex = re.escape(host) + r"($|/.*)"
    url = f"{api_url}/JSON/context/action/includeInContext/"
    r = requests.get(url, params={**base_params, 'contextName': context_name, 'regex': regex},
                     headers=headers, timeout=10)
    r.raise_for_status()


def _setup_form_auth(auth: dict, context_id: int, api_url: str,
                     base_params: dict, headers: dict, user_name: str) -> int:
    """
    Configures form-based authentication and creates the scan user.
    Returns the numeric ZAP userId (what spider/action/scanAsUser and
    ascan/action/scanAsUser expect as their `userId` parameter - NOT the
    username string).
    """
    sm_url = f"{api_url}/JSON/sessionManagement/action/setSessionManagementMethod/"
    r = requests.get(sm_url, params={**base_params, 'contextId': context_id,
                                     'methodName': 'cookieBasedSessionManagement'},
                     headers=headers, timeout=10)
    r.raise_for_status()

    username_field = auth.get('username_field', 'username')
    password_field = auth.get('password_field', 'password')
    login_data = auth.get('login_request_data') or (
        f"{username_field}={{%username%}}&{password_field}={{%password%}}"
    )
    auth_config = f"loginUrl={auth['login_url']}&loginRequestData={login_data}"

    am_url = f"{api_url}/JSON/authentication/action/setAuthenticationMethod/"
    r = requests.get(am_url, params={**base_params, 'contextId': context_id,
                                     'authMethodName': 'formBasedAuthentication',
                                     'authMethodConfigParams': auth_config},
                     headers=headers, timeout=10)
    r.raise_for_status()

    add_url = f"{api_url}/JSON/authentication/action/addUser/"
    r = requests.get(add_url, params={**base_params, 'contextId': context_id,
                                      'name': user_name}, headers=headers, timeout=10)
    r.raise_for_status()
    user_id = r.json().get('userId')
    if user_id is None:
        raise ZapScanError(f"ZAP did not return a userId for '{user_name}': {r.json()}")

    credentials = f"username={auth['username']}&password={auth['password']}"
    creds_url = f"{api_url}/JSON/authentication/action/setUserCredentials/"
    r = requests.get(creds_url, params={**base_params, 'contextId': context_id,
                                        'userId': int(user_id), 'credentials': credentials},
                     headers=headers, timeout=10)
    r.raise_for_status()
    return int(user_id)


def _setup_header_auth(auth: dict, context_id: int, api_url: str,
                       base_params: dict, headers: dict) -> None:
    """Configures HTTP header-based authentication (no per-user needed)."""
    header_name = auth.get('header_name', 'Authorization')
    header_value = auth.get('header_value', '')
    auth_config = f"headerName={header_name}&headerValue={header_value}"

    am_url = f"{api_url}/JSON/authentication/action/setAuthenticationMethod/"
    r = requests.get(am_url, params={**base_params, 'contextId': context_id,
                                     'authMethodName': 'httpHeaderAuthentication',
                                     'authMethodConfigParams': auth_config},
                     headers=headers, timeout=10)
    r.raise_for_status()


def _start_ajax_spider(target: str, api_url: str, base_params: dict,
                       headers: dict, context_name=None, spider_max_wait: int = 300) -> None:
    """Runs ZAP's ajaxSpider (headless browser crawl) and waits for completion."""
    print("        -> Initiating ZAP Ajax Spider (headless browser crawl)...")
    url = f"{api_url}/JSON/ajaxSpider/action/scan/"
    params = {**base_params, 'url': target}
    if context_name:
        params['contextName'] = context_name

    r = requests.get(url, params=params, headers=headers, timeout=10)
    r.raise_for_status()

    _poll_run_status(
        f"{api_url}/JSON/ajaxSpider/view/status/", base_params, headers,
        label="ZAP Ajax Spider", poll_interval=AJAX_POLL_INTERVAL, max_wait=spider_max_wait,
    )
    print("        -> ZAP Ajax Spider finished.")


def _start_spider(target: str, api_url: str, base_params: dict, headers: dict,
                  context_id=None, context_name=None, user_id=None,
                  spider_max_wait: int = 300) -> str:
    """
    Starts the ZAP Spider, waits for 100%, and returns the scan id.

    The standard spider API has no user parameter, so authenticated crawls
    must use spider/action/scanAsUser (contextId + numeric userId). Without a
    user the plain spider runs, scoped to a context when one is given.
    """
    if user_id is not None:
        print("        -> Initiating ZAP Spider as authenticated user...")
        url = f"{api_url}/JSON/spider/action/scanAsUser/"
        params = {**base_params, 'url': target, 'contextId': int(context_id), 'userId': int(user_id)}
    else:
        print("        -> Initiating ZAP Spider...")
        url = f"{api_url}/JSON/spider/action/scan/"
        params = {**base_params, 'url': target}
        if context_id is not None and context_name:
            params['contextName'] = context_name

    r_spider = requests.get(url, params=params, headers=headers, timeout=10)
    r_spider.raise_for_status()
    spider_body = r_spider.json()
    scan_id = spider_body.get('scan')
    if scan_id is None:
        raise ZapScanError(f"ZAP Spider did not start: {spider_body}")

    _poll_scan_status(
        f"{api_url}/JSON/spider/view/status/", scan_id, base_params, headers,
        label="ZAP Spider", poll_interval=SPIDER_POLL_INTERVAL, max_wait=spider_max_wait,
    )
    return scan_id


def _start_ascan(target: str, api_url: str, base_params: dict, headers: dict,
                 context_id=None, user_id=None, ascan_max_wait: int = 900) -> str:
    """Starts the ZAP Active Scan, waits for 100%, and returns the scan id.

    As of ZAP 2.17 the plain ascan/action/scan no longer accepts a `user`
    param - an authenticated scan must use ascan/action/scanAsUser
    (contextId + numeric userId), otherwise it silently runs
    unauthenticated. Without a user the plain scan runs, scoped to a
    context when one is given."""
    if user_id is not None:
        print("        -> Initiating ZAP Active Scan as authenticated user...")
        url = f"{api_url}/JSON/ascan/action/scanAsUser/"
        params = {**base_params, 'url': target, 'contextId': int(context_id), 'userId': int(user_id)}
    else:
        print("        -> Initiating ZAP Active Scan...")
        url = f"{api_url}/JSON/ascan/action/scan/"
        params = {**base_params, 'url': target}
        if context_id is not None:
            params['contextId'] = int(context_id)

    r_ascan = requests.get(url, params=params, headers=headers, timeout=10)
    r_ascan.raise_for_status()
    ascan_body = r_ascan.json()
    ascan_id = ascan_body.get('scan')
    if ascan_id is None:
        raise ZapScanError(f"ZAP Active Scan did not start: {ascan_body}")

    _poll_scan_status(
        f"{api_url}/JSON/ascan/view/status/", ascan_id, base_params, headers,
        label="ZAP Active Scan", poll_interval=ASCAN_POLL_INTERVAL, max_wait=ascan_max_wait,
    )
    return ascan_id


def run_scan(target: str, api_url: str = 'http://localhost:8080', api_key: str = '',
             spider_max_wait: int = 300, ascan_max_wait: int = 900,
             auth: dict = None, ajax_spider: bool = False, context_name: str = None) -> list:
    """
    Triggers an OWASP ZAP scan via its REST API and returns normalized findings.

    Args:
        target: URL to scan.
        api_url / api_key: ZAP daemon API location and optional API key.
        auth: optional dict describing authentication:
            {"method": "form", "login_url": ..., "username_field": ..., "password_field": ...,
             "username": ..., "password": ..., "login_request_data": ...}
          or {"method": "header", "header_name": ..., "header_value": ...}
          or {"method": "none"} (default).
        ajax_spider: also run ZAP's ajaxSpider (headless-browser crawl) before active scanning.
        context_name: name for the ZAP context created to scope the scan.
    """
    print(f"    [>] Triggering OWASP ZAP API against {target}")
    findings = []

    # Clean up the URL just in case there's a trailing slash in the config
    if api_url.endswith('/'):
        api_url = api_url[:-1]

    if not is_zap_ready(api_url):
        print(f"    [!] ZAP daemon unreachable at {api_url} - skipping ZAP phase.")
        return []

    # ZAP requires the API key to be passed as a param (or header) when auth is enabled.
    # We disable the API key via config (api.disablekey=true), but pass it through
    # anyway so this still works if a user re-enables key auth.
    base_params = {}
    if api_key:
        base_params['apikey'] = api_key

    headers = {'Accept': 'application/json'}

    # --- Optional: authenticated + scoped scanning ---
    context_id = None
    user_id = None
    auth_method = (auth or {}).get('method', 'none')
    if auth_method in ('form', 'header'):
        ctx_name = context_name or f"strikehound-{int(time.time())}"
        try:
            context_id = _new_context(api_url, base_params, headers, ctx_name)
            _include_target_in_context(target, api_url, base_params, headers, ctx_name)

            if auth_method == 'form':
                user_id = _setup_form_auth(
                    auth, context_id, api_url, base_params, headers, user_name=f"sh-user-{int(time.time())}"
                )
            else:
                _setup_header_auth(auth, context_id, api_url, base_params, headers)

            print(f"    [+] ZAP context '{ctx_name}' configured (auth: {auth_method}).")
        except requests.exceptions.RequestException as e:
            print(f"    [!] ZAP API reached but context/auth setup failed ({e}).")
            print("        Continuing unauthenticated - authenticated findings will be missing.")
        except ZapScanError as e:
            print(f"    [!] ZAP context/auth setup failed: {e}")
            print("        Continuing unauthenticated - authenticated findings will be missing.")
        except Exception as e:
            print(f"    [!] Unexpected ZAP context/auth setup error: {e}")
            print("        Continuing unauthenticated - authenticated findings will be missing.")
            context_id = None
            user_id = None
    elif auth_method != 'none':
        print(f"    [!] Unknown ZAP auth method '{auth_method}' - ignoring auth config.")
        auth_method = 'none'

    try:
        # Step 1: Start the ZAP Spider (as the context user when authenticated).
        _start_spider(
            target, api_url, base_params, headers,
            context_id=context_id, context_name=ctx_name if context_id else None,
            user_id=user_id, spider_max_wait=spider_max_wait,
        )

        # Step 1.5: Optionally crawl with the headless-browser ajaxSpider too.
        if ajax_spider:
            _start_ajax_spider(target, api_url, base_params, headers,
                               context_name=ctx_name if context_id else None,
                               spider_max_wait=spider_max_wait)

        # Step 2: Start the ZAP Active Scan (authenticated if a user was set up).
        _start_ascan(target, api_url, base_params, headers,
                     context_id=context_id, user_id=user_id, ascan_max_wait=ascan_max_wait)

        # Step 3: Fetch the security alerts (vulnerabilities)
        print("        -> Fetching vulnerabilities from ZAP...")
        alerts_url = f"{api_url}/JSON/core/view/alerts/"
        r_alerts = requests.get(alerts_url, params={**base_params, 'baseurl': target}, headers=headers, timeout=10)
        alerts = r_alerts.json().get('alerts', [])

        # Step 4: Normalize the raw ZAP data into the StrikeHound format
        scheme_port = 443 if str(target).lower().startswith("https") else 80
        for alert in alerts:
            try:
                risk_code = int(alert.get('riskCode', 0))
            except (TypeError, ValueError):
                risk_code = 0
            findings.append({
                "tool": "zap",
                "title": alert.get('name'),
                "severity": risk_code,
                "target": alert.get('url') or target,
                "port": scheme_port,
                "description": alert.get('description'),
                "remediation": alert.get('solution', 'No remediation provided by ZAP.'),
                "confidence": alert.get('confidence'),
                "url": alert.get('url'),
                "evidence": alert.get('evidence'),
                "cwe_id": alert.get('cweid'),
                "wasc_id": alert.get('wascid'),
            })

        print(f"        -> ZAP API finished: Downloaded {len(findings)} live issues.")

    except ZapScanError as e:
        print(f"    [!] ZAP scan aborted: {e}")
    except requests.exceptions.ConnectionError:
        print(f"    [!] ZAP API Error: Could not connect to {api_url}.")
        print("        Ensure the OWASP ZAP application is actually running on your machine.")
    except Exception as e:
        print(f"    [!] ZAP API execution error: {e}")

    return findings