import requests
import time


class ZapScanError(Exception):
    """Raised when a ZAP scan step can't proceed (bad scan ID, error response, etc.)."""
    pass


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
    Returns True if ZAP became ready, False if it timed out.
    """
    waited = 0.0
    while waited < max_wait:
        if is_zap_ready(zap_url):
            return True
        time.sleep(interval)
        waited += interval
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


def run_scan(target: str, api_url: str = 'http://localhost:8080', api_key: str = '',
             spider_max_wait: int = 300, ascan_max_wait: int = 900) -> list:
    """Triggers an OWASP ZAP scan via its REST API and returns normalized findings."""
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

    try:
        # Step 1: Start the ZAP Spider
        print("        -> Initiating ZAP Spider...")
        spider_url = f"{api_url}/JSON/spider/action/scan/"
        r_spider = requests.get(spider_url, params={**base_params, 'url': target}, headers=headers, timeout=10)
        r_spider.raise_for_status()
        spider_body = r_spider.json()
        scan_id = spider_body.get('scan')

        if scan_id is None:
            raise ZapScanError(f"ZAP Spider did not start: {spider_body}")

        # Step 2: Poll the API until the Spider reaches 100%
        _poll_scan_status(
            f"{api_url}/JSON/spider/view/status/", scan_id, base_params, headers,
            label="ZAP Spider", poll_interval=2, max_wait=spider_max_wait,
        )

        # Step 3: Start the ZAP Active Scan
        print("        -> Initiating ZAP Active Scan...")
        ascan_url = f"{api_url}/JSON/ascan/action/scan/"
        r_ascan = requests.get(ascan_url, params={**base_params, 'url': target}, headers=headers, timeout=10)
        r_ascan.raise_for_status()
        ascan_body = r_ascan.json()
        ascan_id = ascan_body.get('scan')

        if ascan_id is None:
            raise ZapScanError(f"ZAP Active Scan did not start: {ascan_body}")

        _poll_scan_status(
            f"{api_url}/JSON/ascan/view/status/", ascan_id, base_params, headers,
            label="ZAP Active Scan", poll_interval=5, max_wait=ascan_max_wait,
        )

        # Step 4: Fetch the security alerts (vulnerabilities)
        print("        -> Fetching vulnerabilities from ZAP...")
        alerts_url = f"{api_url}/JSON/core/view/alerts/"
        r_alerts = requests.get(alerts_url, params={**base_params, 'baseurl': target}, headers=headers, timeout=10)
        alerts = r_alerts.json().get('alerts', [])

        # Step 5: Normalize the raw ZAP data into the StrikeHound format
        for alert in alerts:
            try:
                risk_code = int(alert.get('riskCode', 0))
            except (TypeError, ValueError):
                risk_code = 0
            findings.append({
                "tool": "zap",
                "title": alert.get('name'),
                "severity": risk_code,
                "target": target,
                "port": 80,
                "description": alert.get('description'),
                "remediation": alert.get('solution', 'No remediation provided by ZAP.')
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
