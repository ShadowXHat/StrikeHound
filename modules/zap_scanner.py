import requests
import time


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


def run_scan(target: str, api_url: str = 'http://localhost:8080', api_key: str = '') -> list:
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
        scan_id = r_spider.json().get('scan')

        # Step 2: Poll the API until the Spider reaches 100%
        status = "0"
        status_url = f"{api_url}/JSON/spider/view/status/"
        while int(status) < 100:
            time.sleep(2)
            r_status = requests.get(status_url, params={**base_params, 'scanId': scan_id}, headers=headers, timeout=10)
            status = r_status.json().get('status', '100')

        # Step 3: Start the ZAP Active Scan
        print("        -> Initiating ZAP Active Scan...")
        ascan_url = f"{api_url}/JSON/ascan/action/scan/"
        r_ascan = requests.get(ascan_url, params={**base_params, 'url': target}, headers=headers, timeout=10)
        r_ascan.raise_for_status()
        ascan_id = r_ascan.json().get('scan')

        ascan_status = "0"
        ascan_status_url = f"{api_url}/JSON/ascan/view/status/"
        while int(ascan_status) < 100:
            time.sleep(5)
            r_status = requests.get(ascan_status_url, params={**base_params, 'scanId': ascan_id}, headers=headers, timeout=10)
            ascan_status = r_status.json().get('status', '100')

        # Step 4: Fetch the security alerts (vulnerabilities)
        print("        -> Fetching vulnerabilities from ZAP...")
        alerts_url = f"{api_url}/JSON/core/view/alerts/"
        r_alerts = requests.get(alerts_url, params={**base_params, 'baseurl': target}, headers=headers, timeout=10)
        alerts = r_alerts.json().get('alerts', [])

        # Step 5: Normalize the raw ZAP data into the StrikeHound format
        for alert in alerts:
            findings.append({
                "tool": "zap",
                "title": alert.get('name'),
                "severity": int(alert.get('riskCode', 0)),
                "target": target,
                "port": 80,
                "description": alert.get('description'),
                "remediation": alert.get('solution', 'No remediation provided by ZAP.')
            })

        print(f"        -> ZAP API finished: Downloaded {len(findings)} live issues.")

    except requests.exceptions.ConnectionError:
        print(f"    [!] ZAP API Error: Could not connect to {api_url}.")
        print("        Ensure the OWASP ZAP application is actually running on your machine.")
    except Exception as e:
        print(f"    [!] ZAP API execution error: {e}")

    return findings
