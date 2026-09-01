import requests
import time

def scan_target(zap, target_url):
    print("[*] Starting ZAP Spider...")
    scan_id = zap.spider.scan(target_url)
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(2)
        
    print("[*] Starting ZAP Active Scan...")
    ascan_id = zap.ascan.scan(target_url)
    while int(zap.ascan.status(ascan_id)) < 100:
        time.sleep(5)
        
    return zap.core.alerts(baseurl=target_url)

def run_scan(target: str, api_url: str = 'http://localhost:8080', api_key: str = '') -> list:
    """Triggers an OWASP ZAP scan via its REST API and returns normalized findings."""
    print(f"    [>] Triggering OWASP ZAP API against {target}")
    findings = []

    # Clean up the URL just in case there's a trailing slash in the config
    if api_url.endswith('/'):
        api_url = api_url[:-1]

    # ZAP requires the API key to be passed in the headers
    headers = {
        'Accept': 'application/json',
       
    }

    try:
        # Step 1: Start the ZAP Spider
        print("        -> Initiating ZAP Spider...")
        spider_url = f"{api_url}/JSON/spider/action/scan/"
        r_spider = requests.get(spider_url, params={'url': target}, headers=headers)
        r_spider.raise_for_status()
        scan_id = r_spider.json().get('scan')

        # Step 2: Poll the API until the Spider reaches 100%
        status = "0"
        while int(status) < 100:
            time.sleep(2)  # Wait 2 seconds between checks
            status_url = f"{api_url}/JSON/spider/view/status/"
            r_status = requests.get(status_url, params={'scanId': scan_id}, headers=headers)
            status = r_status.json().get('status', '100')

        # Step 3: Fetch the security alerts (vulnerabilities)
        print("        -> Fetching vulnerabilities from ZAP...")
        alerts_url = f"{api_url}/JSON/core/view/alerts/"
        r_alerts = requests.get(alerts_url, params={'baseurl': target}, headers=headers)
        alerts = r_alerts.json().get('alerts', [])

        # Step 4: Normalize the raw ZAP data into the StrikeHound format
        for alert in alerts:
            findings.append({
                "tool": "zap",
                "title": alert.get('name'),
                "severity": int(alert.get('riskCode', 0)), # Use riskCode to get the integer!
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
