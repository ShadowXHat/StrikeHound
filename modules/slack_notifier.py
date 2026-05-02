import requests
import json

def send_alert(webhook_url, target, total_findings, report_path):
    """Sends a summary alert to a Slack channel via Webhook."""
    if not webhook_url or webhook_url == "your_slack_webhook_here":
        return # Skip if the user hasn't configured a webhook

    message = {
        "text": f"🚀 *StrikeHound Scan Complete!* 🚀\n*Target:* `{target}`\n*Unique Vulnerabilities Found:* `{total_findings}`\n*Report Generated:* `{report_path}`"
    }
    
    try:
        response = requests.post(
            webhook_url, 
            data=json.dumps(message), 
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            print("    [+] Slack notification sent successfully!")
        else:
            print(f"    [-] Slack API returned status code: {response.status_code}")
    except Exception as e:
        print(f"    [!] Failed to send Slack notification: {e}")
