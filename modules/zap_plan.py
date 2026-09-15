"""
Generate ZAP Automation Framework plan files.

ZAP's recommended modern workflow is to describe a scan as a YAML
"automation plan" and execute it in one-shot mode:

    zap.sh -cmd -autorun plan.yaml -port 8080 -config api.disablekey=true

This module builds such a plan from the same zap: config block the REST
path uses (see strikehound.zap_scan_config), so authenticated scans can be
replayed outside the daemon/REST flow - which is where complex auth
(OAuth2, SAML, ...) is reliably supported.
"""
import yaml

AUTH_CONTEXT = "strikehound"
AUTH_USER = "strikehound-user"


def _report_job():
    return {
        "type": "report",
        "parameters": {
            "template": "traditional-json",
            "reportDir": "zap-reports",
            "reportFile": "zap-report.json",
            "display": False,
        },
    }


def build_plan(target: str, out_path: str, auth: dict = None,
               ajax_spider: bool = False) -> str:
    """
    Writes a ZAP automation plan for `target` to `out_path` and returns the path.

    Args:
        target: URL to scan.
        out_path: where to write the YAML plan.
        auth: optional auth dict in the same shape strikehound.zap_scan_config
            produces ('form' or 'header' methods supported).
        ajax_spider: also include a spiderAjax (headless-browser) job.
    """
    urls = [target]
    context = {"name": AUTH_CONTEXT, "urls": urls}
    scan_user = None

    if auth and auth.get("method") == "form":
        login_request_data = auth.get('login_request_data') or (
            f"{auth.get('username_field', 'username')}={{%username%}}&"
            f"{auth.get('password_field', 'password')}={{%password%}}"
        )
        context["authentication"] = {
            "method": "form",
            "parameters": {
                "loginUrl": auth.get("login_url", ""),
                "loginRequestData": login_request_data,
            },
        }
        context["users"] = [{
            "name": AUTH_USER,
            "credentials": {"username": auth["username"], "password": auth["password"]},
        }]
        scan_user = AUTH_USER
    elif auth and auth.get("method") == "header":
        context["authentication"] = {
            "method": "httpHeader",
            "parameters": {
                "headerName": auth.get("header_name", "Authorization"),
                "headerValue": auth.get("header_value", ""),
            },
        }

    jobs = []

    spider_params = {"url": target}
    if scan_user:
        spider_params["context"] = AUTH_CONTEXT
        spider_params["user"] = scan_user
    jobs.append({"type": "spider", "parameters": spider_params})

    if ajax_spider:
        ajax_params = {"runInForeground": True, "waitTime": 2}
        if scan_user:
            ajax_params["context"] = AUTH_CONTEXT
            ajax_params["user"] = scan_user
        jobs.append({"type": "spiderAjax", "parameters": ajax_params})

    jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": 2}})

    asc_params = {"context": AUTH_CONTEXT, "url": target}
    if scan_user:
        asc_params["user"] = scan_user
    jobs.append({"type": "activeScan", "parameters": asc_params})

    jobs.append(_report_job())

    plan = {
        "env": {
            "contexts": [context],
            "parameters": {"failOnError": True, "failOnWarning": False,
                           "progressToStdout": True},
        },
        "jobs": jobs,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(plan, f, default_flow_style=False, sort_keys=False)
    return out_path