"""
Parse ZAP Automation Framework "traditional-json" reports into StrikeHound findings.

When StrikeHound writes an automation plan (zap.automation: true) and the user
runs it with `zap -cmd -autorun`, ZAP writes zap-reports/zap-report.json in the
JSON report template. This module turns that back into the same normalized
finding shape the REST path produces, so automation-run results flow through
dedup, SARIF/JSON/PDF output, and the --fail-on / --policy gates.

The ZAP JSON report's riskcode uses the same 0-3 ZAP risk enum as the REST API,
so findings feed through severity_mapper.normalize('zap', ...) unchanged.
"""
import json
import os

TOOL = "zap"
DEFAULT_REPORT_FILE = "zap-report.json"


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _site_port(site: dict) -> int:
    port = _as_int(site.get("@port"))
    return port if port else (443 if str(site.get("@ssl", "")).lower() == "true" else 80)


def parse_zap_json_report(report_path: str) -> list:
    """Parses a traditional-json ZAP report file into normalized findings."""
    findings = []
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for site in data.get("site") or []:
        target = site.get("@name") or ""
        port = _site_port(site)
        for alert in site.get("alerts") or []:
            findings.append({
                "tool": TOOL,
                "title": alert.get("alert") or alert.get("name"),
                "severity": _as_int(alert.get("riskcode")),
                "target": target,
                "port": port,
                "url": target,
                "description": alert.get("desc"),
                "remediation": alert.get("solution", "No remediation provided by ZAP."),
                "evidence": alert.get("evidence"),
                "confidence": _as_int(alert.get("confidence")),
                "cwe_id": alert.get("cweid"),
                "wasc_id": alert.get("wascid"),
            })
    return findings


def latest_report(report_dir: str):
    """Returns the path of the newest zap-report.json under report_dir, or None."""
    path = os.path.join(report_dir, DEFAULT_REPORT_FILE)
    return path if os.path.isfile(path) else None