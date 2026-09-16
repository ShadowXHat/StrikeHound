import os
import json
from collections import Counter
from fpdf import FPDF
from fpdf.enums import XPos, YPos

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

_FONT_PATHS = [
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed-Bold.ttf"),
]

_REGULAR_FONT, _BOLD_FONT = next(
    (regular, bold) for regular, bold in _FONT_PATHS
    if os.path.isfile(regular) and os.path.isfile(bold)
) if any(os.path.isfile(r) and os.path.isfile(b) for r, b in _FONT_PATHS) else (None, None)

FONT_FAMILY = "StrikeHoundUnicode" if _REGULAR_FONT else "Helvetica"


def _register_font(pdf: FPDF) -> None:
    """Registers a Unicode TTF font when available so non-Latin-1 text (e.g.
    em dashes, smart quotes) renders in PDFs; falls back to Helvetica."""
    if FONT_FAMILY == "StrikeHoundUnicode":
        pdf.add_font("StrikeHoundUnicode", "", _REGULAR_FONT)
        pdf.add_font("StrikeHoundUnicode", "B", _BOLD_FONT)

_SEVERITY_COLOR = {
    "critical": (200, 30, 30),
    "high": (200, 30, 30),
    "medium": (220, 120, 0),
    "low": (30, 100, 200),
    "info": (80, 80, 80),
}


def safe_filename_from_target(target: str) -> str:
    """Turns a target (URL or IP) into a filesystem-safe filename fragment."""
    cleaned = target.replace("http://", "").replace("https://", "")
    cleaned = cleaned.replace("/", "_").replace(":", "_")
    return cleaned


def _report_base(target: str, output_dir: str) -> tuple:
    os.makedirs(output_dir, exist_ok=True)
    base = safe_filename_from_target(target)
    return os.path.join(output_dir, f"StrikeHound_Report_{base}")


def generate_sarif(findings, target, output_file):
    """Writes findings as SARIF 2.1.0 so they plug into GitHub code scanning."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "StrikeHound",
                    "informationUri": "https://github.com/ShadowXHat/StrikeHound",
                    "version": "1.0.0",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    driver = sarif["runs"][0]["tool"]["driver"]
    results = sarif["runs"][0]["results"]
    rule_ids = {}

    for item in findings:
        title = item.get("title") or item.get("name") or "Vulnerability Detected"
        rule_id = f"SH-{len(rule_ids) + 1:04d}"

        rule_ids.setdefault(rule_id, title)
        driver["rules"].append({
            "id": rule_id,
            "name": "strikehound-rule",
            "shortDescription": {"text": title},
            "fullDescription": {"text": item.get("description", "No description provided.")},
            "defaultConfiguration": {"level": "error" if str(item.get("severity", "")).lower() in ("critical", "high") else "warning"},
        })

        severity = str(item.get("severity", "info")).lower()
        level = "error" if severity in ("critical", "high") else ("warning" if severity == "medium" else "note")

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item.get("matched_at") or item.get("target") or target}
                }
            }]
        })

    with open(output_file, 'w') as f:
        json.dump(sarif, f, indent=2)


def generate_json(findings, target, output_file):
    """Writes the deduplicated findings as JSON for machine consumption."""
    payload = {
        "target": target,
        "total_findings": len(findings),
        "severity_counts": dict(Counter(str(f.get("severity", "Info")) for f in findings)),
        "findings": findings,
    }
    with open(output_file, 'w') as f:
        json.dump(payload, f, indent=2)


def generate_report(findings, target, output_dir, open_ports) -> str:
    """
    Generates the PDF report and returns the actual path it was written to,
    so callers (e.g. the Slack notifier) report an accurate filename.
    """
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    _register_font(pdf)
    pdf.add_page()

    # Document Header
    pdf.set_font(FONT_FAMILY, 'B', 22)
    pdf.cell(0, 15, text="StrikeHound Security Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(4)

    # Scan Metadata
    pdf.set_font(FONT_FAMILY, 'B', 10)
    pdf.cell(30, 6, text="Target:", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font(FONT_FAMILY, size=10)
    pdf.cell(0, 6, text=str(target), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font(FONT_FAMILY, 'B', 10)
    pdf.cell(30, 6, text="Open Ports:", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font(FONT_FAMILY, size=10)
    ports_str = ', '.join(map(str, open_ports)) if open_ports else "80, 443"
    pdf.cell(0, 6, text=ports_str, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)

    # Vulnerability Summary Header
    pdf.set_font(FONT_FAMILY, 'B', 14)
    pdf.cell(0, 8, text="Vulnerability Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    if not findings:
        pdf.set_font(FONT_FAMILY, size=10)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 6, text="No findings were reported for this target.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Severity counts summary
    sev_counts = Counter()
    for f in findings:
        if isinstance(f, dict):
            sev_counts[str(f.get('severity') or 'Info').capitalize()] += 1

    if findings:
        pdf.set_font(FONT_FAMILY, size=10)
        counted = 0
        for sev in SEVERITY_ORDER:
            if sev in sev_counts:
                pdf.set_text_color(*_SEVERITY_COLOR.get(sev.lower(), (80, 80, 80)))
                pdf.cell(0, 6, text=f"      {sev}: {sev_counts[sev]}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                counted += 1
        if counted == 0:
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 6, text="      No severity-normalized findings.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

    for raw_issue in findings:
        # Normalize issue to dict if passed as string
        if isinstance(raw_issue, str):
            try:
                issue = json.loads(raw_issue)
            except Exception:
                issue = {'name': raw_issue}
        elif isinstance(raw_issue, dict):
            issue = raw_issue
        else:
            issue = {}

        # Resolve nested info structures
        info = issue.get('info', {}) if isinstance(issue.get('info'), dict) else {}

        name = (
            issue.get('title')
            or issue.get('name')
            or info.get('name')
            or issue.get('alert')
            or issue.get('template-id')
            or "Security Finding"
        )

        url = (
            issue.get('matched-at')
            or issue.get('url')
            or issue.get('host')
            or issue.get('target')
            or info.get('reference')
            or target
        )
        if isinstance(url, list):
            url = url[0] if url else target

        severity = str(
            issue.get('severity')
            or info.get('severity')
            or issue.get('risk')
            or 'Info'
        ).capitalize()

        # Severity Colors
        pdf.set_text_color(*_SEVERITY_COLOR.get(severity.lower(), (80, 80, 80)))

        pdf.set_font(FONT_FAMILY, 'B', 10)
        pdf.cell(0, 6, text=f"[{severity}] {name}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font(FONT_FAMILY, size=9)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 5, f"Matched Endpoint: {url}\nDescription: {issue.get('description') or info.get('description') or 'No description provided.'}")

        remediation = issue.get('remediation') or info.get('remediation')
        if remediation:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 5, f"How to Fix: {remediation}")
        pdf.ln(3)

    report_path = f"{_report_base(target, output_dir)}.pdf"
    pdf.output(report_path)
    print(f"[+] Report generated successfully: {report_path}")

    return report_path