import os
import json
from fpdf import FPDF


def generate_sarif(findings, target, output_file):
    sarif_skeleton = {
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
    
    for idx, item in enumerate(findings):
        rule_id = f"SH-{idx+1:04d}"
        sarif_skeleton["runs"][0]["results"].append({
            "ruleId": rule_id,
            "message": {"text": item.get("name", "Vulnerability Detected")},
            "level": "error" if str(item.get("severity")).lower() in ['critical', 'high'] else "warning",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item.get("url", target)}
                }
            }]
        })

    with open(output_file, 'w') as f:
        json.dump(sarif_skeleton, f, indent=2)

def generate_report(findings, target, output_dir, open_ports):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Document Header
    pdf.set_font("Arial", 'B', 22)
    pdf.cell(0, 15, txt="StrikeHound Security Report", ln=True, align='C')
    pdf.ln(4)
    
    # Scan Metadata
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(30, 6, "Target:", 0, 0)
    pdf.set_font("Arial", size=10)
    pdf.cell(0, 6, str(target), 0, 1)
    
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(30, 6, "Open Ports:", 0, 0)
    pdf.set_font("Arial", size=10)
    ports_str = ', '.join(map(str, open_ports)) if open_ports else "80, 443"
    pdf.cell(0, 6, ports_str, 0, 1)
    pdf.ln(6)

    # Vulnerability Summary Header
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 8, txt="Vulnerability Summary", ln=True)
    pdf.ln(2)
    
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
            issue.get('name') 
            or info.get('name') 
            or issue.get('alert') 
            or issue.get('template-id') 
            or "Security Finding"
        )
        
        url = (
            issue.get('matched-at') 
            or issue.get('url') 
            or issue.get('host') 
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
        if severity.lower() in ['critical', 'high']:
            pdf.set_text_color(200, 30, 30)
        elif severity.lower() == 'medium':
            pdf.set_text_color(220, 120, 0)
        elif severity.lower() == 'low':
            pdf.set_text_color(30, 100, 200)
        else:
            pdf.set_text_color(80, 80, 80)
        
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(0, 6, f"[{severity}] {name}", ln=True)
        
        pdf.set_font("Arial", size=9)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 5, f"Matched Endpoint: {url}")
        pdf.ln(3)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    report_path = os.path.join(output_dir, "strikehound_report.pdf")
    pdf.output(report_path)
    print(f"[+] Report generated successfully: {report_path}")
    
