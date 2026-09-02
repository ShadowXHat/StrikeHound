import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def generate_report(findings: list, target: str, output_dir: str, open_ports: list = None):
    """Generates a professional, color-coded DevSecOps PDF report."""
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Clean the target name for the filename
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    filename = f"StrikeHound_Report_{safe_target}.pdf"
    filepath = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # --- Custom Styles ---
    title_style = styles['Title']
    heading_style = styles['Heading2']
    body_style = styles['Normal']
    
    # --- Title Section ---
    story.append(Paragraph(f"StrikeHound Security Assessment", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Target:</b> {target}", body_style))
    story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Paragraph(f"<b>Total Findings:</b> {len(findings)}", body_style))
    story.append(Spacer(1, 20))

    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", heading_style))
    exec_summary = f"This report outlines the security vulnerabilities discovered during the automated DevSecOps assessment of {target}. A total of {len(findings)} unique issues were identified across the target infrastructure and web applications."
    story.append(Paragraph(exec_summary, body_style))
    story.append(Spacer(1, 20))

    # --- Improvement #1: Discovered Infrastructure (NMAP PORTS) ---
    if open_ports:
        story.append(Paragraph("Discovered Infrastructure", heading_style))
        story.append(Paragraph("The following ports and services were found open during the discovery phase:", body_style))
        story.append(Spacer(1, 10))
        for port in open_ports:
            story.append(Paragraph(f"• Port {port}", body_style))
        story.append(Spacer(1, 20))

    # --- Improvement #3: Color Coded Findings Summary Table ---
    story.append(Paragraph("Findings Summary", heading_style))
    table_data = [["Severity", "Vulnerability", "Tool"]]
    
    for finding in findings:
        # Some findings might not have a tool listed, default to 'UNKNOWN'
        tool_name = finding.get('tool', 'UNKNOWN').upper()
        table_data.append([finding.get('severity', 'Info'), finding.get('title', 'Unknown Issue'), tool_name])

    # Table Styling (Dark mode header)
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.2, 0.2)), # Dark Grey
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ])

    # Apply colors based on severity dynamically
    for i, row in enumerate(table_data[1:], start=1):
        sev = str(row[0]).lower()
        if sev in ['critical', 'high', '3', '2']: # Handling string and int severities
            table_style.add('TEXTCOLOR', (0, i), (0, i), colors.red)
        elif sev in ['medium', '1']:
            table_style.add('TEXTCOLOR', (0, i), (0, i), colors.orange)
        else:
            table_style.add('TEXTCOLOR', (0, i), (0, i), colors.blue)

    summary_table = Table(table_data)
    summary_table.setStyle(table_style)
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # --- Detailed Findings & Improvement #2: Remediation ---
    story.append(Paragraph("Detailed Findings", heading_style))
    for finding in findings:
        story.append(Paragraph(f"<b>{finding.get('title', 'Unknown Issue')}</b>", styles['Heading3']))
        story.append(Paragraph(f"<b>Severity:</b> {finding.get('severity', 'Info')}", body_style))
        story.append(Paragraph(f"<b>Description:</b> {finding.get('description', 'No description provided.')}", body_style))
        
        # Add Remediation if it exists
        remediation = finding.get('remediation')
        if remediation:
            story.append(Spacer(1, 5))
            story.append(Paragraph(f"<b>How to Fix:</b> {remediation}", body_style))
            
        story.append(Spacer(1, 15))

    # --- Generate PDF ---
    doc.build(story)
    print(f"    [+] Report generated successfully: {filepath}")
