#!/usr/bin/env python3
from urllib.parse import urlparse
import argparse
import yaml
import os
import subprocess
import time

# Import our newly built modules
from modules import slack_notifier
from modules.spinner import Spinner
import modules.nmap_scanner as nmap_scanner
import modules.nuclei_scanner as nuclei_scanner
import modules.zap_scanner as zap_scanner
import modules.deduplicator as deduplicator
import modules.severity_mapper as severity_mapper
import modules.ssh_audit as ssh_audit
import reports.pdf_generator as pdf_generator

def load_config(config_path="config.yaml"):
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        print(f"[!] Error: {config_path} not found. Please ensure it exists.")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="StrikeHound: Automated Security Scanning & Reporting Framework")
   # Added -t and -m flags!
    parser.add_argument("-t", "--target", required=True, help="Target IP or URL to scan")
    parser.add_argument("-m", "--profile", choices=["quick", "standard", "full"], default="standard", help="Nmap scan depth (mode)")
    parser.add_argument("-o", "--output-dir", default="./output", help="Where to write results")
    parser.add_argument("--no-report", action="store_true", help="Skip PDF generation")
    
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    config = load_config()

    print(f"[*] Starting strikehound against {args.target}")
    
    # --- NEW: AUTO-START ZAP DAEMON ---
    print("    [+] Booting background scanning engines (this takes a few seconds)...")
    zap_path = config.get('tools', {}).get('zap_path', 'zap.sh')
    
    # We use Popen so it runs in the background without freezing the script
    zap_process = subprocess.Popen(
        [zap_path, "-daemon", "-port", "8080", "-config", "api.disablekey=true"],
        stdout=subprocess.DEVNULL, # Hides ZAP's messy terminal output
        stderr=subprocess.DEVNULL
    )
    time.sleep(10) # Give Java a few seconds to fully boot up
    # ----------------------------------

    # Phase 1: Discovery (Nmap)
    print("\n[*] Phase 1: Running Discovery Scan (Nmap)...")
    
    # Clean the target for Nmap (strip http:// and paths)
    nmap_target = args.target
    if nmap_target.startswith("http"):
        parsed_url = urlparse(nmap_target)
        nmap_target = parsed_url.netloc

    nmap_flags = config.get('scan_profiles', {}).get(args.profile, '-sV -sC -T4')
    # Use the cleaned target for Nmap only!
    open_ports_dict = nmap_scanner.run_scan(nmap_target, nmap_flags) 
    open_ports = list(open_ports_dict.keys())
    nmap_flags = config.get('scan_profiles', {}).get(args.profile, '-sV -sC -T4')
    open_ports_dict = nmap_scanner.run_scan(args.target, nmap_flags)
    open_ports = list(open_ports_dict.keys())
    
    # If Nmap fails or finds nothing, let's at least test web if the user provided a URL
    if not open_ports and (args.target.startswith("http") or args.target.startswith("https")):
        open_ports = [80, 443]

    # Phase 2: Intelligent Orchestration
    print("\n[*] Phase 2: Orchestrating Downstream Scanners...")
    raw_findings = []
    
    if 80 in open_ports or 443 in open_ports or args.target.startswith("http"):
        print("    [+] Web ports detected. Triggering Nuclei and ZAP...")
        
        # --- 1. Run Nuclei ---
        nuclei_path = config.get('tools', {}).get('nuclei_path', 'nuclei')
        nuclei_results = nuclei_scanner.run_scan(args.target, nuclei_path)
        
        for finding in nuclei_results:
            finding['severity'] = severity_mapper.normalize('nuclei', finding.get('severity'))
        raw_findings.extend(nuclei_results)
        
        # --- 2. Run ZAP (with the Spinner) ---
        zap_url = config.get('tools', {}).get('zap_api_url', 'http://localhost:8080')
        zap_key = config.get('tools', {}).get('zap_api_key', '')
        
        scan_spinner = Spinner(message="ZAP is actively crawling and attacking...")
        scan_spinner.start()

        try:
            zap_results = zap_scanner.run_scan(args.target, zap_url, zap_key)
            
            for finding in zap_results:
                finding['severity'] = severity_mapper.normalize('zap', finding.get('severity'))
            raw_findings.extend(zap_results)
            
            scan_spinner.stop(success_message=f"ZAP finished successfully. Found {len(zap_results)} issues.")
            
        except Exception as e:
            scan_spinner.stop()
            print(f"    [!] ZAP Scan failed: {e}")

    else:
        print("    [-] No web ports detected. Skipping web vulnerability scanners.")
    

    # Phase 2.5: SSH Auditing
    if 22 in open_ports:
        print("    [+] SSH port detected (22). Triggering SSH Audit...")
        ssh_results = ssh_audit.run_scan(args.target)
        
        for finding in ssh_results:
            finding['severity'] = severity_mapper.normalize('ssh_audit', finding.get('severity'))
        raw_findings.extend(ssh_results)

    # Phase 3: Data Normalization & Cleanup
    print("\n[*] Phase 3: Deduplicating and Normalizing Findings...")
    normalized_findings = deduplicator.deduplicate(raw_findings)

    # Phase 4: Report Generation
    print("\n[*] Phase 4: Generating PDF Report...")
    report_path = f"{args.output_dir}/StrikeHound_Report_{args.target.replace('http://', '').replace('https://', '').replace('/', '_')}.pdf"
    
    if raw_findings:
        report.generate_report(raw_findings, args.target, args.output_dir, open_ports)
        
        # --- NEW: Trigger Slack Webhook ---
        slack_url = config.get('tools', {}).get('slack_webhook')
        slack_notifier.send_alert(slack_url, args.target, len(raw_findings), report_path)
        # ----------------------------------
    else:
        print("    [-] No findings to report. Skipping PDF generation.")
    
    
    # --- NEW: AUTO-KILL ZAP DAEMON ---
    print("\n[*] Shutting down background engines...")
    zap_process.terminate()
    # ---------------------------------

    print("[+] Pipeline execution complete!")
   

if __name__ == "__main__":
    main()
