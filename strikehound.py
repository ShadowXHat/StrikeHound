#!/usr/bin/env python3
from urllib.parse import urlparse
import argparse
import yaml
import os
import subprocess
import sys

# Import our modules
from modules import slack_notifier
from modules.spinner import Spinner
from modules.validators import is_safe_target
import modules.nmap_scanner as nmap_scanner
import modules.nuclei_scanner as nuclei_scanner
import modules.zap_scanner as zap_scanner
import modules.deduplicator as deduplicator
import modules.severity_mapper as severity_mapper
import modules.ssh_audit as ssh_audit
from modules import report_generator as report

ZAP_BOOT_TIMEOUT_SECONDS = 30


def load_config(config_path="config.yaml"):
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        print(f"[!] Error: {config_path} not found. Copy config.example.yaml to config.yaml first.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"[!] Error: {config_path} is not valid YAML: {e}")
        sys.exit(1)


def clean_target_for_nmap(target: str) -> str:
    """Strips scheme/path from a URL so nmap gets a bare host, not a full URL."""
    if target.startswith("http"):
        return urlparse(target).netloc
    return target


def main():
    parser = argparse.ArgumentParser(description="StrikeHound: Automated Security Scanning & Reporting Framework")
    parser.add_argument("-t", "--target", required=True, help="Target IP or URL to scan")
    parser.add_argument("-m", "--profile", choices=["quick", "standard", "full"], default="standard", help="Nmap scan depth (mode)")
    parser.add_argument("-o", "--output-dir", default="./output", help="Where to write results")
    parser.add_argument("--no-report", action="store_true", help="Skip PDF generation")
    args = parser.parse_args()

    if not is_safe_target(args.target):
        print(f"[!] Error: '{args.target}' doesn't look like a valid target (hostname, IP, or URL).")
        print("    Refusing to pass it to downstream tools.")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    config = load_config()
    severity_map = config.get('severity_map', {})

    print(f"[*] Starting StrikeHound against {args.target}")

    zap_process = None
    try:
        # --- Phase 0: Boot ZAP daemon in the background ---
        print("    [+] Booting background scanning engines...")
        zap_path = config.get('tools', {}).get('zap_path', 'zap.sh')
        zap_api_url = config.get('tools', {}).get('zap_api_url', 'http://localhost:8080')

        if not zap_path:
            print("    [-] No zap_path configured - skipping ZAP entirely for this run.")
            zap_process = None
        else:
            try:
                zap_process = subprocess.Popen(
                    [zap_path, "-daemon", "-port", "8080", "-config", "api.disablekey=true"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except (FileNotFoundError, PermissionError) as e:
                print(f"    [!] Could not launch ZAP at '{zap_path}' - check tools.zap_path in config.yaml. ({e})")
                zap_process = None

        if zap_process:
            print(f"    [~] Waiting up to {ZAP_BOOT_TIMEOUT_SECONDS}s for ZAP to become ready...")
            if zap_scanner.wait_for_zap(zap_api_url, max_wait=ZAP_BOOT_TIMEOUT_SECONDS):
                print("    [+] ZAP daemon is ready.")
            else:
                print("    [!] ZAP did not become ready in time - ZAP scan phase will be skipped.")

        # --- Phase 1: Discovery (Nmap) ---
        print("\n[*] Phase 1: Running Discovery Scan (Nmap)...")
        nmap_target = clean_target_for_nmap(args.target)
        nmap_flags = config.get('scan_profiles', {}).get(args.profile, '-sV -sC -T4')
        open_ports_dict = nmap_scanner.run_scan(nmap_target, nmap_flags)
        open_ports = list(open_ports_dict.keys())

        # If Nmap fails or finds nothing, still try web scanners if a URL was given
        if not open_ports and args.target.startswith(("http://", "https://")):
            open_ports = [80, 443]

        # --- Phase 2: Intelligent Orchestration ---
        print("\n[*] Phase 2: Orchestrating Downstream Scanners...")
        raw_findings = []

        if 80 in open_ports or 443 in open_ports or args.target.startswith(("http://", "https://")):
            print("    [+] Web ports detected. Triggering Nuclei and ZAP...")

            # --- Nuclei ---
            nuclei_path = config.get('tools', {}).get('nuclei_path', 'nuclei')
            nuclei_results = nuclei_scanner.run_scan(args.target, nuclei_path)
            for finding in nuclei_results:
                finding['severity'] = severity_mapper.normalize('nuclei', finding.get('severity'), severity_map)
            raw_findings.extend(nuclei_results)

            # --- ZAP ---
            if zap_process and zap_scanner.is_zap_ready(zap_api_url):
                zap_key = config.get('tools', {}).get('zap_api_key', '')
                scan_spinner = Spinner(message="ZAP is actively crawling and attacking...")
                scan_spinner.start()
                try:
                    zap_results = zap_scanner.run_scan(args.target, zap_api_url, zap_key)
                    for finding in zap_results:
                        finding['severity'] = severity_mapper.normalize('zap', finding.get('severity'), severity_map)
                    raw_findings.extend(zap_results)
                    scan_spinner.stop(success_message=f"ZAP finished successfully. Found {len(zap_results)} issues.")
                except Exception as e:
                    scan_spinner.stop()
                    print(f"    [!] ZAP Scan failed: {e}")
            else:
                print("    [-] ZAP not available. Skipping ZAP scan.")
        else:
            print("    [-] No web ports detected. Skipping web vulnerability scanners.")

        # --- Phase 2.5: SSH Auditing ---
        if 22 in open_ports:
            print("    [+] SSH port detected (22). Triggering SSH Audit...")
            ssh_results = ssh_audit.run_scan(nmap_target)
            for finding in ssh_results:
                finding['severity'] = severity_mapper.normalize('ssh_audit', finding.get('severity'), severity_map)
            raw_findings.extend(ssh_results)

        # --- Phase 3: Data Normalization & Cleanup ---
        print("\n[*] Phase 3: Deduplicating and Normalizing Findings...")
        normalized_findings = deduplicator.deduplicate(raw_findings)

        # --- Phase 4: Report Generation ---
        if args.no_report:
            print("\n[*] Phase 4: Skipping PDF generation (--no-report).")
        elif normalized_findings:
            print("\n[*] Phase 4: Generating PDF Report...")
            report_path = report.generate_report(normalized_findings, args.target, args.output_dir, open_ports)

            slack_url = config.get('tools', {}).get('slack_webhook')
            slack_notifier.send_alert(slack_url, args.target, len(normalized_findings), report_path)
        else:
            print("\n[*] Phase 4: No findings to report. Skipping PDF generation.")

        print("\n[+] Pipeline execution complete!")

    finally:
        # Always attempt to clean up the ZAP daemon, even if something above crashed.
        if zap_process and zap_process.poll() is None:
            print("\n[*] Shutting down background engines...")
            zap_process.terminate()
            try:
                zap_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                zap_process.kill()


if __name__ == "__main__":
    main()
