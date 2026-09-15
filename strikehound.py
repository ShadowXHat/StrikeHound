#!/usr/bin/env python3
from urllib.parse import urlparse
import argparse
import yaml
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import our modules
from modules import slack_notifier
from modules.spinner import Spinner
from modules.validators import is_safe_target
import modules.nmap_scanner as nmap_scanner
import modules.nuclei_scanner as nuclei_scanner
import modules.zap_scanner as zap_scanner
import modules.zap_plan as zap_plan
import modules.deduplicator as deduplicator
import modules.severity_mapper as severity_mapper
import modules.ssh_audit as ssh_audit
from modules import report_generator as report

ZAP_BOOT_TIMEOUT_SECONDS = 30

# Used by --fail-on: the weight of the worst finding determines the exit code.
FAIL_SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


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


def worst_finding_severity(findings) -> str:
    """Returns the label of the highest-severity finding ('Info' if none)."""
    worst = "info"
    for f in findings:
        sev = str(f.get('severity', 'Info')).strip().lower()
        if FAIL_SEVERITY_WEIGHTS.get(sev, 0) > FAIL_SEVERITY_WEIGHTS.get(worst, 0):
            worst = sev
    return worst


def load_targets(args) -> list:
    """Collects targets from -t and/or -l, validates them, and returns a deduped list."""
    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets_file:
        try:
            with open(args.targets_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[!] Error: targets file {args.targets_file} not found.")
            sys.exit(1)

    if not targets:
        print("[!] Error: provide a target with -t, or a list of targets with -l/--targets-file.")
        sys.exit(1)

    seen, cleaned = set(), []
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        if not is_safe_target(target):
            print(f"[!] Error: '{target}' doesn't look like a valid target (hostname, IP, or URL).")
            print("    Refusing to pass it to downstream tools.")
            sys.exit(1)
        cleaned.append(target)
    return cleaned


def zap_scan_config(config) -> tuple:
    """
    Builds the (auth, ajax_spider) arguments for zap_scanner.run_scan from the
    `zap:` config block. Secrets can live in the config OR in environment
    variables (STRIKEHOUND_ZAP_USERNAME / STRIKEHOUND_ZAP_PASSWORD /
    STRIKEHOUND_ZAP_TOKEN); env vars take precedence so CI can supply them.
    """
    zap_cfg = config.get('zap', {}) or {}
    ajax_spider = bool(zap_cfg.get('ajax_spider', False))
    auth = None
    auth_cfg = zap_cfg.get('auth', {}) or {}
    method = str(auth_cfg.get('method', 'none')).strip().lower()

    if method == 'form':
        auth = {
            'method': 'form',
            'login_url': auth_cfg.get('login_url', ''),
            'username_field': auth_cfg.get('username_field', 'username'),
            'password_field': auth_cfg.get('password_field', 'password'),
            'username': os.environ.get('STRIKEHOUND_ZAP_USERNAME') or auth_cfg.get('username', ''),
            'password': os.environ.get('STRIKEHOUND_ZAP_PASSWORD') or auth_cfg.get('password', ''),
            'login_request_data': auth_cfg.get('login_request_data', ''),
        }
    elif method == 'header':
        auth = {
            'method': 'header',
            'header_name': auth_cfg.get('header_name', 'Authorization'),
            'header_value': os.environ.get('STRIKEHOUND_ZAP_TOKEN') or auth_cfg.get('header_value', ''),
        }
    elif method != 'none':
        print(f"    [!] Unknown zap.auth.method '{method}' in config - ignoring auth config.")

    return auth, ajax_spider


def zap_plan_enabled(config: dict) -> bool:
    """Whether ZAP should be driven by an automation plan instead of the REST API."""
    return bool((config.get('zap', {}) or {}).get('automation', False))


def write_zap_plan(target: str, config: dict, output_dir: str) -> str:
    """Writes a ZAP automation plan for `target` and prints how to run it."""
    plans_dir = os.path.join(output_dir, "zap-plans")
    os.makedirs(plans_dir, exist_ok=True)
    plan_path = os.path.join(plans_dir, f"zap-plan-{report.safe_filename_from_target(target)}.yaml")

    auth, ajax_spider = zap_scan_config(config)
    zap_plan.build_plan(target, plan_path, auth=auth, ajax_spider=ajax_spider)

    zap_path = config.get('tools', {}).get('zap_path', 'zap.sh')
    print(f"    [+] ZAP automation plan written: {plan_path}")
    print(f"        Run it in one-shot mode: {zap_path} -cmd -autorun {plan_path} -port 8080 -config api.disablekey=true")
    return plan_path


def parallel_map(fn, items, jobs: int):
    """
    Applies fn to each item, running at most `jobs` threads.
    Preserves input order; degrades to a plain loop when jobs < 2.
    """
    items = list(items)
    if jobs <= 1 or len(items) <= 1:
        return [fn(x) for x in items]

    results = [None] * len(items)
    with ThreadPoolExecutor(max_workers=min(jobs, len(items))) as executor:
        future_to_index = {executor.submit(fn, item): i for i, item in enumerate(items)}
        for future in as_completed(future_to_index):
            results[future_to_index[future]] = future.result()
    return results


def scan_target(target: str, args, config: dict, severity_map: dict,
                zap_available: bool, zap_api_url: str, zap_key: str,
                zap_lock: threading.Lock = None) -> dict:
    """Runs the full per-target pipeline and returns findings + report path."""
    print(f"[*] Starting StrikeHound against {target}")

    # --- Phase 1: Discovery (Nmap) ---
    print("\n[*] Phase 1: Running Discovery Scan (Nmap)...")
    nmap_target = clean_target_for_nmap(target)
    nmap_flags = config.get('scan_profiles', {}).get(args.profile, '-sV -sC -T4')
    open_ports_dict = nmap_scanner.run_scan(nmap_target, nmap_flags, args.output_dir)
    open_ports = list(open_ports_dict.keys())

    # If Nmap fails or finds nothing, still try web scanners if a URL was given
    if not open_ports and target.startswith(("http://", "https://")):
        open_ports = [80, 443]

    # --- Phase 2: Intelligent Orchestration ---
    print("\n[*] Phase 2: Orchestrating Downstream Scanners...")
    raw_findings = []

    if 80 in open_ports or 443 in open_ports or target.startswith(("http://", "https://")):
        print("    [+] Web ports detected. Triggering Nuclei and ZAP...")

        # --- Nuclei ---
        nuclei_path = config.get('tools', {}).get('nuclei_path', 'nuclei')
        nuclei_cfg = config.get('nuclei', {}) or {}
        nuclei_results = nuclei_scanner.run_scan(
            target, nuclei_path, output_dir=args.output_dir,
            rate_limit=nuclei_cfg.get('rate_limit', nuclei_scanner.DEFAULT_RATE_LIMIT),
            concurrency=nuclei_cfg.get('concurrency', nuclei_scanner.DEFAULT_CONCURRENCY),
            bulk_size=nuclei_cfg.get('bulk_size', nuclei_scanner.DEFAULT_BULK_SIZE),
            timeout=nuclei_cfg.get('timeout', nuclei_scanner.DEFAULT_TIMEOUT),
            retries=nuclei_cfg.get('retries', nuclei_scanner.DEFAULT_RETRIES),
            tags=nuclei_cfg.get('tags', ''),
            severity=nuclei_cfg.get('severity', ''),
        )
        for finding in nuclei_results:
            finding['severity'] = severity_mapper.normalize('nuclei', finding.get('severity'), severity_map)
        raw_findings.extend(nuclei_results)

        # --- ZAP ---
        if zap_plan_enabled(config):
            write_zap_plan(target, config, args.output_dir)
        elif zap_available:
            auth, ajax_spider = zap_scan_config(config)
            context_name = f"strikehound-{report.safe_filename_from_target(target)}"
            # The Spinner runs its own thread; keep it serial-only so parallel
            # runs don't fight over the terminal.
            spinner = None if args.jobs != 1 else Spinner(message="ZAP is actively crawling and attacking...")
            if spinner:
                spinner.start()
            try:
                # A ZAP daemon can only handle a handful of active scans at
                # once, so serialize the ZAP phase across targets.
                if zap_lock:
                    with zap_lock:
                        zap_results = zap_scanner.run_scan(
                            target, zap_api_url, zap_key,
                            auth=auth, ajax_spider=ajax_spider, context_name=context_name,
                        )
                else:
                    zap_results = zap_scanner.run_scan(
                        target, zap_api_url, zap_key,
                        auth=auth, ajax_spider=ajax_spider, context_name=context_name,
                    )
                for finding in zap_results:
                    finding['severity'] = severity_mapper.normalize('zap', finding.get('severity'), severity_map)
                raw_findings.extend(zap_results)
                if spinner:
                    spinner.stop(success_message=f"ZAP finished successfully. Found {len(zap_results)} issues.")
            except Exception as e:
                if spinner:
                    spinner.stop()
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

    # --- Phase 3.5: Machine-readable output (always emitted) ---
    base = os.path.join(args.output_dir, f"StrikeHound_Report_{report.safe_filename_from_target(target)}")
    sarif_path = f"{base}.sarif"
    json_path = f"{base}.json"
    report.generate_sarif(normalized_findings, target, sarif_path)
    report.generate_json(normalized_findings, target, json_path)
    print(f"[+] SARIF written: {sarif_path}")
    print(f"[+] JSON written: {json_path}")

    # --- Phase 4: Report Generation ---
    report_path = None
    if args.no_report:
        print("\n[*] Phase 4: Skipping PDF generation (--no-report).")
    elif normalized_findings:
        print("\n[*] Phase 4: Generating PDF Report...")
        report_path = report.generate_report(normalized_findings, target, args.output_dir, open_ports)

        slack_url = config.get('tools', {}).get('slack_webhook')
        slack_notifier.send_alert(slack_url, target, len(normalized_findings), report_path)
    else:
        print("\n[*] Phase 4: No findings to report. Skipping PDF generation.")
        report_path = json_path

    return {"findings": normalized_findings, "report_path": report_path}


def main():
    parser = argparse.ArgumentParser(description="StrikeHound: Automated Security Scanning & Reporting Framework")
    parser.add_argument("-t", "--target", help="Target IP or URL to scan (or use -l/--targets-file for many)")
    parser.add_argument("-l", "--targets-file", help="File with one target per line (# comments and blank lines allowed)")
    parser.add_argument("-m", "--profile", choices=["quick", "standard", "full"], default="standard", help="Nmap scan depth (mode)")
    parser.add_argument("-o", "--output-dir", default="./output", help="Where to write results")
    parser.add_argument("-j", "--jobs", type=int, default=1,
                        help="Scan up to N targets in parallel (default 1). ZAP active scans stay serialized.")
    parser.add_argument("--no-report", action="store_true", help="Skip PDF generation")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default=None,
                        help="Exit with code 1 if any finding is at or above this severity. Useful as a CI gate.")
    args = parser.parse_args()

    targets = load_targets(args)
    os.makedirs(args.output_dir, exist_ok=True)
    config = load_config()
    severity_map = config.get('severity_map', {})

    zap_process = None
    try:
        # --- Phase 0: Boot ZAP daemon in the background (once for all targets) ---
        print("    [+] Booting background scanning engines...")
        zap_path = config.get('tools', {}).get('zap_path', 'zap.sh')
        zap_api_url = config.get('tools', {}).get('zap_api_url', 'http://localhost:8080')

        if not zap_path:
            # No zap_path means ZAP is externally managed (e.g. a separate
            # Docker container). We don't launch it ourselves, but it may
            # still be reachable over the network - check for that below.
            print("    [-] No zap_path configured - assuming ZAP is externally managed.")
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

        print(f"    [~] Waiting up to {ZAP_BOOT_TIMEOUT_SECONDS}s for ZAP to become ready at {zap_api_url}...")
        zap_available = zap_scanner.wait_for_zap(zap_api_url, max_wait=ZAP_BOOT_TIMEOUT_SECONDS)
        if zap_available:
            print("    [+] ZAP is ready.")
        else:
            print("    [!] ZAP did not become ready in time - ZAP scan phase will be skipped.")

        print(f"[*] Loaded {len(targets)} target(s).")
        zap_key = config.get('tools', {}).get('zap_api_key', '')

        # A ZAP daemon handles active scans best one at a time - serialize the
        # ZAP phase across parallel workers with a shared lock.
        zap_lock = threading.Lock() if args.jobs > 1 else None

        def _run_one(target):
            return scan_target(target, args, config, severity_map, zap_available,
                               zap_api_url, zap_key, zap_lock=zap_lock)

        print(f"[*] Scanning with {args.jobs} worker(s)...")
        results = dict(zip(targets, parallel_map(_run_one, targets, args.jobs)))

        all_findings = []
        last_report_path = None
        for target in targets:
            result = results[target]
            all_findings.extend(result['findings'])
            last_report_path = result['report_path'] or last_report_path
            print(f"[+] Target '{target}' done: {len(result['findings'])} finding(s).")

        print("\n[+] Pipeline execution complete!")
        if last_report_path:
            print(f"[+] Latest report: {last_report_path}")

        # --- Phase 5: CI severity gate (across all targets) ---
        if args.fail_on:
            worst = worst_finding_severity(all_findings)
            threshold = FAIL_SEVERITY_WEIGHTS[args.fail_on]
            if FAIL_SEVERITY_WEIGHTS.get(worst, 0) >= threshold:
                print(f"[!] --fail-on {args.fail_on} triggered: worst severity is '{worst.upper()}'.")
                return 1
            print(f"[+] --fail-on {args.fail_on} passed: worst severity is '{worst.upper()}'.")
        return 0

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
    sys.exit(main())