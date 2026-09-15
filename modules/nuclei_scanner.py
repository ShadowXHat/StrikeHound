import subprocess
import json
import os

from .validators import is_safe_target

# Sensible defaults for Nuclei. The tool ships with an aggressive default
# of 150 req/s which gets production targets/WAFs to ban your IP quickly.
DEFAULT_RATE_LIMIT = 50
DEFAULT_CONCURRENCY = 25
DEFAULT_BULK_SIZE = 10
DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 1
DEFAULT_SCAN_TIMEOUT = 600


def run_scan(target: str, nuclei_path: str = "nuclei", output_dir: str = "output",
             rate_limit: int = DEFAULT_RATE_LIMIT, concurrency: int = DEFAULT_CONCURRENCY,
             bulk_size: int = DEFAULT_BULK_SIZE, timeout: int = DEFAULT_TIMEOUT,
             retries: int = DEFAULT_RETRIES, tags: str = "", severity: str = "",
             scan_timeout: int = DEFAULT_SCAN_TIMEOUT) -> list:
    """Runs Nuclei and parses the JSONL output.

    Security note: this builds an argument list and calls subprocess.run()
    without shell=True, so shell metacharacters in `target` can't reach a
    shell interpreter. strikehound.py already validates the target before
    calling this function; we re-check here as defense in depth in case
    this function is ever called directly.
    """
    if not is_safe_target(target):
        print(f"    [!] Refusing to scan unsafe-looking target: {target!r}")
        return []

    print(f"    [>] Executing Nuclei against {target}")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "nuclei_result.jsonl")

    # Build the Nuclei command. Rate limiting and template filters keep the
    # scan respectful of the target and cut false-positive noise.
    cmd = [
        nuclei_path,
        "-target", target,
        "-jsonl", "-o", output_file,
        "-silent",
        "-rate-limit", str(rate_limit),
        "-c", str(concurrency),
        "-bulk-size", str(bulk_size),
        "-timeout", str(timeout),
        "-retries", str(retries),
    ]
    if tags:
        cmd += ["-tags", tags]
    if severity:
        cmd += ["-severity", severity]

    findings = []

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_timeout)
        if result.returncode != 0:
            print(f"    [!] Nuclei returned exit code {result.returncode}; parsing partial output if present.")

        # Parse the JSONL output
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        info = data.get("info", {})
                        classification = info.get("classification", {}) or {}

                        scheme_port = 443 if str(target).lower().startswith("https") else 80
                        raw_port = data.get("port")
                        try:
                            port = int(raw_port) if raw_port else scheme_port
                        except (TypeError, ValueError):
                            port = scheme_port

                        findings.append({
                            "tool": "nuclei",
                            "title": info.get("name", "Unknown Vulnerability"),
                            "template_id": data.get("template-id"),
                            "severity": info.get("severity", "info"),
                            "target": data.get("host", target),
                            "port": port,
                            "matched_at": data.get("matched-at"),
                            "description": info.get("description", "No description provided."),
                            "remediation": info.get("remediation", "No remediation provided."),
                            "reference": info.get("reference", []),
                            "cve": classification.get("cve-2024") or classification.get("cve", []),
                            "cwe": classification.get("cwe", []),
                        })
            print(f"        -> Nuclei finished: Found {len(findings)} issues.")
    except FileNotFoundError:
        print(f"    [!] Error: Nuclei binary not found at '{nuclei_path}'.")
    except subprocess.TimeoutExpired:
        print(f"    [!] Nuclei scan against {target} timed out after {scan_timeout}s.")
    except Exception as e:
        print(f"    [!] Nuclei execution error: {e}")

    return findings
