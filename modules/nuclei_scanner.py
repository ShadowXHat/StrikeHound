import subprocess
import json
import os

from .validators import is_safe_target


def run_scan(target: str, nuclei_path: str = "nuclei") -> list:
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
    output_file = "output/nuclei_result.jsonl"

    # Build the Nuclei command
    cmd = [
        nuclei_path,
        "-target", target,
        "-jsonl", "-o", output_file,
        "-silent" # Keep stdout clean
    ]

    findings = []

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        # Parse the JSONL output
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        findings.append({
                            "tool": "nuclei",
                            "title": data.get("info", {}).get("name", "Unknown Vulnerability"),
                            "severity": data.get("info", {}).get("severity", "info"),
                            "target": data.get("host", target),
                            "description": data.get("info", {}).get("description", "No description provided.")
                        })
            print(f"        -> Nuclei finished: Found {len(findings)} issues.")
    except FileNotFoundError:
        print(f"    [!] Error: Nuclei binary not found at '{nuclei_path}'.")
    except subprocess.TimeoutExpired:
        print(f"    [!] Nuclei scan against {target} timed out after 600s.")
    except Exception as e:
        print(f"    [!] Nuclei execution error: {e}")

    return findings
