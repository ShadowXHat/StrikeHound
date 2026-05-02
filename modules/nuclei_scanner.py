import subprocess
import json
import os

def run_scan(target: str, nuclei_path: str = "nuclei") -> list:
    """Runs Nuclei and parses the JSONL output."""
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
        subprocess.run(cmd, capture_output=True, text=True)
        
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
    except Exception as e:
        print(f"    [!] Nuclei execution error: {e}")
        
    return findings
