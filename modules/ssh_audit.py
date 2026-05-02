import subprocess

def run_scan(target: str, port: int = 22) -> list:
    """Runs an SSH configuration audit using Nmap's NSE scripts."""
    print(f"    [>] Triggering SSH Audit against {target}:{port}")
    findings = []
    
    # We use Nmap's ssh2-enum-algos script to check the SSH configuration
    cmd = ["nmap", "-p", str(port), "--script", "ssh2-enum-algos", target]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Simple parsing logic: if the script ran, we log it as an informational finding to review
        if "ssh2-enum-algos" in result.stdout:
            findings.append({
                "tool": "ssh_audit",
                "title": "SSH Algorithms Exposed",
                "severity": "Low", # We will map this!
                "target": target,
                "port": port,
                "description": "Successfully enumerated SSH algorithms. Review the configuration to ensure weak ciphers (e.g., arcfour, 3des-cbc) are disabled."
            })
        print(f"        -> SSH Audit finished: Found {len(findings)} issues.")
        
    except Exception as e:
        print(f"    [!] SSH Audit execution error: {e}")
        
    return findings
