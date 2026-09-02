import subprocess
import re

from .validators import is_safe_target

# Known-weak SSH algorithms, grouped by category. Not an exhaustive
# cryptographic audit - this flags widely-recognized deprecated/weak
# choices (SHA-1 based KEX, CBC-mode ciphers, RC4/3DES, MD5/SHA-1 MACs,
# and legacy host key types) that show up in most hardening guides
# (e.g. Mozilla OpenSSH guidelines, NIST SP 800-131A).
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-",
    "gss-group14-sha1-",
    "rsa1024-sha1",
}
WEAK_HOST_KEY = {
    "ssh-dss",
    "ssh-rsa",  # SHA-1 signature scheme, deprecated by OpenSSH
}
WEAK_ENCRYPTION = {
    "arcfour", "arcfour128", "arcfour256",
    "3des-cbc", "des-cbc", "blowfish-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "cast128-cbc", "rijndael-cbc@lysator.liu.se",
    "none",
}
WEAK_MAC = {
    "hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com",
    "hmac-sha1-96", "hmac-sha1-96-etm@openssh.com",
    "none",
}

# nmap's ssh2-enum-algos output groups algorithms under headers like:
#   |   kex_algorithms: (9)
#   |       curve25519-sha256
#   |       ...
#   |   encryption_algorithms: (6)
_CATEGORY_HEADER_RE = re.compile(r"^\|\s+(\w+):\s*\(\d+\)")
_ALGO_LINE_RE = re.compile(r"^\|\s+([\w@.\-]+)\s*$")

_CATEGORY_TO_WEAK_SET = {
    "kex_algorithms": WEAK_KEX,
    "server_host_key_algorithms": WEAK_HOST_KEY,
    "encryption_algorithms": WEAK_ENCRYPTION,
    "mac_algorithms": WEAK_MAC,
}

_CATEGORY_LABEL = {
    "kex_algorithms": "key exchange algorithm",
    "server_host_key_algorithms": "host key algorithm",
    "encryption_algorithms": "encryption cipher",
    "mac_algorithms": "MAC algorithm",
}


def _parse_algorithms_by_category(nmap_output: str) -> dict:
    """
    Parses nmap's ssh2-enum-algos script output into
    {category_name: [algorithm, ...]}.
    """
    categories = {}
    current_category = None

    for line in nmap_output.splitlines():
        header_match = _CATEGORY_HEADER_RE.match(line)
        if header_match:
            current_category = header_match.group(1)
            categories[current_category] = []
            continue

        if current_category:
            algo_match = _ALGO_LINE_RE.match(line)
            if algo_match:
                categories[current_category].append(algo_match.group(1))
            elif line.strip() == "" or not line.startswith("|"):
                # Blank line or non-pipe line ends the algorithm block
                current_category = None

    return categories


def run_scan(target: str, port: int = 22) -> list:
    """
    Runs an SSH configuration audit using Nmap's ssh2-enum-algos NSE
    script, then parses the returned algorithm lists to flag any weak
    key exchange, host key, encryption, or MAC algorithms the server
    still offers.
    """
    if not is_safe_target(target):
        print(f"    [!] Refusing to scan unsafe-looking target: {target!r}")
        return []

    print(f"    [>] Triggering SSH Audit against {target}:{port}")
    findings = []

    cmd = ["nmap", "-p", str(port), "--script", "ssh2-enum-algos", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
    except subprocess.TimeoutExpired:
        print(f"    [!] SSH Audit against {target}:{port} timed out.")
        return []
    except Exception as e:
        print(f"    [!] SSH Audit execution error: {e}")
        return []

    if "ssh2-enum-algos" not in result.stdout:
        print("        -> SSH Audit finished: script did not return algorithm data.")
        return []

    categories = _parse_algorithms_by_category(result.stdout)

    for category, algorithms in categories.items():
        weak_set = _CATEGORY_TO_WEAK_SET.get(category)
        if not weak_set:
            continue

        label = _CATEGORY_LABEL.get(category, category)
        weak_found = [algo for algo in algorithms if algo in weak_set]

        for algo in weak_found:
            findings.append({
                "tool": "ssh_audit",
                "title": f"Weak SSH {label} offered: {algo}",
                "severity": "medium" if category == "encryption_algorithms" else "low",
                "target": target,
                "port": port,
                "description": (
                    f"The SSH server at {target}:{port} offers the {label} '{algo}', "
                    "which is considered weak or deprecated. Consider disabling it in "
                    "the server's SSH configuration (e.g. sshd_config)."
                ),
            })

    if not findings:
        findings.append({
            "tool": "ssh_audit",
            "title": "SSH Algorithms Enumerated - No Known-Weak Algorithms Found",
            "severity": "info",
            "target": target,
            "port": port,
            "description": (
                "SSH algorithm enumeration completed successfully and no algorithms "
                "matching our known-weak list were offered by the server."
            ),
        })

    print(f"        -> SSH Audit finished: {len(findings)} finding(s).")
    return findings
