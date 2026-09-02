import nmap
import os

from .validators import is_safe_target


def run_scan(target: str, profile_flags: str) -> dict:
    """
    Executes the Nmap scan and returns parsed open ports.
    Returns: { port_number: { 'state': state, 'service': service, 'version': version } }

    Security note: python-nmap invokes nmap via subprocess with an argument
    list (no shell=True), so classic shell metacharacter injection (`;`,
    `|`, `` ` ``, etc.) is not possible here. However, python-nmap does
    shlex.split() the 'hosts' string internally before passing it to nmap,
    so a target containing whitespace could be split into extra nmap
    arguments/flags (e.g. "target.com --script=malicious"). strikehound.py
    already validates the target via validators.is_safe_target() before
    calling this function, but we re-check here too - this function may be
    called directly (e.g. from other code or tests) without going through
    that upstream check, and defense in depth costs us one cheap call.
    """
    if not is_safe_target(target):
        print(f"    [!] Refusing to scan unsafe-looking target: {target!r}")
        return {}

    print(f"    [>] Executing Nmap against {target} with flags: {profile_flags}")

    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()

    # Ensure output directory exists for the XML dump
    os.makedirs('output', exist_ok=True)

    try:
        # Run the scan WITHOUT the -oX flag in the arguments
        nm.scan(hosts=target, arguments=profile_flags)

        # Manually save the XML output to satisfy our pipeline documentation
        xml_output = nm.get_nmap_last_output()
        if isinstance(xml_output, bytes):
            xml_output = xml_output.decode('utf-8')

        with open("output/nmap_result.xml", "w") as f:
            f.write(xml_output)

    except nmap.PortScannerError as e:
        print(f"    [!] Nmap error: {e}")
        return {}
    except Exception as e:
        print(f"    [!] Unexpected error: {e}")
        return {}

    parsed_results = {}

    # Parse the results into our standard dictionary format
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                if state == 'open':
                    parsed_results[port] = {
                        'state': state,
                        'service': nm[host][proto][port]['name'],
                        'version': nm[host][proto][port]['version']
                    }
                    print(f"        -> Discovered open port: {port}/tcp ({nm[host][proto][port]['name']})")

    return parsed_results
