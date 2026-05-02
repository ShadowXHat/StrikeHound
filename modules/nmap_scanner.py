import nmap
import os

def run_scan(target: str, profile_flags: str) -> dict:
    """
    Executes the Nmap scan and returns parsed open ports.
    Returns: { port_number: { 'state': state, 'service': service, 'version': version } }
    """
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
    
    # Parse the results into our standard dictionary format [cite: 31]
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
