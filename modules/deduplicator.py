def get_severity_weight(severity: str) -> int:
    """Assigns a numerical weight to severities to act as a pseudo-CVSS for deduplication."""
    weights = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Info": 0
    }
    return weights.get(severity, 0)

def deduplicate(findings: list) -> list:
    """
    Removes duplicate findings across different tools.
    Prefers the finding with the higher severity if duplicates exist.
    """
    print(f"    [>] Running deduplication on {len(findings)} raw findings...")
    seen = {}
    
    for f in findings:
        title = f.get("title", "Unknown")
        target = f.get("target", "Unknown")
        # Default port to 80/443 logic if not explicitly set by the web scanner
        port = str(f.get("port", "web")) 
        
        # Create a unique composite key hash
        key = hash(title + target + port)
        
        current_weight = get_severity_weight(f.get("severity", "Info"))
        
        # If we haven't seen this finding, OR if the current one has a higher severity, keep it
        if key not in seen:
            seen[key] = f
        else:
            existing_weight = get_severity_weight(seen[key].get("severity", "Info"))
            if current_weight > existing_weight:
                seen[key] = f
                
    deduplicated_list = list(seen.values())
    print(f"        -> Deduplication complete. {len(deduplicated_list)} unique findings retained.")
    
    return deduplicated_list
