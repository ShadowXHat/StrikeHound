import yaml

def load_severity_map(config_path="config.yaml"):
    """Loads the severity mapping from the config file."""
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            return config.get('severity_map', {})
    except Exception as e:
        print(f"    [!] Error loading severity map: {e}")
        return {}

def normalize(tool_name: str, raw_severity) -> str:
    """
    Normalizes a tool-specific severity into a standard string 
    (Critical, High, Medium, Low, Info).
    """
    severity_map = load_severity_map()
    
    if tool_name not in severity_map:
        return "Info" # Default fallback
        
    tool_map = severity_map[tool_name]
    
    # Handle integer-based severities (like ZAP) vs string-based (like Nuclei)
    if isinstance(raw_severity, str):
        raw_severity = raw_severity.lower()
        
    return tool_map.get(raw_severity, "Info")
