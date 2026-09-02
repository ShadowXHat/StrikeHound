#!/bin/bash
#
# StrikeHound setup script.
# Checks for required tools, installs anything missing, sets up a Python
# virtual environment, and auto-generates config.yaml. Run this once:
#
#   ./setup.sh
#
set -e

echo "=== StrikeHound Setup ==="
echo

# --- 1. Python ---
if ! command -v python3 &>/dev/null; then
    echo "[!] python3 not found. Install it first (it should be preinstalled on Kali)."
    exit 1
fi
echo "[+] python3 found: $(command -v python3)"

# --- 2. nmap ---
if ! command -v nmap &>/dev/null; then
    echo "[*] nmap not found - installing..."
    sudo apt-get update -qq && sudo apt-get install -y nmap
else
    echo "[+] nmap found: $(command -v nmap)"
fi

# --- 3. nuclei ---
if ! command -v nuclei &>/dev/null; then
    echo "[*] nuclei not found - installing..."
    if apt-cache show nuclei &>/dev/null 2>&1; then
        sudo apt-get install -y nuclei
    else
        echo "    Not available via apt - installing with Go instead."
        if ! command -v go &>/dev/null; then
            sudo apt-get install -y golang-go
        fi
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        sudo cp "$(go env GOPATH)/bin/nuclei" /usr/local/bin/nuclei
    fi
else
    echo "[+] nuclei found: $(command -v nuclei)"
fi

# --- 4. OWASP ZAP ---
ZAP_PATH=""
if command -v zaproxy &>/dev/null; then
    ZAP_PATH="$(command -v zaproxy)"
elif command -v zap.sh &>/dev/null; then
    ZAP_PATH="$(command -v zap.sh)"
else
    echo "[!] OWASP ZAP not found."
    read -r -p "    Install it now via apt? (y/N) " yn
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        sudo apt-get install -y zaproxy
        ZAP_PATH="$(command -v zaproxy || true)"
    else
        echo "    Skipping - ZAP scanning will be disabled until you install it and re-run setup."
    fi
fi
if [ -n "$ZAP_PATH" ]; then
    echo "[+] ZAP found: $ZAP_PATH"
fi

# --- 5. Python virtual environment ---
if [ ! -d venv ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "[+] Python dependencies installed into ./venv"

# --- 6. config.yaml ---
if [ ! -f config.yaml ]; then
    echo "[*] Generating config.yaml with detected tool paths..."
    NMAP_PATH="$(command -v nmap || echo /usr/bin/nmap)"
    NUCLEI_PATH="$(command -v nuclei || echo /usr/local/bin/nuclei)"
    cat > config.yaml <<EOF
tools:
  nmap_path: ${NMAP_PATH}
  nuclei_path: ${NUCLEI_PATH}
  zap_path: "${ZAP_PATH}"
  zap_api_url: http://localhost:8080
  zap_api_key: ""
  slack_webhook: ""

scan_profiles:
  quick: '-F -T4'
  standard: '-sV -sC -T4'
  full: '-A -T3 -p-'

severity_map:
  nuclei:
    critical: Critical
    high: High
    medium: Medium
    low: Low
  zap:
    3: Critical
    2: High
    1: Medium
    0: Low
  ssh_audit:
    low: Low
EOF
    echo "[+] config.yaml created."
else
    echo "[+] config.yaml already exists - leaving it untouched."
fi

mkdir -p output

echo
echo "=== Setup complete! ==="
echo "Run a scan with:"
echo "  ./scan.sh http://example.com quick"
