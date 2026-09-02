# 🐕‍🦺 StrikeHound

**StrikeHound** is a fully automated DevSecOps orchestration engine built in Python. It seamlessly coordinates industry-standard security tools to discover, scan, and report on web application vulnerabilities.

By acting as a central brain, StrikeHound eliminates manual scanning fatigue. It runs Discovery (Nmap), triggers Deep Scanning (Nuclei & OWASP ZAP), normalizes and deduplicates the data, and generates executive-ready PDF deliverables while alerting your team via Slack.

## ✨ Core Features
* **Intelligent Orchestration:** Automatically triggers web-scanners only if web ports (80/443) are discovered.
* **Background Daemon Management:** Boots and cleanly terminates OWASP ZAP in the background, even on failure.
* **Data Normalization:** Parses complex XML and JSON outputs from multiple tools and maps them to a unified severity scale.
* **Smart Deduplication:** Identifies overlapping vulnerabilities caught by different tools to reduce alert fatigue.
* **Executive PDF Reporting:** Generates color-coded, professional PDF reports with infrastructure summaries.
* **Slack Integration:** Fires real-time webhook alerts to your security team upon scan completion.

## 🛠️ Prerequisites

* A Debian/Kali-based Linux system (the setup script uses `apt`)
* Python 3.8+
* `sudo` access (to install nmap/nuclei/ZAP if not already present)

Everything else (Nmap, Nuclei, OWASP ZAP, Python packages) is checked for and installed automatically by `setup.sh` below.

## 🚀 Installation & Setup

```bash
git clone https://github.com/ShadowXHat/StrikeHound.git
cd StrikeHound
chmod +x setup.sh scan.sh
./setup.sh
```

`setup.sh` will:
* Check for nmap, nuclei, and OWASP ZAP - installing any that are missing
* Create a Python virtual environment and install dependencies into it
* Auto-generate `config.yaml` with the correct paths for your system

You only need to run this once. To customize settings afterward (e.g. add a Slack webhook), edit `config.yaml` directly.

### Alternative: Docker

If you'd rather not install tools directly on your system (e.g. running on a non-Kali machine, or want isolation), a `Dockerfile` and `compose.yml` are also included:

```bash
docker compose build
docker compose run --rm strikehound -t http://example.com -m standard
```

This is optional - the native `setup.sh` path above is recommended if you're already on Kali or a similar pentesting distro, since it uses tools you likely already have instead of duplicating them inside a container.

| Key | Description |
|---|---|
| `tools.nmap_path` | Path to the `nmap` binary |
| `tools.nuclei_path` | Path to the `nuclei` binary |
| `tools.zap_path` | Path to `zap.sh` (used to auto-launch the daemon) |
| `tools.zap_api_url` | Base URL where the ZAP daemon's API is reachable |
| `tools.zap_api_key` | ZAP API key (leave blank if `api.disablekey=true`) |
| `tools.slack_webhook` | Slack Incoming Webhook URL for scan-complete alerts |
| `scan_profiles.*` | Nmap flag presets used by `-m/--profile` |
| `severity_map.*` | Maps each tool's native severity values to Critical/High/Medium/Low/Info |

> ⚠️ `config.yaml` is git-ignored on purpose — it will hold real credentials once configured. Never commit it.

## 🚀 Usage

```bash
./scan.sh http://example.com quick
```

Or call the script directly for full control:
```bash
source venv/bin/activate
python3 strikehound.py -t http://example.com -m standard
```

| Flag | Description | Default |
|---|---|---|
| `-t`, `--target` | Target IP or URL to scan (required) | — |
| `-m`, `--profile` | Nmap scan depth: `quick`, `standard`, `full` | `standard` |
| `-o`, `--output-dir` | Where to write the report and scan output | `./output` |
| `--no-report` | Skip PDF generation | off |

### Docker Compose (optional)

A `compose.yml` is also included if you'd rather run via Docker instead of `setup.sh` — see the Installation section above.

## ⚠️ Legal Disclaimer

This tool is provided for educational purposes only and for use in authorized security auditing environments.

StrikeHound and its author (ShadowXHat) are not responsible for any misuse, damage, or illegal activities caused by this software. Use this tool only on infrastructure where you have explicit, written permission to perform security testing.

Always stay within scope and follow responsible disclosure guidelines.
