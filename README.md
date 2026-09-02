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
* Python 3.8+
* [Nmap](https://nmap.org/)
* [Nuclei](https://github.com/projectdiscovery/nuclei)
* [OWASP ZAP](https://www.zaproxy.org/) (local installation, or via `compose.yml`)

## 🚀 Installation & Setup

```bash
git clone https://github.com/ShadowXHat/StrikeHound.git
cd StrikeHound
pip install -r requirements.txt
```

### Configuration

Before your first run, create your local config file from the template:

```bash
cp config.example.yaml config.yaml
```

Then edit `config.yaml`:

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
python3 strikehound.py -t http://example.com -m standard
```

| Flag | Description | Default |
|---|---|---|
| `-t`, `--target` | Target IP or URL to scan (required) | — |
| `-m`, `--profile` | Nmap scan depth: `quick`, `standard`, `full` | `standard` |
| `-o`, `--output-dir` | Where to write the report and scan output | `./output` |
| `--no-report` | Skip PDF generation | off |

### Docker Compose

A `compose.yml` is included to run ZAP + StrikeHound together:

```bash
docker compose up
```

## ⚠️ Legal Disclaimer

This tool is provided for educational purposes only and for use in authorized security auditing environments.

StrikeHound and its author (ShadowXHat) are not responsible for any misuse, damage, or illegal activities caused by this software. Use this tool only on infrastructure where you have explicit, written permission to perform security testing.

Always stay within scope and follow responsible disclosure guidelines.
