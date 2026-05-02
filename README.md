# 🐕‍🦺 StrikeHound

**StrikeHound** is a fully automated DevSecOps orchestration engine built in Python. It seamlessly coordinates industry-standard security tools to discover, exploit, and report on web application vulnerabilities.

By acting as a central brain, StrikeHound eliminates manual scanning fatigue. It runs Discovery (Nmap), triggers parallel Deep Scanning (Nuclei & OWASP ZAP), normalizes and deduplicates the data, and generates executive-ready PDF deliverables while alerting your team via Slack.

## ✨ Core Features
* **Intelligent Orchestration:** Automatically triggers web-scanners only if web-ports (80/443) are discovered.
* **Background Daemon Management:** Silently boots and cleanly terminates Java-based tools (OWASP ZAP) in the background.
* **Data Normalization:** Parses complex XML and JSON outputs from multiple tools and maps them to a unified severity scale.
* **Smart Deduplication:** Identifies overlapping vulnerabilities caught by different tools to reduce alert fatigue.
* **Executive PDF Reporting:** Generates color-coded, professional PDF reports complete with infrastructure summaries and remediation steps.
* **Slack Integration:** Fires real-time webhook alerts to your security team upon scan completion.

## 🛠️ Prerequisites
To run StrikeHound, you must have the following installed on your system:
* Python 3.8+
* [Nmap](https://nmap.org/)
* [Nuclei](https://github.com/projectdiscovery/nuclei)
* [OWASP ZAP](https://www.zaproxy.org/) (Local installation)

## 🚀 Installation & Setup

1. **Clone the repository**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/StrikeHound.git](https://github.com/YOUR_USERNAME/StrikeHound.git)
   cd StrikeHound
## 🚀 Usage

### 1. Setup Configuration
Before your first run, you must create your local config file:
```bash
cp config.example.yaml config.yaml
python3 strikehound.py -t [http://example.com](http://example.com) -m standard

---

## ⚠️ Legal Disclaimer

This tool is provided for **educational purposes only** and for use in **authorized security auditing** environments. 

**StrikeHound** and its author (**ShadowXHat**) are not responsible for any misuse, damage, or illegal activities caused by this software. Use this tool only on infrastructure where you have explicit, written permission to perform security testing. Performing unauthorized scans against third-party networks can lead to severe legal consequences.

**Always stay within scope and follow responsible disclosure guidelines.**
