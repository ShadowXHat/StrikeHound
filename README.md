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
