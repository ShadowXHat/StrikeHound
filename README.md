# 🐕‍🦺 StrikeHound

**StrikeHound** is a fully automated DevSecOps orchestration engine built in Python. It seamlessly coordinates industry-standard security tools to discover, scan, and report on web application vulnerabilities.

By acting as a central brain, StrikeHound eliminates manual scanning fatigue. It runs Discovery (Nmap), triggers Deep Scanning (Nuclei & OWASP ZAP), normalizes and deduplicates the data, and generates executive-ready PDF deliverables while alerting your team via Slack.

## ✨ Core Features
* **Intelligent Orchestration:** Automatically triggers web-scanners only if web ports (80/443) are discovered.
* **Background Daemon Management:** Boots and cleanly terminates OWASP ZAP in the background, even on failure.
* **Authenticated Scanning:** ZAP can scan authenticated web applications — form-based logins (login page + credentials) or static headers (`Authorization: Bearer ...`) — using ZAP contexts and users. Opt in via the `zap:` config block.
* **ZAP Automation Framework:** Emit a ZAP Automation plan (`zap.automation: true`) for complex auth (OAuth2/SAML) and run it one-shot with `zap -cmd -autorun`; results merge back into the pipeline.
* **Parallel Multi-Target Scanning:** `-l targets.txt -j 4` scans many hosts at once (ZAP active scans stay serialized).
* **Resume Support:** `--resume` skips targets already scanned (per-target marker files), so long runs can restart after a crash.
* **CI Seatbelt:** `--fail-on` (global) or `--policy` (per-target thresholds) gate the exit code for CI pipelines.
* **Data Normalization:** Parses complex XML and JSON outputs from multiple tools and maps them to a unified severity scale.
* **Smart Deduplication:** Identifies overlapping vulnerabilities caught by different tools using a deterministic, normalized fingerprint (title/host/port), keeps the highest severity, and is reproducible across runs and tools.
* **Executive PDF Reporting:** Generates color-coded, professional PDF reports with severity summaries + remediation guidance.
* **SARIF + JSON Output:** Every scan emits SARIF 2.1.0 (importable into GitHub code scanning) and full JSON.
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

You only need to run this once. To customize settings afterward, edit `config.yaml` directly.

| Key | Description |
|---|---|
| `tools.nmap_path` | Path to the `nmap` binary |
| `tools.nuclei_path` | Path to the `nuclei` binary |
| `tools.zap_path` | Path to `zap.sh` (used to auto-launch the daemon). Leave `""` if ZAP is externally managed (e.g. Docker) |
| `tools.zap_api_url` | Base URL where the ZAP daemon's API is reachable |
| `tools.zap_api_key` | ZAP API key (leave blank if `api.disablekey=true`) |
| `tools.slack_webhook` | Slack Incoming Webhook URL for scan-complete alerts |
| `zap.automation` | `false` = drive ZAP via REST API; `true` = write an Automation plan per target and print the `zap -cmd -autorun` command |
| `zap.ajax_spider` | Also run ZAP's headless-browser crawl (helps with SPAs & auth'd pages) |
| `zap.auth.method` | `none` (default), `form`, or `header` — see *Authenticated scans* below |
| `nuclei.*` | Tuning passed to Nuclei: `rate_limit` (req/s — Nuclei defaults to 150, too aggressive for most targets), `concurrency`, `bulk_size`, `timeout`, `retries`, and optional `tags`/`severity` template filters |
| `scan_profiles.*` | Nmap flag presets used by `-m/--profile` |
| `severity_map.*` | Maps each tool's native severity values to Critical/High/Medium/Low/Info |

> ⚠️ `config.yaml` is git-ignored on purpose — it will hold real credentials once configured. Never commit it.

### Authenticated scans

```yaml
zap:
  ajax_spider: false
  auth:
    method: form            # "form", "header", or "none"
    login_url: "https://app.example.com/login"
    username_field: "username"
    password_field: "password"
    login_request_data: ""  # optional; defaults to username={%username%}&password={%password%}
    username: "svc-audit"
    password: ""            # or export STRIKEHOUND_ZAP_PASSWORD
    header_name: "Authorization"
    header_value: ""        # or export STRIKEHOUND_ZAP_TOKEN
```

* **Secrets**: `STRIKEHOUND_ZAP_USERNAME`, `STRIKEHOUND_ZAP_PASSWORD`, `STRIKEHOUND_ZAP_TOKEN` environment variables override the config values — recommended for CI so credentials never sit in a file.
* **Header auth** needs no ZAP user (e.g. `Authorization: Bearer <token>` / API keys).
* If ZAP rejects auth setup (e.g. an older version with a different API shape), StrikeHound **degrades gracefully** to unauthenticated scanning with a clear warning rather than failing the whole run.

### ZAP Automation Framework (complex auth)

ZAP's modern recommended workflow is a one-shot automation plan, which handles OAuth2/SAML and other complex auth reliably:

```yaml
zap:
  automation: true
```

Then run StrikeHound — it writes `output/zap-plans/zap-plan-<target>.yaml` and prints the command, e.g.:

```bash
zap.sh -cmd -autorun output/zap-plans/zap-plan-example.com.yaml -port 8080 -config api.disablekey=true
```

After it finishes, re-run StrikeHound and the results in `output/zap-reports/zap-report.json` are merged back into the pipeline (SARIF/JSON/PDF + gates).

## 🚀 Usage

```bash
./scan.sh http://example.com quick
```

Or call the script directly for full control:
```bash
source venv/bin/activate
python3 strikehound.py -t http://example.com -m standard
```

Single target, or many via a file (one per line, `#` comments allowed):

```bash
python3 strikehound.py -l targets.txt -j 4 -m quick --resume
```

| Flag | Description | Default |
|---|---|---|
| `-t`, `--target` | Target IP or URL to scan | — |
| `-l`, `--targets-file` | File with one target per line (`#` comments + blank lines allowed) | — |
| `-m`, `--profile` | Nmap scan depth: `quick`, `standard`, `full` | `standard` |
| `-o`, `--output-dir` | Where to write the report and scan output | `./output` |
| `-j`, `--jobs` | Scan up to N targets in parallel (ZAP active scans stay serialized) | `1` |
| `--resume` | Skip targets with a completed-scan marker in `<output-dir>/.strikehound-done` | off |
| `--no-report` | Skip PDF generation | off |
| `--fail-on` | Exit 1 if any finding is at/above `critical`/`high`/`medium`/`low`/`info` (global gate) | off |
| `--policy` | YAML file of per-target thresholds — see below (mutually exclusive with `--fail-on`) | off |

### Outputs

Every scan always emits two machine-readable files next to the optional PDF:
`StrikeHound_Report_<target>.sarif` (SARIF 2.1.0, importable into GitHub code
scanning) and `StrikeHound_Report_<target>.json` (full deduplicated findings).

### CI gates

Global gate (any High or Critical fails the build):

```bash
python3 strikehound.py -t http://staging.example.com -m quick --fail-on high
```

Per-target policies — `policies.yaml`:

```yaml
default: high        # everything must not exceed High
staging.example.com: medium   # this host must not exceed Medium
prod.example.com: critical
```

```bash
python3 strikehound.py -l targets.txt --policy policies.yaml
```

Exit 1 if any target's worst finding is at/above its threshold. Hosts match on
exact name or parent-domain suffix (`app.example.com` matches `example.com`).

### CI (GitHub Actions)

Pushes/PRs run the unit suite, then a live scan against a test target. You can
also run the `security-audit` job manually with **Run workflow → inputs**
(`target`, `profile`, `fail_on`) instead of the default test target.

## 🧪 Testing

StrikeHound has a unit test suite covering the core logic (deduplication, severity mapping, target validation, ZAP auth/plan generation/report parsing, and scanner modules) using mocked tool/API responses — no live scan or external network access required to run it.

```bash
source venv/bin/activate
pip install -r requirements-dev.txt
python3 -m pytest tests/ -v
```

### Verifying ZAP auth against a real daemon

Unit tests mock ZAP's API. To verify the auth/context flow against your actual
ZAP version (recommended before trusting authenticated findings in production):

```bash
# Kali / Debian — boots ZAP if needed, runs the checks, shuts it back down
./scripts/verify_zap_auth.sh
./scripts/verify_zap_auth.sh \
    --target https://app.example.com \
    --username svc-audit --password 's3cret' \
    --login-url https://app.example.com/login
```

Or run the Python checker directly against a ZAP daemon you manage yourself:

```bash
python3 scripts/zap_env_check.py --url http://localhost:8080 --target https://example.com
python3 scripts/zap_env_check.py --url http://localhost:8080 --target https://example.com \
    --username alice --password 's3cret' --login-url https://example.com/login
```

Exit code 0 = reachable + context/auth working; 1 = failure (it tells you which step).

> **Authenticated crawling detail:** the plain ZAP spider API has no user
> parameter, so form-auth scans crawl through `spider/action/scanAsUser`
> (context + numeric user id) and run the active scan as that user
> (`ascan/action/scan` with the user id — *not* the username). If your ZAP
> version rejects either call, StrikeHound logs it and continues
> unauthenticated rather than crashing.

## ⚠️ Legal Disclaimer

This tool is provided for educational purposes only and for use in authorized security auditing environments.

StrikeHound and its author (ShadowXHat) are not responsible for any misuse, damage, or illegal activities caused by this software. Use this tool only on infrastructure where you have explicit, written permission to perform security testing.

Always stay within scope and follow responsible disclosure guidelines.