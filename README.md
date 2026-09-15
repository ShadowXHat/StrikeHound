<div align="center">

# 🐕‍🦺 StrikeHound

**A fully automated DevSecOps orchestration engine for web application security.**

StrikeHound coordinates industry-standard offensive-security tools into a single,
repeatable pipeline — discover, scan, correlate, and report — so you can move
from a bare hostname to an executive-ready deliverable in one command.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform: Kali / Debian](https://img.shields.io/badge/platform-Kali%20%7C%20Debian-557C94.svg)](#-prerequisites)
[![Tests: 118 passing](https://img.shields.io/badge/tests-118%20passing-brightgreen.svg)](#-testing)

</div>

---

## 📖 Table of Contents

- [Why StrikeHound](#-why-strikehound)
- [How It Works](#-how-it-works)
- [Core Features](#-core-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#%EF%B8%8F-configuration)
  - [Authenticated Scans](#authenticated-scans)
  - [ZAP Automation Framework](#zap-automation-framework-complex-auth)
- [Usage](#-usage)
  - [Outputs](#outputs)
  - [CI Gates](#ci-gates)
  - [GitHub Actions](#ci-github-actions)
- [Project Layout](#-project-layout)
- [Testing](#-testing)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)

---

## 🎯 Why StrikeHound

Running `nmap`, `nuclei`, and `ZAP` by hand is slow, inconsistent, and easy to
get wrong. StrikeHound turns that ad-hoc process into a **single, deterministic
pipeline**:

- **One command** replaces a dozen manual tool invocations.
- **Normalized data** — every tool's output is mapped to a unified severity scale.
- **No duplicate noise** — overlapping findings are collapsed deterministically.
- **CI-ready** — machine-readable exits and artifacts drop straight into a pipeline.

---

## 🔄 How It Works

```
   target(s)
       │
       ▼
 ┌─────────────────┐
 │   Discovery     │   Nmap — quick / standard / full profiles
 └────────┬────────┘
          │  web port 80/443 open?
          ▼
 ┌─────────────────┐
 │  Deep Scanning  │   Nuclei  +  OWASP ZAP
 │                 │   ZAP: spider → (ajax spider) → active scan
 └────────┬────────┘
          │  (optional: SSH audit)
          ▼
 ┌─────────────────┐
 │ Normalize &     │   severity mapping · deterministic cross-tool dedup
 │ Deduplicate     │
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │   Reporting     │   PDF · SARIF · JSON · Slack · CI exit gate
 └─────────────────┘
```

ZAP is booted in the background and cleanly terminated even on failure, and web
scanners are only triggered when a web port is actually discovered — no wasted
cycles.

---

## ✨ Core Features

| | Feature | Description |
|---|---|---|
| 🧠 | **Intelligent Orchestration** | Triggers web scanners only when web ports (80/443) are discovered. |
| ♻️ | **Daemon Lifecycle** | Boots and cleanly terminates OWASP ZAP in the background, even on failure. |
| 🔐 | **Authenticated Scanning** | ZAP scans behind logins — form-based auth or static headers (`Authorization: Bearer …`) using ZAP contexts and users. |
| 🤖 | **ZAP Automation Framework** | Emits an Automation plan (`zap.automation: true`) for complex auth (OAuth2/SAML) and runs it via `zap -cmd -autorun`; results merge back. |
| ⚡ | **Parallel Multi-Target** | `-l targets.txt -j 4` scans many hosts at once (ZAP active scans stay serialized). |
| 🔁 | **Resume Support** | `--resume` skips already-scanned targets via per-target markers, so long runs survive a crash. |
| 🚦 | **CI Seatbelt** | `--fail-on` (global) or `--policy` (per-target thresholds) gate the exit code. |
| 🧩 | **Data Normalization** | Parses XML/JSON from multiple tools into a unified severity scale. |
| 🧬 | **Smart Deduplication** | Deterministic, normalized fingerprints (title/host/port) keep the highest severity — reproducible across runs and tools. |
| 📄 | **Executive PDF Reporting** | Color-coded PDF reports with severity summaries and remediation guidance. |
| 🧾 | **SARIF + JSON Output** | Every scan emits SARIF 2.1.0 (GitHub code scanning) plus full JSON. |
| 💬 | **Slack Alerts** | Real-time webhook notifications on scan completion. |

---

## 🛠️ Prerequisites

- A **Debian/Kali-based Linux** system (the setup script uses `apt`)
- **Python 3.8+**
- **`sudo` access** (to install `nmap` / `nuclei` / ZAP when missing)

Everything else — Nmap, Nuclei, OWASP ZAP, and Python packages — is detected and
installed for you by `setup.sh`.

---

## 🚀 Installation

```bash
git clone https://github.com/ShadowXHat/StrikeHound.git
cd StrikeHound
chmod +x setup.sh scan.sh
./setup.sh
```

`setup.sh` will:

1. Check for `nmap`, `nuclei`, and OWASP ZAP — installing anything missing.
2. Create a Python virtual environment and install dependencies into it.
3. Auto-generate `config.yaml` with the correct paths for your system.

Run it once. To customize afterwards, edit `config.yaml` directly.

---

## ⚙️ Configuration

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
| `zap.auth.method` | `none` (default), `form`, or `header` — see [Authenticated Scans](#authenticated-scans) |
| `nuclei.*` | Tuning passed to Nuclei: `rate_limit` (req/s — Nuclei defaults to 150, too aggressive for most targets), `concurrency`, `bulk_size`, `timeout`, `retries`, and optional `tags`/`severity` filters |
| `scan_profiles.*` | Nmap flag presets used by `-m/--profile` |
| `severity_map.*` | Maps each tool's native severity values to Critical/High/Medium/Low/Info |

> ⚠️ **`config.yaml` is git-ignored on purpose** — it holds real credentials once
> configured. **Never commit it.**

### Authenticated Scans

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

- **Secrets** — the `STRIKEHOUND_ZAP_USERNAME`, `STRIKEHOUND_ZAP_PASSWORD`, and
  `STRIKEHOUND_ZAP_TOKEN` environment variables override config values. Recommended
  for CI so credentials never sit in a file.
- **Header auth** needs no ZAP user (e.g. `Authorization: Bearer <token>` / API keys).
- If ZAP rejects auth setup (e.g. an older version with a different API shape),
  StrikeHound **degrades gracefully** to unauthenticated scanning with a clear
  warning rather than failing the whole run.

### ZAP Automation Framework (Complex Auth)

ZAP's modern recommended workflow is a one-shot automation plan, which handles
OAuth2/SAML and other complex auth reliably:

```yaml
zap:
  automation: true
```

Then run StrikeHound — it writes `output/zap-plans/zap-plan-<target>.yaml` and
prints the command, e.g.:

```bash
zap.sh -cmd -autorun output/zap-plans/zap-plan-example.com.yaml -port 8080 -config api.disablekey=true
```

After it finishes, re-run StrikeHound and the results in
`output/zap-reports/zap-report.json` are merged back into the pipeline
(SARIF/JSON/PDF + gates).

---

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
| `--policy` | YAML file of per-target thresholds (mutually exclusive with `--fail-on`) | off |

### Outputs

Every scan always emits two machine-readable files next to the optional PDF:

| File | Format | Use |
|---|---|---|
| `StrikeHound_Report_<target>.sarif` | SARIF 2.1.0 | Importable into GitHub code scanning |
| `StrikeHound_Report_<target>.json` | JSON | Full deduplicated findings |
| `StrikeHound_Report_<target>.pdf` | PDF | Executive deliverable (unless `--no-report`) |

### CI Gates

Global gate — any High or Critical fails the build:

```bash
python3 strikehound.py -t http://staging.example.com -m quick --fail-on high
```

Per-target policies — `policies.yaml`:

```yaml
default: high                  # everything must not exceed High
staging.example.com: medium    # this host must not exceed Medium
prod.example.com: critical
```

```bash
python3 strikehound.py -l targets.txt --policy policies.yaml
```

Exit code is `1` if any target's worst finding is at/above its threshold. Hosts
match on exact name or parent-domain suffix (`app.example.com` matches
`example.com`).

### CI (GitHub Actions)

Pushes/PRs run the unit suite, then a live scan against a test target. You can
also run the `security-audit` job manually via **Run workflow → inputs**
(`target`, `profile`, `fail_on`) instead of the default test target.

---

## 📂 Project Layout

```
StrikeHound/
├── strikehound.py            # Orchestrator / CLI entry point
├── scan.sh                   # Convenience wrapper
├── setup.sh                  # One-time installer
├── config.example.yaml       # Config template (copy → config.yaml)
├── modules/                  # Pipeline components
│   ├── nmap_scanner.py       #   discovery
│   ├── nuclei_scanner.py     #   template scanning
│   ├── zap_scanner.py        #   authenticated web scanning (REST API)
│   ├── zap_plan.py           #   ZAP Automation Framework plan generation
│   ├── zap_report_parser.py  #   parse/merge automation reports
│   ├── ssh_audit.py          #   SSH cipher/config audit
│   ├── severity_mapper.py    #   unified severity scale
│   ├── deduplicator.py       #   deterministic cross-tool dedup
│   ├── validators.py         #   target validation
│   ├── report_generator.py   #   PDF / SARIF / JSON reporting
│   └── slack_notifier.py     #   webhook alerts
├── scripts/
│   ├── verify_zap_auth.sh    # Boot ZAP, verify auth flow, shut down
│   └── zap_env_check.py      # Live ZAP diagnostic
└── tests/                    # Unit suite (mocked, no live tools needed)
```

---

## 🧪 Testing

StrikeHound ships a unit suite covering the core logic — deduplication, severity
mapping, target validation, ZAP auth/plan generation/report parsing, and the
scanner modules — using mocked tool/API responses, so **no live scan or network
access is required**.

```bash
source venv/bin/activate
pip install -r requirements-dev.txt
python3 -m pytest tests/ -v
```

### Verifying ZAP Auth Against a Real Daemon

Unit tests mock ZAP's API. To verify the auth/context flow against your **actual**
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

Exit code `0` = reachable + context/auth working; `1` = failure (it reports which step).

> **Authenticated crawling detail:** the plain ZAP spider API has no user
> parameter, so form-auth scans crawl through `spider/action/scanAsUser`
> (context + numeric user id) and run the active scan through
> `ascan/action/scanAsUser` with the same context + numeric user id — *not* the
> username. As of ZAP 2.17, plain `ascan/action/scan` no longer accepts a `user`
> param, so using it would silently scan unauthenticated. If your ZAP version
> rejects either call, StrikeHound logs it and continues unauthenticated rather
> than crashing.

---

## ⚠️ Legal Disclaimer

This tool is provided for **educational purposes only** and for use in
**authorized security auditing environments**.

StrikeHound and its author (ShadowXHat) are not responsible for any misuse,
damage, or illegal activities caused by this software. Use this tool only on
infrastructure where you have **explicit, written permission** to perform
security testing.

Always stay within scope and follow responsible disclosure guidelines.
