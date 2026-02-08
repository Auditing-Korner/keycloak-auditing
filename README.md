# keycloak-auditing

A modular Python framework to audit the security of Keycloak. It integrates Nuclei workflows/templates with automated enumeration, audit checks, vulnerability scanning, safe exploitation, and final report generation.

[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](docs/index.md) [![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-MIT-informational.svg)](LICENSE)

- Docs: [Site](docs/index.md) · [Tutorial](docs/tutorial.md) · [CLI Reference](docs/reference.md)

---

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Configuration & Performance](#configuration--performance)
- [Wordlists](#wordlists)
- [Outputs](#outputs)
- [Support Matrix](#support-matrix)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security & Responsible Use](#security--responsible-use)
- [License](#license)

## Overview
Keycloak Auditor helps security professionals assess Keycloak deployments. It combines public discovery with authenticated checks (when provided), leverages local Nuclei templates/workflows for vulnerability detection, safely demonstrates select issues, and produces actionable reports.

## Key Features
- **Enumeration**: OIDC discovery, realms, clients/roles/groups/IDPs/flows counts (with token)
- **Configuration Audit**: HTTPS, security headers, admin console exposure, session cookie security, and more
- **Vulnerability Scanning**: Runs local Nuclei templates/workflows against targets (with optional AI guidance)
- **Real-World Data**: Integrated database of actual Keycloak CVEs (e.g., CVE-2022-1245) for accurate version assessment
- **Compliance Mapping**: Automated mapping of findings to CIS and OWASP ASVS controls
- **Safe Exploitation**: Non-destructive PoCs to validate suspicious findings
- **Reporting**: Consolidated interactive HTML, Markdown, and JSON reports

## Architecture
- CLI (`keycloak_auditor/cli.py`) orchestrates stages: enumerate → audit → scan → exploit → report
- Core config and throttled HTTP client for rate-limited, reliable requests
- Nuclei integration executes templates/workflows and parses JSONL output
- Wordlists compose target URLs (paths + subdomains) for broader coverage

```
+---------+     +------------+     +--------+     +-----------+     +---------+
| Config  | --> | Enumerate  | --> | Audit  | --> | Scan (NU) | --> | Report  |
+---------+     +------------+     +--------+     +-----------+     +---------+
                       \______________ Exploit (safe) _____________/
```

## Prerequisites
- Python 3.10+
- Optional: Nuclei binary installed (`nuclei` on PATH) or provide via `--nuclei-path`
- Optional (AI features): A Nuclei build that supports `-ai` and a valid API key configured per Nuclei docs
- Network access to the target Keycloak base URL
- Authorization to test the target

## Installation

### Prerequisites
- Python 3.10+
- [Nuclei](https://github.com/projectdiscovery/nuclei) (optional, for scanning)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/AuditingKorner/keycloak-auditor.git
cd keycloak-auditor

# Install dependencies
pip install -r requirements.txt

# (Optional) Install AWS Pentest Tools
# Helper script located in scripts/
bash scripts/install_aws_tools.sh
```

Windows (PowerShell):
```powershell
python -m pip install -e .
```

## Quickstart
Basic help:
```bash
keycloak-auditor --help
```

Run full pipeline (end-to-end):
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --nuclei-templates nuclei-templates \
  full --workflow
```

Run Nuclei with AI assistance (requires supported nuclei build):
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --nuclei-templates nuclei-templates \
  --nuclei-ai \
  --nuclei-ai-prompt "Focus on Keycloak misconfigurations and weak redirect URIs" \
  scan --workflow
```

## Usage
Performance and safety flags:
- `--rate-limit`: HTTP/Nuclei requests per second (default 5)
- `--timeout`: HTTP/Nuclei timeout seconds (default 15)
- `--retries`: HTTP retries (default 2)
- `--insecure`: skip TLS verification
- `--nuclei-ai`: enable Nuclei AI (experimental)
- `--nuclei-ai-prompt`: custom prompt to guide AI

Generate reports in different formats:
```bash
# All formats (default)
keycloak-auditor --base-url https://kc.example.com --realm master report

# HTML only (interactive with charts)
keycloak-auditor --base-url https://kc.example.com --realm master report --format html

# SARIF for CI/CD integration
keycloak-auditor --base-url https://kc.example.com --realm master report --format sarif
```

Generate compliance reports:
```bash
# All frameworks (CIS + OWASP)
keycloak-auditor --base-url https://kc.example.com --realm master compliance

# CIS Controls only
keycloak-auditor --base-url https://kc.example.com --realm master compliance --framework cis

# OWASP ASVS only
keycloak-auditor --base-url https://kc.example.com --realm master compliance --framework owasp
```

Baseline management and drift detection:
```bash
# Create baseline after initial scan
keycloak-auditor --base-url https://kc.example.com --realm master full --workflow
keycloak-auditor --base-url https://kc.example.com --realm master baseline-create --name "initial-scan" --description "Baseline after initial security scan"

# List available baselines
keycloak-auditor --base-url https://kc.example.com --realm master baseline-list

# Compare current state with baseline (detect drift)
keycloak-auditor --base-url https://kc.example.com --realm master full --workflow
keycloak-auditor --base-url https://kc.example.com --realm master baseline-compare --baseline "initial-scan"
```

Plugin management:
```bash
# List available plugins
keycloak-auditor --base-url https://kc.example.com --realm master plugins-list

# Plugins are automatically loaded and executed during scans
keycloak-auditor --base-url https://kc.example.com --realm master full --workflow
```

See [CLI Reference](docs/reference.md) for all options.

## Configuration & Performance
- Requests are rate-limited (global RPS) with retries and backoff.
- `--rate-limit` is applied to both HTTP requests and Nuclei via `-rate-limit`.
- Use higher values cautiously to avoid throttling or noisy scans.

## Wordlists
Wordlists live in `wordlists/` and drive broader discovery:
- `keycloak-directories.txt`: common paths (supports `{realm}`)
- `keycloak-subdomains.txt`: common subdomain prefixes
- `keycloak-admin-api.txt`: admin API endpoints (supports `{realm}`)

Enable during scans:
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --use-wordlists \
  --wordlists-dir wordlists \
  --nuclei-templates nuclei-templates \
  scan --workflow
```
The scanner composes target URLs into `audit-output/targets.txt` and uses `-l` for Nuclei.

## Outputs
- `audit-output/enumeration.json`
- `audit-output/audit.json`
- `audit-output/nuclei.json`, `audit-output/nuclei.jsonl`, `audit-output/targets.txt`
- `audit-output/exploitation.json`
- `audit-output/report.md`, `audit-output/report.json`
- `audit-output/report.html` (interactive with charts)
- `audit-output/report.sarif` (for CI/CD integration)
- `audit-output/compliance-{framework}.md` (compliance reports)
- `audit-output/compliance-{framework}.json` (compliance data)
- `audit-output/baselines/` (baseline snapshots)
- `audit-output/drift-{baseline}.md` (drift reports)
- `audit-output/drift-{baseline}.json` (drift data)
- `plugins/` (custom plugin directory)

## Support Matrix
- Keycloak: modern versions 18+ (tested primarily against 20+). Older endpoints may differ.
- Platforms: Linux, macOS, Windows (PowerShell). Nuclei required for scanning features.

## Troubleshooting
- Nuclei not found: install from `https://github.com/projectdiscovery/nuclei` or pass `--nuclei-path`.
- Timeout/connection errors: increase `--timeout`, reduce `--rate-limit`, or check network/SSL; use `--insecure` for lab/self-signed.
- Limited enumeration: provide `--token` or `--client-id/--client-secret` for admin API access.
- Empty findings: ensure `--nuclei-templates` points to a directory with Keycloak templates/workflows.
- AI flags ignored: verify your Nuclei build supports `-ai`, and that AI credentials/env are configured.

## Roadmap
- [x] **Core**: Enumeration, Audit, and Scan modules
- [x] **Reporting**: Interactive HTML reports with charts
- [x] **Data**: Real Keycloak CVE database
- [x] **Compliance**: CIS and OWASP ASVS mapping
- [ ] **AI**: Enhanced Nuclei AI integration
- [ ] **Cloud**: AWS/Azure specific checks

## Contributing
Contributions are welcome! Please:
- Open an issue to discuss major changes
- Submit PRs with clear descriptions and tests when possible
- Follow the project’s coding style and keep code readable

Run tests:
```bash
pytest -q
```

## Security & Responsible Use
Use this framework only against systems you are authorized to test. Some checks require admin/token; without it, enumeration is limited to public endpoints.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE).
