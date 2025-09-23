# Tutorial

This tutorial walks through using Keycloak Auditor to assess a Keycloak deployment.

## Prerequisites
- Python 3.10+
- Nuclei binary installed (`nuclei` on PATH) or specify `--nuclei-path`
- Access to a Keycloak base URL (authorized testing only)

## Install
```bash
pip install -e .
```

## Quickstart
Enumerate public endpoints and generate a basic audit:
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --out audit-output enumerate

keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master audit
```

Run Nuclei scans using local templates and wordlists:
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --use-wordlists \
  --wordlists-dir wordlists \
  --nuclei-templates nuclei-templates \
  scan --workflow
```

Generate a final report:
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master report
```

## Authenticated Enumeration
To enumerate realms, clients, roles, and more, provide a client credentials token:
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --client-id admin-cli \
  --client-secret $SECRET \
  enumerate
```

## Performance and Safety
- `--rate-limit` controls HTTP/Nuclei RPS (default 5). Increase cautiously.
- `--timeout` controls request timeout.
- `--retries` controls HTTP retries (exponential backoff).
- `--insecure` disables TLS verification (use only in lab environments).

## Outputs
Artifacts written to `audit-output/` by default:
- `enumeration.json`: Enumeration results
- `audit.json`: Audit checks
- `nuclei.json`/`nuclei.jsonl`: Nuclei findings
- `targets.txt`: Targets composed from wordlists
- `exploitation.json`: Exploitation attempts/results
- `report.md` and `report.json`: Consolidated report
- `report.html`: Interactive HTML report with charts
- `report.sarif`: SARIF format for CI/CD integration

## Report Formats
Generate different report formats:
```bash
# All formats (default)
keycloak-auditor --base-url https://kc.example.com --realm master report

# HTML only (interactive with charts)
keycloak-auditor --base-url https://kc.example.com --realm master report --format html

# SARIF for CI/CD integration
keycloak-auditor --base-url https://kc.example.com --realm master report --format sarif
```

## Extending the Framework
- Add Nuclei templates under `nuclei-templates/` and rerun scans.
- Add URLs/subdomains to `wordlists/` to broaden coverage.
- Implement custom checks under `keycloak_auditor/audit/` and import in CLI.
- Add new exploitation PoCs under `keycloak_auditor/exploitation/`.
