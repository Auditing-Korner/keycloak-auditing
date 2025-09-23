# keycloak-auditing

A modular Python framework to audit the security of Keycloak. It integrates Nuclei workflows/templates with automated enumeration, audit checks, vulnerability scanning, safe exploitation, and final report generation.

## Features
- Enumeration: OIDC discovery, realms, clients/roles counts (with token)
- Audit: Basic security posture checks (HTTPS, headers, admin console exposure)
- Vulnerability scanning: Runs local Nuclei templates/workflows against the target
- Safe exploitation: Non-destructive checks to validate potential issues
- Reporting: Consolidated Markdown and JSON reports

## Install

- Python 3.9+
- Optional: Nuclei binary on PATH (`nuclei`) or specify via `--nuclei-path`

```bash
pip install -e .
```

## Usage

Basic help:
```bash
keycloak-auditor --help
```

Run end-to-end (adjust URL/realm):
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --out audit-output enumerate

keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master audit

keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --nuclei-templates nuclei-templates scan --workflow

keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master exploit

keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master report
```

Authenticated enumeration (client credentials):
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --client-id my-admin-client \
  --client-secret $SECRET \
  enumerate
```

## Nuclei Integration
- By default, scans all templates in `nuclei-templates/`.
- If `--workflow` is set and `nuclei-templates/keycloak-security-workflow.yaml` exists, uses it.
- Outputs JSONL to `audit-output/nuclei.jsonl` and consolidated JSON to `audit-output/nuclei.json`.

## Outputs
- `audit-output/enumeration.json`
- `audit-output/audit.json`
- `audit-output/nuclei.json`, `audit-output/nuclei.jsonl`
- `audit-output/exploitation.json`
- `audit-output/report.md`, `audit-output/report.json`

## Tests
```bash
pytest -q
```

## Notes
- Use responsibly against systems you are authorized to test.
- Some checks require admin/token. Without it, enumeration is limited to public endpoints.