# keycloak-auditing

A modular Python framework to audit the security of Keycloak. It integrates Nuclei workflows/templates with automated enumeration, audit checks, vulnerability scanning, safe exploitation, and final report generation.

## Features
- Enumeration: OIDC discovery, realms, clients/roles/groups/IDPs/flows counts (with token)
- Audit: Basic security posture checks (HTTPS, headers, admin console exposure)
- Vulnerability scanning: Runs local Nuclei templates/workflows against the target
- Safe exploitation: Non-destructive checks to validate potential issues
- Reporting: Consolidated Markdown and JSON reports

## Install

- Python 3.10+
- Optional: Nuclei binary on PATH (`nuclei`) or specify via `--nuclei-path`

```bash
pip install -e .
```

## Usage

Basic help:
```bash
keycloak-auditor --help
```

Performance and safety flags:
- `--rate-limit`: HTTP/Nuclei requests per second (default 5)
- `--timeout`: HTTP/Nuclei timeout seconds (default 15)
- `--retries`: HTTP retries (default 2)
- `--insecure`: skip TLS verification

## Wordlists Integration
- Wordlists live in `wordlists/`:
  - `keycloak-directories.txt`: common paths (supports `{realm}`)
  - `keycloak-subdomains.txt`: common subdomain prefixes
  - `keycloak-admin-api.txt`: admin API endpoints (supports `{realm}`)
- Enable during scans with `--use-wordlists` (and optionally `--wordlists-dir`):
```bash
keycloak-auditor \
  --base-url https://kc.example.com \
  --realm master \
  --use-wordlists \
  --wordlists-dir wordlists \
  --rate-limit 5 \
  --timeout 20 \
  --nuclei-templates nuclei-templates \
  scan --workflow
```
- The scanner composes target URLs into `audit-output/targets.txt` and uses `-l` for Nuclei.

## Outputs
- `audit-output/enumeration.json`
- `audit-output/audit.json`
- `audit-output/nuclei.json`, `audit-output/nuclei.jsonl`, `audit-output/targets.txt`
- `audit-output/exploitation.json`
- `audit-output/report.md`, `audit-output/report.json`

## Tests
```bash
pytest -q
```

## Notes
- Use responsibly against systems you are authorized to test.
- Some checks require admin/token. Without it, enumeration is limited to public endpoints.