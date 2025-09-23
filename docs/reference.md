# CLI Reference

## Global Options
- `--base-url TEXT` (required)
- `--realm TEXT` (default: master)
- `--client-id TEXT`
- `--client-secret TEXT`
- `--token TEXT`
- `--nuclei-path TEXT` (default: nuclei)
- `--nuclei-templates PATH` (default: nuclei-templates)
- `--wordlists-dir PATH` (default: wordlists)
- `--use-wordlists`
- `--rate-limit FLOAT` (default: 5.0)
- `--timeout INTEGER` (default: 15)
- `--retries INTEGER` (default: 2)
- `--insecure`
- `--out PATH` (default: audit-output)

## Commands
- `enumerate`: Enumerate Keycloak instance details
- `audit`: Run configuration audit checks
- `scan [--workflow]`: Run Nuclei scans
- `exploit`: Attempt safe exploitation
- `report`: Generate Markdown and JSON reports
