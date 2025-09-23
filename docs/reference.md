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
- `--workflow`: Use nuclei workflow if available
- `--nuclei-ai`: Enable nuclei AI (experimental)
- `--nuclei-ai-prompt TEXT`: Custom AI prompt
- `--nuclei-severity TEXT`: Filter by severity (e.g. critical,high,medium)
- `--nuclei-tags TEXT`: Filter by tags (comma-separated)
- `--out PATH` (default: audit-output)

## Commands
- `enumerate`: Enumerate Keycloak instance details
- `audit`: Run configuration audit checks
- `scan [--workflow]`: Run Nuclei scans
- `exploit`: Attempt safe exploitation
- `report [--format]`: Generate reports (markdown/html/sarif/all)
- `full [--workflow]`: Run complete pipeline
- `selftest [--pytest-args]`: Run test suite
