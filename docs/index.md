# Keycloak Auditor

Keycloak Auditor is a modular security auditing framework for Keycloak. It integrates Nuclei workflows/templates and AI-guided checks to enumerate, audit, scan, safely validate, and report on Keycloak deployments.

## Features
- **Enumeration**: Realms, clients, roles, groups, IDPs, flows, version detection
- **Configuration Audit**: HTTPS, headers, PKCE, redirect URIs, SAML metadata
- **Vulnerability Scanning**: Nuclei templates/workflows with AI assistance
- **Safe Exploitation**: Non-destructive PoCs and validation checks
- **CVE Mapping**: Version-based vulnerability matching
- **Multi-format Reports**: Markdown, HTML (with charts), SARIF for CI/CD
- **Compliance Mapping**: CIS Controls and OWASP ASVS compliance reporting
- **Baseline Comparison**: Track configuration drift over time
- **Plugin System**: Extensible architecture for custom checks and enumeration

## Quick Start
```bash
# Install
pip install -e .

# Run full audit
keycloak-auditor --base-url https://kc.example.com --realm master full --workflow

# Generate HTML report
keycloak-auditor --base-url https://kc.example.com --realm master report --format html
```

## Documentation
- [Tutorial](tutorial.md) - Complete walkthrough
- [CLI Reference](reference.md) - All commands and options
- [Plugin System](plugins.md) - Extending the framework with custom plugins
