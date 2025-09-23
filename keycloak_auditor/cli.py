import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .core.config import AuditorConfig
from .enumeration.enumerator import KeycloakEnumerator
from .audit.checks import AuditRunner
from .scanner.nuclei import NucleiScanner
from .exploitation.poc import ExploitationRunner
from .report.generator import ReportGenerator

console = Console()


@click.group()
@click.option("--base-url", required=True, help="Keycloak base URL, e.g., https://kc.example.com")
@click.option("--realm", default="master", show_default=True, help="Realm to target")
@click.option("--client-id", default=None, help="Client ID for authenticated API calls (optional)")
@click.option("--client-secret", default=None, help="Client secret for client credentials flow (optional)")
@click.option("--token", default=None, help="Bearer token if already obtained (optional)")
@click.option("--nuclei-path", default="nuclei", show_default=True, help="Path to nuclei binary")
@click.option("--nuclei-templates", default=str(Path("nuclei-templates").resolve()), show_default=True, help="Path to nuclei templates")
@click.option("--out", default="audit-output", show_default=True, help="Output directory for artifacts")
@click.pass_context
def main(ctx, base_url, realm, client_id, client_secret, token, nuclei_path, nuclei_templates, out):
	"""Keycloak Auditor CLI."""
	config = AuditorConfig(
		base_url=base_url.rstrip("/"),
		realm=realm,
		client_id=client_id,
		client_secret=client_secret,
		token=token,
		nuclei_path=nuclei_path,
		nuclei_templates=nuclei_templates,
		output_dir=out,
	)
	Path(out).mkdir(parents=True, exist_ok=True)
	ctx.obj = {
		"config": config,
	}


@main.command()
@click.pass_context
def enumerate(ctx):
	"""Enumerate Keycloak instance details."""
	config: AuditorConfig = ctx.obj["config"]
	enumr = KeycloakEnumerator(config)
	results = enumr.run()
	console.print("[bold]Enumeration Results[/bold]")
	table = Table(show_header=True, header_style="bold magenta")
	table.add_column("Key")
	table.add_column("Value")
	for key, value in results.items():
		if isinstance(value, (dict, list)):
			value_str = json.dumps(value, indent=2)
		else:
			value_str = str(value)
		table.add_row(key, value_str)
	console.print(table)
	(Path(config.output_dir) / "enumeration.json").write_text(json.dumps(results, indent=2))


@main.command()
@click.pass_context
def audit(ctx):
	"""Run configuration audit checks."""
	config: AuditorConfig = ctx.obj["config"]
	auditor = AuditRunner(config)
	findings = auditor.run()
	console.print(f"[bold]Audit Findings: {len(findings)}[/bold]")
	(Path(config.output_dir) / "audit.json").write_text(json.dumps(findings, indent=2))


@main.command()
@click.option("--workflow", is_flag=True, help="Use nuclei workflow if available")
@click.pass_context
def scan(ctx, workflow):
	"""Run Nuclei scans against Keycloak using local templates."""
	config: AuditorConfig = ctx.obj["config"]
	scanner = NucleiScanner(config)
	results = scanner.run(use_workflow=workflow)
	console.print(f"[bold]Nuclei Findings: {len(results)}[/bold]")
	(Path(config.output_dir) / "nuclei.json").write_text(json.dumps(results, indent=2))


@main.command()
@click.pass_context
def exploit(ctx):
	"""Attempt safe exploitation for selected vulnerabilities."""
	config: AuditorConfig = ctx.obj["config"]
	exp = ExploitationRunner(config)
	results = exp.run()
	console.print(f"[bold]Exploitation Attempts: {len(results)}[/bold]")
	(Path(config.output_dir) / "exploitation.json").write_text(json.dumps(results, indent=2))


@main.command(name="report")
@click.pass_context
def report_cmd(ctx):
	"""Generate final markdown and JSON reports."""
	config: AuditorConfig = ctx.obj["config"]
	reporter = ReportGenerator(config)
	output = reporter.generate()
	console.print(f"[bold]Report generated at[/bold] {output}")


if __name__ == "__main__":
	main()
