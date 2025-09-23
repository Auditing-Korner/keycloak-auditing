import json
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .core.config import AuditorConfig
from .enumeration.enumerator import KeycloakEnumerator
from .audit.checks import AuditRunner
from .scanner.nuclei import NucleiScanner
from .exploitation.poc import ExploitationRunner
from .report.generator import ReportGenerator
from .report.html_generator import HTMLReportGenerator
from .export.sarif import SARIFExporter

console = Console()


def _print_findings_table(title: str, findings: list[dict]):
	sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
	counts = {s: 0 for s in sev_order}
	for f in findings or []:
		sev = (
			(str(f.get("severity")) or str((f.get("info") or {}).get("severity")) or "unknown").lower()
		)
		counts[sev] = counts.get(sev, 0) + 1
	table = Table(title=title, show_header=True, header_style="bold cyan")
	table.add_column("Severity")
	table.add_column("Count", justify="right")
	for s in sev_order:
		if counts.get(s, 0) > 0:
			table.add_row(s.capitalize(), str(counts[s]))
	console.print(table)


def _run_full_pipeline(config: AuditorConfig, workflow: bool) -> str:
	# Enumerate
	with console.status("Enumerating..."):
		enumr = KeycloakEnumerator(config)
		enum_res = enumr.run()
	(Path(config.output_dir) / "enumeration.json").write_text(json.dumps(enum_res, indent=2))
	# Audit
	with console.status("Auditing..."):
		auditor = AuditRunner(config)
		audit_res = auditor.run()
	(Path(config.output_dir) / "audit.json").write_text(json.dumps(audit_res, indent=2))
	# Scan
	with console.status("Scanning (Nuclei)..."):
		scanner = NucleiScanner(config)
		scan_res = scanner.run(use_workflow=workflow)
	(Path(config.output_dir) / "nuclei.json").write_text(json.dumps(scan_res, indent=2))
	# Exploit
	with console.status("Running safe exploitation..."):
		exp = ExploitationRunner(config)
		exploit_res = exp.run()
	(Path(config.output_dir) / "exploitation.json").write_text(json.dumps(exploit_res, indent=2))
	# Report
	with console.status("Generating report..."):
		reporter = ReportGenerator(config)
		report_path = reporter.generate()
	# Summaries
	_print_findings_table("Audit Findings", audit_res)
	_print_findings_table("Nuclei Findings", scan_res)
	_print_findings_table("Exploitation Attempts", exploit_res)
	console.print(Panel.fit(f"[bold]Report ready:[/bold] {report_path}", border_style="green"))
	return report_path


@click.group(invoke_without_command=True)
@click.option("--base-url", required=True, help="Keycloak base URL, e.g., https://kc.example.com")
@click.option("--realm", default="master", show_default=True, help="Realm to target")
@click.option("--client-id", default=None, help="Client ID for authenticated API calls (optional)")
@click.option("--client-secret", default=None, help="Client secret for client credentials flow (optional)")
@click.option("--token", default=None, help="Bearer token if already obtained (optional)")
@click.option("--nuclei-path", default="nuclei", show_default=True, help="Path to nuclei binary")
@click.option("--nuclei-templates", default=str(Path("nuclei-templates").resolve()), show_default=True, help="Path to nuclei templates")
@click.option("--wordlists-dir", default=str(Path("wordlists").resolve()), show_default=True, help="Path to wordlists directory")
@click.option("--use-wordlists", is_flag=True, help="Use wordlists to build URL targets for scanning")
@click.option("--rate-limit", type=float, default=5.0, show_default=True, help="Max HTTP requests per second")
@click.option("--timeout", type=int, default=15, show_default=True, help="HTTP timeout in seconds")
@click.option("--retries", type=int, default=2, show_default=True, help="HTTP retry attempts")
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification")
@click.option("--workflow", is_flag=True, help="Use nuclei workflow if available in templates (default for no-command mode)")
@click.option("--nuclei-ai", is_flag=True, help="Enable nuclei AI (requires supported build and API key)")
@click.option("--nuclei-ai-prompt", default=None, help="Custom AI prompt to guide nuclei templates")
@click.option("--nuclei-severity", default=None, help="Filter nuclei by severity (e.g. critical,high,medium)")
@click.option("--nuclei-tags", default=None, help="Filter nuclei by tags (comma-separated)")
@click.option("--out", default="audit-output", show_default=True, help="Output directory for artifacts")
@click.pass_context
def main(ctx, base_url, realm, client_id, client_secret, token, nuclei_path, nuclei_templates, wordlists_dir, use_wordlists, rate_limit, timeout, retries, insecure, workflow, nuclei_ai, nuclei_ai_prompt, nuclei_severity, nuclei_tags, out):
	"""Keycloak Auditor CLI.

	If no COMMAND is provided, runs the full pipeline by default.
	"""
	config = AuditorConfig(
		base_url=base_url.rstrip("/"),
		realm=realm,
		client_id=client_id,
		client_secret=client_secret,
		token=token,
		nuclei_path=nuclei_path,
		nuclei_templates=nuclei_templates,
		wordlists_dir=wordlists_dir,
		use_wordlists=use_wordlists,
		rate_limit_rps=rate_limit,
		http_timeout_seconds=timeout,
		retries=retries,
		verify_ssl=not insecure,
		nuclei_ai=nuclei_ai,
		nuclei_ai_prompt=nuclei_ai_prompt,
		nuclei_severity=nuclei_severity,
		nuclei_tags=nuclei_tags,
		output_dir=out,
	)
	Path(out).mkdir(parents=True, exist_ok=True)
	ctx.obj = {
		"config": config,
	}
	if ctx.invoked_subcommand is None and not ctx.resilient_parsing:
		console.rule("[bold green]Full Pipeline (default)")
		_run_full_pipeline(config, workflow)


@main.command()
@click.pass_context
def enumerate(ctx):
	"""Enumerate Keycloak instance details."""
	config: AuditorConfig = ctx.obj["config"]
	with console.status("Enumerating Keycloak..."):
		enumr = KeycloakEnumerator(config)
		results = enumr.run()
	console.print(Panel.fit("[bold]Enumeration Results[/bold]", border_style="magenta"))
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
	with console.status("Running audit checks..."):
		auditor = AuditRunner(config)
		findings = auditor.run()
	(Path(config.output_dir) / "audit.json").write_text(json.dumps(findings, indent=2))
	_print_findings_table("Audit Findings", findings)


@main.command()
@click.option("--workflow", is_flag=True, help="Use nuclei workflow if available")
@click.pass_context
def scan(ctx, workflow):
	"""Run Nuclei scans against Keycloak using local templates."""
	config: AuditorConfig = ctx.obj["config"]
	with console.status("Running nuclei scans..."):
		scanner = NucleiScanner(config)
		results = scanner.run(use_workflow=workflow)
	(Path(config.output_dir) / "nuclei.json").write_text(json.dumps(results, indent=2))
	_print_findings_table("Nuclei Findings", results)


@main.command()
@click.pass_context
def exploit(ctx):
	"""Attempt safe exploitation for selected vulnerabilities."""
	config: AuditorConfig = ctx.obj["config"]
	with console.status("Attempting safe exploitation..."):
		exp = ExploitationRunner(config)
		results = exp.run()
	(Path(config.output_dir) / "exploitation.json").write_text(json.dumps(results, indent=2))
	_print_findings_table("Exploitation Attempts", results)


@main.command(name="report")
@click.option("--format", type=click.Choice(["markdown", "html", "sarif", "all"]), default="all", help="Report format")
@click.pass_context
def report_cmd(ctx, format):
	"""Generate final reports in various formats."""
	config: AuditorConfig = ctx.obj["config"]
	with console.status("Generating reports..."):
		reporter = ReportGenerator(config)
		output = reporter.generate()
		console.print(f"[bold]Markdown report:[/bold] {output}")
		
		if format in ["html", "all"]:
			html_gen = HTMLReportGenerator(config)
			html_path = html_gen.generate()
			console.print(f"[bold]HTML report:[/bold] {html_path}")
		
		if format in ["sarif", "all"]:
			sarif_exporter = SARIFExporter(config)
			sarif_path = sarif_exporter.export()
			console.print(f"[bold]SARIF report:[/bold] {sarif_path}")


@main.command()
@click.option("--workflow", is_flag=True, help="Use nuclei workflow if available in templates")
@click.pass_context
def full(ctx, workflow):
	"""Run full pipeline: enumerate -> audit -> scan -> exploit -> report."""
	config: AuditorConfig = ctx.obj["config"]
	console.rule("[bold green]Full Pipeline")
	_run_full_pipeline(config, workflow)


@main.command()
@click.option("--pytest-args", default="-q", show_default=True, help="Additional pytest args")
@click.pass_context
def selftest(ctx, pytest_args):
	"""Run the framework's test suite (pytest)."""
	cmd = [sys.executable, "-m", "pytest"] + pytest_args.split()
	console.print(Panel.fit("Running tests...", border_style="blue"))
	proc = subprocess.run(" ".join(cmd), shell=True)
	if proc.returncode == 0:
		console.print("[bold green]All tests passed[/bold green]")
	else:
		console.print(f"[bold red]Tests failed with code {proc.returncode}[/bold red]")
		sys.exit(proc.returncode)


if __name__ == "__main__":
	main()
