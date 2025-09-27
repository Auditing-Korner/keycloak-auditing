import json
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template

from ..core.config import AuditorConfig
from .mappings import get_compliance_checks, map_findings_to_compliance


COMPLIANCE_TEMPLATE = Template(
	"""
	# Compliance Report

	## Summary
	- **Framework**: {{ framework }}
	- **Total Controls**: {{ total_controls }}
	- **Passed**: {{ passed_count }}
	- **Failed**: {{ failed_count }}
	- **Unknown**: {{ unknown_count }}
	- **Compliance Score**: {{ compliance_score }}%

	## Controls Status

	| Control ID | Title | Status | Findings |
	|---|---|---|---|
	{% for control_id, result in results.items() %}
	| {{ result.check.control_id }} | {{ result.check.title }} | {{ result.status|upper }} | {{ result.fail_count }} |
	{% endfor %}

	## Detailed Results

	{% for control_id, result in results.items() %}
	### {{ result.check.control_id }} - {{ result.check.title }}
	- **Framework**: {{ result.check.framework }}
	- **Severity**: {{ result.check.severity }}
	- **Status**: {{ result.status|upper }}
	- **Description**: {{ result.check.description }}
	- **Pass Condition**: {{ result.check.pass_condition }}
	- **Fail Condition**: {{ result.check.fail_condition }}

	{% if result.findings %}
	**Findings:**
	{% for finding in result.findings %}
	- {{ finding.title }} ({{ finding.severity }})
	{% endfor %}
	{% endif %}

	---
	{% endfor %}
	"""
)


class ComplianceReporter:
	def __init__(self, config: AuditorConfig):
		self.config = config

	def _read_json(self, path: Path) -> Any:
		if path.exists():
			try:
				return json.loads(path.read_text())
			except json.JSONDecodeError:
				return None
		return None

	def generate_report(self, framework: str = "all") -> str:
		"""Generate compliance report for specified framework."""
		out_dir = Path(self.config.output_dir)
		audit: List[Dict[str, Any]] = self._read_json(out_dir / "audit.json") or []
		nuclei: List[Dict[str, Any]] = self._read_json(out_dir / "nuclei.json") or []
		
		all_findings = audit + nuclei
		checks = get_compliance_checks(framework if framework != "all" else None)
		results = map_findings_to_compliance(all_findings, checks)
		
		# Calculate summary
		total_controls = len(results)
		passed_count = sum(1 for r in results.values() if r["status"] == "pass")
		failed_count = sum(1 for r in results.values() if r["status"] == "fail")
		unknown_count = sum(1 for r in results.values() if r["status"] == "unknown")
		compliance_score = int((passed_count / total_controls * 100)) if total_controls > 0 else 0
		
		report = COMPLIANCE_TEMPLATE.render(
			framework=framework.upper(),
			total_controls=total_controls,
			passed_count=passed_count,
			failed_count=failed_count,
			unknown_count=unknown_count,
			compliance_score=compliance_score,
			results=results
		)
		
		# Save report
		report_path = out_dir / f"compliance-{framework.lower()}.md"
		report_path.write_text(report)
		
		# Save JSON summary
		summary = {
			"framework": framework,
			"total_controls": total_controls,
			"passed_count": passed_count,
			"failed_count": failed_count,
			"unknown_count": unknown_count,
			"compliance_score": compliance_score,
			"results": {
				control_id: {
					"control": result["check"].__dict__,
					"status": result["status"],
					"findings": result["findings"],
					"pass_count": result["pass_count"],
					"fail_count": result["fail_count"]
				}
				for control_id, result in results.items()
			}
		}
		
		summary_path = out_dir / f"compliance-{framework.lower()}.json"
		summary_path.write_text(json.dumps(summary, indent=2))
		
		return str(report_path)

