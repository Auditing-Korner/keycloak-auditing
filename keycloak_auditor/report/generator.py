import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template

from ..core.config import AuditorConfig


REPORT_TEMPLATE = Template(
	"""
	# Keycloak Audit Report

	- Base URL: {{ base_url }}
	- Realm: {{ realm }}

	## Summary
	- Enumeration items: {{ enumeration|length if enumeration else 0 }}
	- Audit findings: {{ audit|length if audit else 0 }}
	- Nuclei findings: {{ nuclei|length if nuclei else 0 }}
	- Exploit attempts: {{ exploitation|length if exploitation else 0 }}

	### Severity Breakdown (All Sources)
	| Severity | Count |
	|---|---:|
	{% for sev, count in severity_breakdown %}| {{ sev }} | {{ count }} |
	{% endfor %}

	### Top Findings
	{% for f in top_findings %}
	- [{{ f.severity|capitalize }}] {{ f.title or (f.info.name if f.info and f.info.name) or f.id }}
	{% endfor %}

	## Enumeration
	```
	{{ enumeration | tojson(indent=2) }}
	```

	## Audit Findings
	```
	{{ audit | tojson(indent=2) }}
	```

	## Nuclei Findings
	```
	{{ nuclei | tojson(indent=2) }}
	```

	## Exploitation
	```
	{{ exploitation | tojson(indent=2) }}
	```
	"""
)


def _normalize_severity(item: Dict[str, Any]) -> str:
	sev = item.get("severity") or ((item.get("info") or {}).get("severity")) or "unknown"
	return str(sev).lower()


def _title(item: Dict[str, Any]) -> str:
	return item.get("title") or ((item.get("info") or {}).get("name")) or item.get("id") or "finding"


class ReportGenerator:
	def __init__(self, config: AuditorConfig):
		self.config = config

	def _read_json(self, path: Path) -> Any:
		if path.exists():
			try:
				return json.loads(path.read_text())
			except json.JSONDecodeError:
				return None
		return None

	def generate(self) -> str:
		out_dir = Path(self.config.output_dir)
		enumeration = self._read_json(out_dir / "enumeration.json")
		audit: List[Dict[str, Any]] = self._read_json(out_dir / "audit.json") or []
		nuclei: List[Dict[str, Any]] = self._read_json(out_dir / "nuclei.json") or []
		exploitation: List[Dict[str, Any]] = self._read_json(out_dir / "exploitation.json") or []

		all_findings: List[Dict[str, Any]] = []
		all_findings.extend(audit)
		all_findings.extend(nuclei)
		all_findings.extend(exploitation)

		sev_counts = Counter(_normalize_severity(f) for f in all_findings)
		sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
		severity_breakdown = [(s.capitalize(), sev_counts.get(s, 0)) for s in sev_order if sev_counts.get(s, 0) > 0]

		top_findings = sorted(
			[{"severity": _normalize_severity(f), "title": _title(f), "info": f.get("info"), "id": f.get("id")} for f in all_findings],
			key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else len(sev_order),
		)[:10]

		markdown = REPORT_TEMPLATE.render(
			base_url=self.config.base_url,
			realm=self.config.realm,
			enumeration=enumeration,
			audit=audit,
			nuclei=nuclei,
			exploitation=exploitation,
			severity_breakdown=severity_breakdown,
			top_findings=top_findings,
		)
		(out_dir / "report.md").write_text(markdown)
		summary = {
			"base_url": self.config.base_url,
			"realm": self.config.realm,
			"enumeration": enumeration,
			"audit": audit,
			"nuclei": nuclei,
			"exploitation": exploitation,
			"severity_breakdown": severity_breakdown,
			"top_findings": top_findings,
		}
		(out_dir / "report.json").write_text(json.dumps(summary, indent=2))
		return str(out_dir / "report.md")
