import json
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
		audit = self._read_json(out_dir / "audit.json")
		nuclei = self._read_json(out_dir / "nuclei.json")
		exploitation = self._read_json(out_dir / "exploitation.json")

		markdown = REPORT_TEMPLATE.render(
			base_url=self.config.base_url,
			realm=self.config.realm,
			enumeration=enumeration,
			audit=audit,
			nuclei=nuclei,
			exploitation=exploitation,
		)
		(out_dir / "report.md").write_text(markdown)
		# Also consolidated JSON
		summary = {
			"base_url": self.config.base_url,
			"realm": self.config.realm,
			"enumeration": enumeration,
			"audit": audit,
			"nuclei": nuclei,
			"exploitation": exploitation,
		}
		(out_dir / "report.json").write_text(json.dumps(summary, indent=2))
		return str(out_dir / "report.md")
